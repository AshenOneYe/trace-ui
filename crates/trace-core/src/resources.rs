use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundPriority {
    Low,
    Normal,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudgets {
    pub max_memory_bytes: u64,
    pub max_parallel_scans: usize,
    pub max_index_cache_bytes: u64,
    pub max_concurrent_queries: usize,
    pub background_priority: BackgroundPriority,
}

impl Default for ResourceBudgets {
    fn default() -> Self {
        Self {
            max_memory_bytes: 0,
            max_parallel_scans: std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(4),
            max_index_cache_bytes: 0,
            max_concurrent_queries: 4,
            background_priority: BackgroundPriority::Normal,
        }
    }
}

impl ResourceBudgets {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_parallel_scans == 0 {
            return Err("max_parallel_scans must be greater than zero".to_string());
        }
        Ok(())
    }

    pub fn estimated_index_memory(&self, trace_bytes: usize) -> u64 {
        (trace_bytes as u64).saturating_mul(3)
    }

    pub fn effective_parallel_scans(&self) -> usize {
        match self.background_priority {
            BackgroundPriority::Low => (self.max_parallel_scans / 2).max(1),
            BackgroundPriority::Normal | BackgroundPriority::High => self.max_parallel_scans,
        }
    }
}

pub struct QueryLease<'a> {
    active: &'a AtomicUsize,
}

impl<'a> QueryLease<'a> {
    pub fn try_acquire(
        active: &'a AtomicUsize,
        limit: usize,
    ) -> Result<Self, crate::error::TraceError> {
        if limit == 0 {
            active.fetch_add(1, Ordering::Relaxed);
            return Ok(Self { active });
        }
        let mut current = active.load(Ordering::Relaxed);
        loop {
            if current >= limit {
                return Err(crate::error::TraceError::ResourceBudgetExceeded(format!(
                    "concurrent query limit {limit} reached"
                )));
            }
            match active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Self { active }),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for QueryLease<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_query_limit_is_enforced_and_released() {
        let active = AtomicUsize::new(0);
        let first = QueryLease::try_acquire(&active, 1).unwrap();
        assert!(QueryLease::try_acquire(&active, 1).is_err());
        drop(first);
        assert!(QueryLease::try_acquire(&active, 1).is_ok());
    }

    #[test]
    fn budgets_reject_zero_parallel_scans() {
        let mut budgets = ResourceBudgets::default();
        budgets.max_parallel_scans = 0;
        assert!(budgets.validate().is_err());
    }
}
