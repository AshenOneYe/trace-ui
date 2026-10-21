use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

pub const DEFAULT_MEMORY_BUDGET_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_MEMORY_RESERVE_BYTES: u64 = 512 * 1024 * 1024;
pub const MIN_INDEX_MEMORY_BYTES: u64 = 64 * 1024 * 1024;

impl Default for ResourceBudgets {
    fn default() -> Self {
        Self {
            max_memory_bytes: DEFAULT_MEMORY_BUDGET_BYTES,
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
        self.estimated_index_memory_bytes(trace_bytes as u64)
    }

    pub fn estimated_index_memory_bytes(&self, trace_bytes: u64) -> u64 {
        trace_bytes.saturating_mul(3)
    }

    /// The configured cap constrained by currently reclaimable system memory.
    /// A zero configured cap still leaves the safety reserve in place.
    pub fn effective_memory_limit_bytes(&self) -> u64 {
        let available = available_memory_bytes()
            .unwrap_or(u64::MAX)
            .saturating_sub(DEFAULT_MEMORY_RESERVE_BYTES);
        if self.max_memory_bytes == 0 {
            available
        } else {
            self.max_memory_bytes.min(available)
        }
    }

    pub fn should_use_lite_index(&self, trace_bytes: u64) -> bool {
        self.estimated_index_memory_bytes(trace_bytes) > self.effective_memory_limit_bytes()
    }

    pub fn effective_parallel_scans(&self) -> usize {
        match self.background_priority {
            BackgroundPriority::Low => (self.max_parallel_scans / 2).max(1),
            BackgroundPriority::Normal | BackgroundPriority::High => self.max_parallel_scans,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryStatus {
    pub process_rss_bytes: Option<u64>,
    pub process_peak_rss_bytes: Option<u64>,
    pub available_memory_bytes: Option<u64>,
    pub configured_memory_limit_bytes: u64,
    pub effective_memory_limit_bytes: u64,
    pub safety_reserve_bytes: u64,
    pub pressure: bool,
    pub sampled_at_unix_ms: u128,
}

impl MemoryStatus {
    pub fn headroom_bytes(&self) -> u64 {
        self.effective_memory_limit_bytes
            .saturating_sub(self.process_rss_bytes.unwrap_or(0))
    }

    pub fn can_allocate(&self, additional_bytes: u64) -> bool {
        !self.pressure && additional_bytes <= self.headroom_bytes()
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(target_os = "linux")]
pub fn process_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    (page_size > 0).then(|| resident_pages.saturating_mul(page_size as u64))
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
pub fn process_rss_bytes() -> Option<u64> {
    let mut info = std::mem::MaybeUninit::<libc::mach_task_basic_info>::uninit();
    let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
    let result = unsafe {
        libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            info.as_mut_ptr().cast(),
            &mut count,
        )
    };
    if result != libc::KERN_SUCCESS {
        return None;
    }
    Some(unsafe { info.assume_init().resident_size as u64 })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn process_rss_bytes() -> Option<u64> {
    None
}

pub fn process_peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    let usage = unsafe { usage.assume_init() };
    let value = usage.ru_maxrss as u64;
    #[cfg(target_os = "macos")]
    {
        Some(value)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(value.saturating_mul(1024))
    }
}

#[cfg(target_os = "linux")]
pub fn available_memory_bytes() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kib = meminfo.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == "MemAvailable:").then(|| fields.next()?.parse::<u64>().ok())?
    })?;
    Some(kib.saturating_mul(1024))
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
pub fn available_memory_bytes() -> Option<u64> {
    let mut stats = std::mem::MaybeUninit::<libc::vm_statistics64>::uninit();
    let mut count = libc::HOST_VM_INFO64_COUNT;
    let result = unsafe {
        libc::host_statistics64(
            libc::mach_host_self(),
            libc::HOST_VM_INFO64,
            stats.as_mut_ptr().cast(),
            &mut count,
        )
    };
    if result != libc::KERN_SUCCESS {
        return None;
    }
    let stats = unsafe { stats.assume_init() };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }
    let pages =
        stats.free_count as u64 + stats.inactive_count as u64 + stats.speculative_count as u64;
    Some(pages.saturating_mul(page_size as u64))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn available_memory_bytes() -> Option<u64> {
    None
}

pub struct MemoryWatchdog {
    configured_limit: AtomicU64,
    emergency: AtomicBool,
    status: RwLock<MemoryStatus>,
}

impl MemoryWatchdog {
    pub fn start(configured_limit: u64) -> Arc<Self> {
        let watchdog = Arc::new(Self {
            configured_limit: AtomicU64::new(configured_limit),
            emergency: AtomicBool::new(false),
            status: RwLock::new(Self::sample(configured_limit, false)),
        });
        let sampler = watchdog.clone();
        std::thread::Builder::new()
            .name("trace-ui-memory-watchdog".to_string())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_millis(500));
                let configured = sampler.configured_limit.load(Ordering::Relaxed);
                let mut status = Self::sample(configured, false);
                let hard_pressure = status.process_rss_bytes.is_some_and(|rss| {
                    rss > status.effective_memory_limit_bytes
                        || status
                            .available_memory_bytes
                            .is_some_and(|available| available < DEFAULT_MEMORY_RESERVE_BYTES / 2)
                });
                if hard_pressure {
                    status.pressure = true;
                }
                sampler.emergency.store(hard_pressure, Ordering::Release);
                if let Ok(mut current) = sampler.status.write() {
                    *current = status;
                }
            })
            .ok();
        watchdog
    }

    fn sample(configured_limit: u64, pressure: bool) -> MemoryStatus {
        let available = available_memory_bytes();
        let effective = available
            .unwrap_or(u64::MAX)
            .saturating_sub(DEFAULT_MEMORY_RESERVE_BYTES);
        let effective = if configured_limit == 0 {
            effective
        } else {
            configured_limit.min(effective)
        };
        MemoryStatus {
            process_rss_bytes: process_rss_bytes(),
            process_peak_rss_bytes: process_peak_rss_bytes(),
            available_memory_bytes: available,
            configured_memory_limit_bytes: configured_limit,
            effective_memory_limit_bytes: effective,
            safety_reserve_bytes: DEFAULT_MEMORY_RESERVE_BYTES,
            pressure,
            sampled_at_unix_ms: now_ms(),
        }
    }

    pub fn configure(&self, configured_limit: u64) {
        self.configured_limit
            .store(configured_limit, Ordering::Relaxed);
        self.emergency.store(false, Ordering::Release);
        if let Ok(mut status) = self.status.write() {
            *status = Self::sample(configured_limit, false);
        }
    }

    pub fn status(&self) -> MemoryStatus {
        let configured = self.configured_limit.load(Ordering::Relaxed);
        let mut status = Self::sample(configured, self.emergency.load(Ordering::Acquire));
        if status.process_rss_bytes.is_some_and(|rss| {
            rss > status.effective_memory_limit_bytes
                || status
                    .available_memory_bytes
                    .is_some_and(|available| available < DEFAULT_MEMORY_RESERVE_BYTES / 2)
        }) {
            status.pressure = true;
        }
        status
    }

    pub fn ensure_capacity(&self, additional_bytes: u64) -> Result<(), String> {
        let status = self.status();
        if status.can_allocate(additional_bytes) {
            return Ok(());
        }
        Err(format!(
            "memory guard rejected {additional_bytes} additional bytes: rss={:?}, headroom={} bytes, available={:?}",
            status.process_rss_bytes,
            status.headroom_bytes(),
            status.available_memory_bytes
        ))
    }

    pub fn pressure(&self) -> bool {
        self.emergency.load(Ordering::Acquire)
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

    #[test]
    fn tiny_budget_selects_lite_index() {
        let mut budgets = ResourceBudgets::default();
        budgets.max_memory_bytes = MIN_INDEX_MEMORY_BYTES;
        assert!(budgets.should_use_lite_index(128 * 1024 * 1024));
        assert!(!budgets.should_use_lite_index(1024));
    }

    #[test]
    fn memory_watchdog_reports_process_metrics() {
        let watchdog = MemoryWatchdog::start(ResourceBudgets::default().max_memory_bytes);
        let status = watchdog.status();
        assert!(status.effective_memory_limit_bytes > 0);
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(status.process_rss_bytes.is_some());
        }
    }
}
