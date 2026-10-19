use std::collections::BTreeMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallTreeNode {
    pub id: u32,
    pub func_addr: u64,
    #[serde(default)]
    pub func_name: Option<String>,
    pub entry_seq: u64,
    pub exit_seq: u64,
    pub parent_id: Option<u32>,
    pub children_ids: Vec<u32>,
    #[serde(default = "default_call_count")]
    pub call_count: u32,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CallTree {
    pub nodes: Vec<CallTreeNode>,
}

pub struct CallTreeBuilder {
    nodes: Vec<CallTreeNode>,
    call_stack: Vec<u32>,
    next_id: u32,
    current_id: u32,
}

impl CallTreeBuilder {
    pub fn new() -> Self {
        let root = CallTreeNode {
            id: 0,
            func_addr: 0,
            func_name: None,
            entry_seq: 0,
            exit_seq: u64::MAX,
            parent_id: None,
            children_ids: Vec::new(),
            call_count: 1,
        };
        Self {
            nodes: vec![root],
            call_stack: Vec::new(),
            next_id: 1,
            current_id: 0,
        }
    }

    /// 设置根节点的地址（用 trace 第一行的实际指令地址）
    pub fn set_root_addr(&mut self, addr: u64) {
        self.nodes[0].func_addr = addr;
    }

    pub fn on_call(&mut self, seq: u64, target_addr: u64) {
        let child_id = self.next_id;
        self.next_id += 1;
        let child = CallTreeNode {
            id: child_id,
            func_addr: target_addr,
            func_name: None,
            entry_seq: seq,
            exit_seq: u64::MAX,
            parent_id: Some(self.current_id),
            children_ids: Vec::new(),
            call_count: 1,
        };
        self.nodes.push(child);
        self.nodes[self.current_id as usize]
            .children_ids
            .push(child_id);
        self.call_stack.push(self.current_id);
        self.current_id = child_id;
    }

    /// 根据 entry_seq 查找节点并设置 func_name
    pub fn set_func_name_by_entry_seq(&mut self, entry_seq: u64, name: &str) {
        for node in self.nodes.iter_mut().rev() {
            if node.entry_seq == entry_seq {
                node.func_name = Some(name.to_string());
                return;
            }
        }
    }

    /// 更新当前节点的 func_addr（用于 BLR 后从下一行获取实际目标地址）
    pub fn update_current_func_addr(&mut self, addr: u64) {
        if self.current_id != 0 {
            self.nodes[self.current_id as usize].func_addr = addr;
        }
    }

    pub fn on_ret(&mut self, seq: u64) {
        if let Some(parent_id) = self.call_stack.pop() {
            self.nodes[self.current_id as usize].exit_seq = seq;
            self.current_id = parent_id;
        }
    }

    pub fn finish(mut self, total_lines: u64) -> CallTree {
        self.nodes[0].exit_seq = total_lines.saturating_sub(1);
        while let Some(parent_id) = self.call_stack.pop() {
            self.nodes[self.current_id as usize].exit_seq = total_lines.saturating_sub(1);
            self.current_id = parent_id;
        }
        compact_anonymous(self.nodes)
    }
}

fn default_call_count() -> u32 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ChildKey {
    Named(u32),
    Anonymous(u64),
    Unknown(u32),
}

fn child_key(node: &CallTreeNode) -> ChildKey {
    if node.func_name.is_some() {
        // Annotated calls stay distinct: two named invocations are meaningful
        // execution nodes even when they target the same address.
        ChildKey::Named(node.id)
    } else if node.func_addr != 0 {
        // Without annotations, a hot loop calling the same helper thousands of
        // times is one static target, not thousands of distinct functions.
        ChildKey::Anonymous(node.func_addr)
    } else {
        // Unresolved BLR targets cannot be safely merged by address.
        ChildKey::Unknown(node.id)
    }
}

fn compact_anonymous(old_nodes: Vec<CallTreeNode>) -> CallTree {
    if old_nodes.len() <= 1 {
        return CallTree { nodes: old_nodes };
    }

    let mut new_nodes: Vec<CallTreeNode> = Vec::with_capacity(old_nodes.len().min(4096));
    new_nodes.push(CallTreeNode {
        id: 0,
        func_addr: old_nodes[0].func_addr,
        func_name: old_nodes[0].func_name.clone(),
        entry_seq: old_nodes[0].entry_seq,
        exit_seq: old_nodes[0].exit_seq,
        parent_id: None,
        children_ids: Vec::new(),
        call_count: old_nodes[0].call_count.max(1),
    });

    // Explicit work stack. Call trees can be very deep when a trace is
    // truncated or returns are missing; recursion here would risk a stack
    // overflow before the UI ever sees the tree.
    let mut work: Vec<(u32, Vec<u32>)> = vec![(0, old_nodes[0].children_ids.clone())];
    while let Some((parent_new_id, old_child_ids)) = work.pop() {
        let mut groups: BTreeMap<ChildKey, Vec<u32>> = BTreeMap::new();
        for old_id in old_child_ids {
            let Some(node) = old_nodes.get(old_id as usize) else {
                continue;
            };
            groups.entry(child_key(node)).or_default().push(old_id);
        }

        let mut new_children = Vec::with_capacity(groups.len());
        for group in groups.into_values() {
            let first = &old_nodes[group[0] as usize];
            let new_id = new_nodes.len() as u32;
            let entry_seq = group
                .iter()
                .map(|id| old_nodes[*id as usize].entry_seq)
                .min()
                .unwrap_or(first.entry_seq);
            let exit_seq = group
                .iter()
                .map(|id| old_nodes[*id as usize].exit_seq)
                .max()
                .unwrap_or(first.exit_seq);
            let call_count = group
                .iter()
                .map(|id| old_nodes[*id as usize].call_count.max(1))
                .sum();
            let mut grandchild_ids = Vec::new();
            for old_id in &group {
                grandchild_ids.extend_from_slice(&old_nodes[*old_id as usize].children_ids);
            }

            new_nodes.push(CallTreeNode {
                id: new_id,
                func_addr: first.func_addr,
                func_name: first.func_name.clone(),
                entry_seq,
                exit_seq,
                parent_id: Some(parent_new_id),
                children_ids: Vec::new(),
                call_count,
            });
            new_children.push(new_id);
            if !grandchild_ids.is_empty() {
                work.push((new_id, grandchild_ids));
            }
        }
        new_nodes[parent_new_id as usize].children_ids = new_children;
    }

    CallTree { nodes: new_nodes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_call_tree() {
        let mut b = CallTreeBuilder::new();
        b.on_call(5, 0x1000);
        b.on_ret(10);
        b.on_call(15, 0x2000);
        b.on_call(20, 0x3000);
        b.on_ret(25);
        b.on_ret(30);
        let tree = b.finish(35);
        assert_eq!(tree.nodes.len(), 4);
        assert_eq!(tree.nodes[0].children_ids, vec![1, 2]);
        assert_eq!(tree.nodes[1].func_addr, 0x1000);
        assert_eq!(tree.nodes[1].exit_seq, 10);
        assert_eq!(tree.nodes[2].children_ids, vec![3]);
    }

    #[test]
    fn test_unbalanced_rets() {
        let mut b = CallTreeBuilder::new();
        b.on_ret(5); // extra ret, should be ignored
        b.on_call(10, 0x1000);
        b.on_ret(15);
        let tree = b.finish(20);
        assert_eq!(tree.nodes.len(), 2);
    }

    #[test]
    fn test_unclosed_calls() {
        let mut b = CallTreeBuilder::new();
        b.on_call(5, 0x1000);
        b.on_call(10, 0x2000);
        // no rets
        let tree = b.finish(20);
        assert_eq!(tree.nodes.len(), 3);
        assert_eq!(tree.nodes[1].exit_seq, 19);
        assert_eq!(tree.nodes[2].exit_seq, 19);
    }

    #[test]
    fn test_anonymous_repeated_calls_are_aggregated() {
        let mut b = CallTreeBuilder::new();
        for i in 0..100u64 {
            b.on_call(i * 2, 0x1000);
            b.on_ret(i * 2 + 1);
        }
        let tree = b.finish(300);
        assert_eq!(tree.nodes.len(), 2);
        assert_eq!(tree.nodes[0].children_ids, vec![1]);
        assert_eq!(tree.nodes[1].func_addr, 0x1000);
        assert_eq!(tree.nodes[1].call_count, 100);
        assert_eq!(tree.nodes[1].entry_seq, 0);
        assert_eq!(tree.nodes[1].exit_seq, 199);
    }

    #[test]
    fn test_named_calls_remain_distinct() {
        let mut b = CallTreeBuilder::new();
        b.on_call(5, 0x1000);
        b.set_func_name_by_entry_seq(5, "helper");
        b.on_ret(10);
        b.on_call(15, 0x1000);
        b.set_func_name_by_entry_seq(15, "helper");
        b.on_ret(20);
        let tree = b.finish(30);
        assert_eq!(tree.nodes.len(), 3);
        assert_eq!(tree.nodes[0].children_ids, vec![1, 2]);
        assert_eq!(tree.nodes[1].call_count, 1);
        assert_eq!(tree.nodes[2].call_count, 1);
    }
}
