use crate::query::call_tree::{CallTree, CallTreeNode};

use super::cache_format::{SectionReader, SectionWriter};

const NO_PARENT: u32 = u32::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FlatCallTreeNode {
    pub func_addr: u64,
    pub entry_seq: u64,
    pub exit_seq: u64,
    pub name_offset: u64,
    pub name_len: u32,
    pub children_start: u32,
    pub children_count: u32,
    pub parent_id: u32,
    pub call_count: u32,
    pub reserved: u32,
}

pub struct CallTreeArchive {
    pub nodes: Vec<FlatCallTreeNode>,
    pub children: Vec<u32>,
    pub names: Vec<u8>,
}

impl CallTreeArchive {
    pub fn from_tree(tree: &CallTree) -> Self {
        let mut nodes = Vec::with_capacity(tree.nodes.len());
        let mut children = Vec::new();
        let mut names = Vec::new();
        for node in &tree.nodes {
            let children_start = children.len() as u32;
            children.extend_from_slice(&node.children_ids);
            let (name_offset, name_len) = if let Some(name) = &node.func_name {
                let offset = names.len() as u64;
                names.extend_from_slice(name.as_bytes());
                (offset, name.len().min(u32::MAX as usize) as u32)
            } else {
                (0, 0)
            };
            nodes.push(FlatCallTreeNode {
                func_addr: node.func_addr,
                entry_seq: node.entry_seq,
                exit_seq: node.exit_seq,
                name_offset,
                name_len,
                children_start,
                children_count: node.children_ids.len().min(u32::MAX as usize) as u32,
                parent_id: node.parent_id.unwrap_or(NO_PARENT),
                call_count: node.call_count,
                reserved: 0,
            });
        }
        Self {
            nodes,
            children,
            names,
        }
    }

    pub fn to_sections(&self) -> Vec<u8> {
        let mut writer = SectionWriter::new();
        writer.write_slice(&self.nodes);
        writer.write_slice(&self.children);
        writer.write_slice(&self.names);
        writer.finish()
    }

    pub fn views_from_sections(data: &[u8]) -> Option<CallTreeView<'_>> {
        let reader = SectionReader::new(data)?;
        if reader.num_sections() < 3 {
            return None;
        }
        Some(CallTreeView {
            nodes: reader.slice(0),
            children: reader.slice(1),
            names: reader.bytes(2),
        })
    }

    pub fn view(&self) -> CallTreeView<'_> {
        CallTreeView {
            nodes: &self.nodes,
            children: &self.children,
            names: &self.names,
        }
    }
}

#[derive(Clone, Copy)]
pub struct CallTreeView<'a> {
    nodes: &'a [FlatCallTreeNode],
    children: &'a [u32],
    names: &'a [u8],
}

impl<'a> CallTreeView<'a> {
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn node(&self, id: u32) -> Option<CallTreeNodeView<'a>> {
        let raw = self.nodes.get(id as usize)?;
        let name = if raw.name_len == 0 {
            None
        } else {
            let start = raw.name_offset as usize;
            let end = start.checked_add(raw.name_len as usize)?;
            Some(std::str::from_utf8(self.names.get(start..end)?).ok()?)
        };
        let children_start = raw.children_start as usize;
        let children_end = children_start.checked_add(raw.children_count as usize)?;
        Some(CallTreeNodeView {
            id,
            raw,
            func_name: name,
            children_ids: self.children.get(children_start..children_end)?,
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = CallTreeNodeView<'a>> + '_ {
        (0..self.nodes.len() as u32).filter_map(|id| self.node(id))
    }
}

#[derive(Clone, Copy)]
pub struct CallTreeNodeView<'a> {
    pub id: u32,
    raw: &'a FlatCallTreeNode,
    pub func_name: Option<&'a str>,
    pub children_ids: &'a [u32],
}

impl CallTreeNodeView<'_> {
    pub fn func_addr(&self) -> u64 {
        self.raw.func_addr
    }

    pub fn entry_seq(&self) -> u64 {
        self.raw.entry_seq
    }

    pub fn exit_seq(&self) -> u64 {
        self.raw.exit_seq
    }

    pub fn parent_id(&self) -> Option<u32> {
        (self.raw.parent_id != NO_PARENT).then_some(self.raw.parent_id)
    }

    pub fn call_count(&self) -> u32 {
        self.raw.call_count
    }

    pub fn to_owned_node(&self) -> CallTreeNode {
        CallTreeNode {
            id: self.id,
            func_addr: self.raw.func_addr,
            func_name: self.func_name.map(str::to_string),
            entry_seq: self.raw.entry_seq,
            exit_seq: self.raw.exit_seq,
            parent_id: self.parent_id(),
            children_ids: self.children_ids.to_vec(),
            call_count: self.raw.call_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::call_tree::CallTreeBuilder;

    #[test]
    fn call_tree_flat_round_trip() {
        let mut builder = CallTreeBuilder::new();
        builder.on_call(1, 0x1000);
        builder.set_func_name_by_entry_seq(1, "helper");
        builder.on_ret(5);
        let tree = builder.finish(10);
        let archive = CallTreeArchive::from_tree(&tree);
        let bytes = archive.to_sections();
        let view = CallTreeArchive::views_from_sections(&bytes).unwrap();
        assert_eq!(view.node_count(), 2);
        assert_eq!(view.node(1).unwrap().func_name, Some("helper"));
        assert_eq!(view.node(0).unwrap().children_ids, &[1]);
    }
}
