use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rayon::prelude::*;
use trace_parser::gumtrace::CallAnnotation;
use trace_parser::types::TraceFormat;

use crate::api_types::{
    CallInfoDto, RangeSearchOutcome, SearchMatch, SearchOptions, SearchResultLite,
};
use crate::browse::{parse_trace_line, parse_trace_line_gumtrace};
use crate::error::{Result, TraceError};
use crate::utils::ascii_contains;

use super::TraceEngine;

/// 搜索首页返回的最大序列号数量
const SEARCH_FIRST_PAGE_SIZE: usize = 5000;

// ── Search mode ──

enum SearchMode {
    TextInsensitive(Vec<u8>),
    TextSensitive(Vec<u8>),
    /// 多个关键词模糊匹配（空格分隔，全部命中才算匹配，不区分大小写）
    FuzzyText(Vec<Vec<u8>>),
    Regex(regex::bytes::Regex),
}

fn parse_search_mode(
    query: &str,
    case_sensitive: bool,
    use_regex: bool,
    fuzzy: bool,
) -> Result<SearchMode> {
    if query.starts_with('/') && query.ends_with('/') && query.len() > 2 {
        let pattern = &query[1..query.len() - 1];
        let re = regex::bytes::Regex::new(pattern)
            .map_err(|e| TraceError::Internal(format!("正则表达式错误: {}", e)))?;
        return Ok(SearchMode::Regex(re));
    }
    if use_regex {
        let pattern = if case_sensitive {
            query.to_string()
        } else {
            format!("(?i){}", query)
        };
        let re = regex::bytes::Regex::new(&pattern)
            .map_err(|e| TraceError::Internal(format!("正则表达式错误: {}", e)))?;
        Ok(SearchMode::Regex(re))
    } else if case_sensitive {
        Ok(SearchMode::TextSensitive(query.as_bytes().to_vec()))
    } else if fuzzy {
        // 模糊匹配：按空格拆分为多个 token，每个独立匹配
        let tokens: Vec<Vec<u8>> = query
            .split_whitespace()
            .map(|t| t.to_lowercase().into_bytes())
            .collect();
        if tokens.len() > 1 {
            Ok(SearchMode::FuzzyText(tokens))
        } else {
            Ok(SearchMode::TextInsensitive(
                query.to_lowercase().into_bytes(),
            ))
        }
    } else {
        // 默认：整体子串匹配（含空格）
        Ok(SearchMode::TextInsensitive(
            query.to_lowercase().into_bytes(),
        ))
    }
}

// ── Match helpers ──

/// 零分配多关键词模糊匹配
#[inline]
fn ascii_fuzzy_match(haystack: &[u8], tokens: &[Vec<u8>]) -> bool {
    tokens.iter().all(|t| ascii_contains(haystack, t))
}

#[inline]
fn ascii_contains_sensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// 对一行执行匹配（支持原始行 + call_search_text 双重匹配）
#[inline]
fn matches_line(mode: &SearchMode, line: &[u8], call_text: Option<&[u8]>) -> bool {
    let line_match = match mode {
        SearchMode::TextInsensitive(needle) => ascii_contains(line, needle),
        SearchMode::TextSensitive(needle) => ascii_contains_sensitive(line, needle),
        SearchMode::FuzzyText(tokens) => ascii_fuzzy_match(line, tokens),
        SearchMode::Regex(re) => re.is_match(line),
    };
    if line_match {
        return true;
    }
    if let Some(text) = call_text {
        match mode {
            SearchMode::TextInsensitive(needle) => ascii_contains(text, needle),
            SearchMode::TextSensitive(needle) => ascii_contains_sensitive(text, needle),
            SearchMode::FuzzyText(tokens) => ascii_fuzzy_match(text, tokens),
            SearchMode::Regex(re) => re.is_match(text),
        }
    } else {
        false
    }
}

fn matches_mode_bytes(mode: &SearchMode, text: &[u8]) -> bool {
    match mode {
        SearchMode::TextInsensitive(needle) => ascii_contains(text, needle),
        SearchMode::TextSensitive(needle) => ascii_contains_sensitive(text, needle),
        SearchMode::FuzzyText(tokens) => ascii_fuzzy_match(text, tokens),
        SearchMode::Regex(re) => re.is_match(text),
    }
}

fn matches_mode_str(mode: &SearchMode, text: &str) -> bool {
    matches_mode_bytes(mode, text.as_bytes())
}

fn rendered_search_text(
    address: &str,
    disasm: &str,
    changes: &str,
    mem_rw: Option<&str>,
    call_summary: Option<&str>,
) -> String {
    let mut parts = Vec::with_capacity(5);
    if let Some(rw) = mem_rw.filter(|rw| !rw.is_empty()) {
        parts.push(rw);
    }
    if !address.is_empty() {
        parts.push(address);
    }
    if !disasm.is_empty() {
        parts.push(disasm);
    }
    if let Some(summary) = call_summary.filter(|summary| !summary.is_empty()) {
        parts.push(summary);
    }
    if !changes.is_empty() {
        parts.push(changes);
    }
    parts.join("\n")
}

/// 轻量搜索：只收集匹配的 seq 号，不解析行内容
fn search_chunk_seqs(
    data: &[u8],
    start_seq: u64,
    end_seq: u64,
    start_offset: usize,
    mode: &SearchMode,
    consumed_seqs: &HashSet<u64>,
    call_search_texts: &HashMap<u64, String>,
    max_results_per_chunk: usize,
) -> (Vec<u64>, u64) {
    let mut match_seqs = Vec::new();
    let mut total_matches = 0u64;
    let mut pos = start_offset;
    let mut seq = start_seq;

    while pos < data.len() && seq < end_seq {
        let end = memchr::memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());
        let line = &data[pos..end];

        if !consumed_seqs.contains(&seq) {
            let call_text = call_search_texts.get(&seq).map(|s| s.as_bytes());
            if matches_line(mode, line, call_text) {
                total_matches += 1;
                if match_seqs.len() < max_results_per_chunk {
                    match_seqs.push(seq);
                }
            }
        }

        pos = end + 1;
        seq += 1;
    }

    (match_seqs, total_matches)
}

/// 范围搜索的分块扫描：在 [start_seq, end_seq) 窗口内收集匹配，
/// 可选按指令地址（so_offset 或绝对地址）过滤，保留前 keep_cap 个匹配供分页。
fn search_range_chunk(
    data: &[u8],
    start_seq: u64,
    end_seq: u64,
    start_offset: usize,
    mode: &SearchMode,
    consumed_seqs: &HashSet<u64>,
    call_search_texts: &HashMap<u64, String>,
    addr_filter: Option<(u64, u64)>,
    keep_cap: usize,
) -> (Vec<u64>, u64) {
    let mut kept = Vec::new();
    let mut total = 0u64;
    let mut pos = start_offset;
    let mut seq = start_seq;

    while pos < data.len() && seq < end_seq {
        let end = memchr::memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());
        let line = &data[pos..end];

        if !consumed_seqs.contains(&seq) {
            let call_text = call_search_texts.get(&seq).map(|s| s.as_bytes());
            if matches_line(mode, line, call_text) {
                let pass_addr = match addr_filter {
                    Some((lo, hi)) => {
                        let line_str = std::str::from_utf8(line).unwrap_or("");
                        let so_off = crate::phase2::extract_insn_offset(line_str);
                        let abs = crate::phase2::extract_insn_addr(line_str);
                        (so_off != 0 && so_off >= lo && so_off <= hi)
                            || (abs != 0 && abs >= lo && abs <= hi)
                    }
                    None => true,
                };
                if pass_addr {
                    total += 1;
                    if kept.len() < keep_cap {
                        kept.push(seq);
                    }
                }
            }
        }

        pos = end + 1;
        seq += 1;
    }

    (kept, total)
}

// ── TraceEngine methods ──

impl TraceEngine {
    pub fn search(
        &self,
        session_id: &str,
        query: &str,
        options: SearchOptions,
    ) -> Result<SearchResultLite> {
        let handle = self.get_handle(session_id)?;

        if query.is_empty() {
            *handle
                .search_cache
                .lock()
                .map_err(|e| TraceError::Internal(e.to_string()))? = (0, Vec::new());
            return Ok(SearchResultLite {
                match_seqs: Vec::new(),
                total_scanned: 0,
                total_matches: 0,
                truncated: false,
            });
        }

        let mode = parse_search_mode(
            query,
            options.case_sensitive,
            options.use_regex,
            options.fuzzy,
        )?;
        let paginated = options.max_results.is_none();
        let max_results = if paginated {
            usize::MAX
        } else {
            options.max_results.unwrap() as usize
        };

        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        // 从 session 中提取搜索所需数据，并预计算分块边界
        let (mmap_arc, scan_start, scan_end, call_search_texts, consumed_seqs, chunks) = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;

            let total_lines = state
                .lidx_store
                .as_ref()
                .map(|s| s.total_lines())
                .unwrap_or(0);
            let (scan_start, scan_end) = handle
                .segment_range()
                .map(|(start, end)| (start.min(total_lines), (end + 1).min(total_lines)))
                .unwrap_or((0, total_lines));

            let chunks: Option<Vec<(u64, u64, usize)>> =
                if num_cpus > 1 && scan_end.saturating_sub(scan_start) > 10000 {
                    state.line_index_view().map(|li| {
                        let data: &[u8] = &state.mmap;
                        let num_chunks = num_cpus.min(16);
                        let window_lines = scan_end.saturating_sub(scan_start);
                        let lines_per_chunk = (window_lines as usize + num_chunks - 1) / num_chunks;
                        let mut result = Vec::with_capacity(num_chunks);
                        for i in 0..num_chunks {
                            let start_seq = scan_start + (i * lines_per_chunk) as u64;
                            if start_seq >= scan_end {
                                break;
                            }
                            let end_seq =
                                (scan_start + ((i + 1) * lines_per_chunk) as u64).min(scan_end);
                            let start_offset =
                                li.line_byte_offset(data, start_seq).unwrap_or(0) as usize;
                            result.push((start_seq, end_seq, start_offset));
                        }
                        result
                    })
                } else {
                    None
                };

            let consumed: HashSet<u64> = state.consumed_seqs.iter().copied().collect();

            (
                state.mmap.clone(),
                scan_start,
                scan_end,
                state.call_search_texts.clone(),
                consumed,
                chunks,
            )
        };

        let data: Arc<memmap2::Mmap> = mmap_arc;

        let (all_seqs, total_matches) = if let Some(chunks) = chunks {
            let chunk_results: Vec<(Vec<u64>, u64)> = chunks
                .par_iter()
                .map(|&(start_seq, end_seq, start_offset)| {
                    search_chunk_seqs(
                        &data,
                        start_seq,
                        end_seq,
                        start_offset,
                        &mode,
                        &consumed_seqs,
                        &call_search_texts,
                        max_results,
                    )
                })
                .collect();

            let mut merged = Vec::new();
            let mut tm = 0u64;
            for (chunk_seqs, chunk_total) in chunk_results {
                tm += chunk_total;
                if paginated {
                    merged.extend(chunk_seqs);
                } else if merged.len() < max_results {
                    let remaining = max_results - merged.len();
                    merged.extend(chunk_seqs.into_iter().take(remaining));
                }
            }
            (merged, tm)
        } else {
            let start_offset = {
                let state = handle
                    .state
                    .read()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                state
                    .line_index_view()
                    .and_then(|line_index| line_index.line_byte_offset(&state.mmap, scan_start))
                    .unwrap_or(0) as usize
            };
            let (match_seqs, total_matches) = search_chunk_seqs(
                &data,
                scan_start,
                scan_end,
                start_offset,
                &mode,
                &consumed_seqs,
                &call_search_texts,
                max_results,
            );
            (match_seqs, total_matches)
        };

        if paginated {
            // 全量模式：缓存结果，只返回首页
            let first_page_end = SEARCH_FIRST_PAGE_SIZE.min(all_seqs.len());
            let first_page = all_seqs[..first_page_end].to_vec();
            let mut cache = handle
                .search_cache
                .lock()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            let gen = cache.0 + 1;
            *cache = (gen, all_seqs); // move, not clone
            Ok(SearchResultLite {
                match_seqs: first_page,
                total_scanned: scan_end.saturating_sub(scan_start),
                total_matches,
                truncated: total_matches as usize > SEARCH_FIRST_PAGE_SIZE,
            })
        } else {
            // 截断模式（GotoOverlay / MCP）：不缓存，按原逻辑返回
            Ok(SearchResultLite {
                match_seqs: all_seqs,
                total_scanned: scan_end.saturating_sub(scan_start),
                total_matches,
                truncated: total_matches > max_results as u64,
            })
        }
    }

    /// 从缓存的搜索结果中拉取指定范围的匹配序列号
    pub fn fetch_search_page(
        &self,
        session_id: &str,
        offset: u32,
        count: u32,
    ) -> Result<(u64, Vec<u64>)> {
        let handle = self.get_handle(session_id)?;
        let cache = handle
            .search_cache
            .lock()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let (gen, ref all_seqs) = *cache;
        let start = (offset as usize).min(all_seqs.len());
        let end = (start + count as usize).min(all_seqs.len());
        Ok((gen, all_seqs[start..end].to_vec()))
    }

    /// 范围感知搜索：仅在 [start_seq, end_seq) 窗口内扫描，支持
    /// 指令地址过滤（so_offset 或绝对地址命中其一即算）与 offset 分页。
    ///
    /// 与 `search` 的关键区别：`search` 先全局截断到前 N 个匹配再由调用方过滤，
    /// 当窗口内匹配不在全局前 N 时会得到"空结果但 total>0"的错误行为；
    /// 本方法直接在窗口内扫描，total_in_range 是窗口内的精确总数。
    pub fn search_in_range(
        &self,
        session_id: &str,
        query: &str,
        options: SearchOptions,
        start_seq: u64,
        end_seq: u64,
        addr_filter: Option<(u64, u64)>,
        offset: u64,
        limit: u64,
    ) -> Result<RangeSearchOutcome> {
        if query.is_empty() || limit == 0 {
            return Ok(RangeSearchOutcome {
                match_seqs: Vec::new(),
                total_in_range: 0,
                total_scanned: 0,
            });
        }
        let handle = self.get_handle(session_id)?;
        let (start_seq, end_seq) = handle
            .segment_range()
            .map(|(segment_start, segment_end)| {
                (
                    start_seq.max(segment_start),
                    end_seq.min(segment_end.saturating_add(1)),
                )
            })
            .unwrap_or((start_seq, end_seq));
        let mode = parse_search_mode(
            query,
            options.case_sensitive,
            options.use_regex,
            options.fuzzy,
        )?;

        let (mmap_arc, call_search_texts, consumed_seqs, chunks, start, end) = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;

            let total_lines = state
                .lidx_store
                .as_ref()
                .map(|s| s.total_lines())
                .unwrap_or(0);

            let start = start_seq.min(total_lines);
            let end = end_seq.min(total_lines);
            if start >= end {
                return Ok(RangeSearchOutcome {
                    match_seqs: Vec::new(),
                    total_in_range: 0,
                    total_scanned: 0,
                });
            }

            let num_cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4);

            // 窗口较大时并行分块（与 search 相同的分块策略）
            let chunks: Option<Vec<(u64, u64, usize)>> = if num_cpus > 1 && end - start > 200_000 {
                state.line_index_view().map(|li| {
                    let data: &[u8] = &state.mmap;
                    let num_chunks = num_cpus.min(16);
                    let lines_per_chunk = ((end - start) as usize + num_chunks - 1) / num_chunks;
                    let mut result = Vec::with_capacity(num_chunks);
                    let mut chunk_start = start;
                    while chunk_start < end {
                        let chunk_end = (chunk_start + lines_per_chunk as u64).min(end);
                        let start_offset =
                            li.line_byte_offset(data, chunk_start).unwrap_or(0) as usize;
                        result.push((chunk_start, chunk_end, start_offset));
                        chunk_start = chunk_end;
                    }
                    result
                })
            } else {
                None
            };

            let consumed: HashSet<u64> = state.consumed_seqs.iter().copied().collect();

            (
                state.mmap.clone(),
                state.call_search_texts.clone(),
                consumed,
                chunks,
                start,
                end,
            )
        };

        let data: Arc<memmap2::Mmap> = mmap_arc;
        let keep_cap = offset.saturating_add(limit) as usize;

        let (kept, total_in_range) = if let Some(chunks) = chunks {
            let chunk_results: Vec<(Vec<u64>, u64)> = chunks
                .par_iter()
                .map(|&(cs, ce, coff)| {
                    search_range_chunk(
                        &data,
                        cs,
                        ce,
                        coff,
                        &mode,
                        &consumed_seqs,
                        &call_search_texts,
                        addr_filter,
                        keep_cap,
                    )
                })
                .collect();
            let mut merged = Vec::new();
            let mut total = 0u64;
            for (chunk_kept, chunk_total) in chunk_results {
                total += chunk_total;
                // 各块保留的是自身匹配的前缀，按块序拼接后截断即得全局前 keep_cap 个
                if merged.len() < keep_cap {
                    let remaining = keep_cap - merged.len();
                    merged.extend(chunk_kept.into_iter().take(remaining));
                }
            }
            (merged, total)
        } else {
            let start_offset = {
                // 单线程路径：需要行索引定位窗口起点
                let state = handle
                    .state
                    .read()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                let li = state
                    .line_index_view()
                    .ok_or_else(|| TraceError::IndexNotReady)?;
                li.line_byte_offset(&state.mmap, start).unwrap_or(0) as usize
            };
            search_range_chunk(
                &data,
                start,
                end,
                start_offset,
                &mode,
                &consumed_seqs,
                &call_search_texts,
                addr_filter,
                keep_cap,
            )
        };

        // 分页：[offset, offset+limit)
        let page_start = (offset as usize).min(kept.len());
        let page_end = (page_start + limit as usize).min(kept.len());
        let match_seqs = kept[page_start..page_end].to_vec();

        Ok(RangeSearchOutcome {
            match_seqs,
            total_in_range,
            total_scanned: end - start,
        })
    }

    pub fn get_search_matches(
        &self,
        session_id: &str,
        query: &str,
        seqs: &[u64],
        case_sensitive: bool,
        use_regex: bool,
        fuzzy: bool,
    ) -> Result<Vec<SearchMatch>> {
        if seqs.is_empty() {
            return Ok(Vec::new());
        }

        let mode = parse_search_mode(query, case_sensitive, use_regex, fuzzy)?;

        // 持锁期间提取所有必要数据
        let (mmap_arc, trace_format, call_search_texts, call_annotations, li_data) = {
            let handle = self.get_handle(session_id)?;
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;

            let li = state
                .line_index_view()
                .ok_or_else(|| TraceError::Internal("Line index not available".to_string()))?;

            let data: &[u8] = &state.mmap;
            // 预计算各 seq 的字节偏移，同时过滤 consumed_seqs
            let consumed: HashSet<u64> = state.consumed_seqs.iter().copied().collect();
            let offsets: Vec<(u64, usize)> = seqs
                .iter()
                .filter(|&&seq| !consumed.contains(&seq))
                .filter_map(|&seq| {
                    li.line_byte_offset(data, seq)
                        .map(|off| (seq, off as usize))
                })
                .collect();

            (
                state.mmap.clone(),
                state.trace_format,
                state.call_search_texts.clone(),
                state.call_annotations.clone(),
                offsets,
            )
        };

        let data: &[u8] = &mmap_arc;
        let mut matches = Vec::with_capacity(li_data.len());

        for (seq, offset) in li_data {
            let end = memchr::memchr(b'\n', &data[offset..])
                .map(|i| offset + i)
                .unwrap_or(data.len());
            let line = &data[offset..end];

            let parsed = match trace_format {
                TraceFormat::Unidbg => parse_trace_line(seq, line),
                TraceFormat::Gumtrace => parse_trace_line_gumtrace(seq, line),
            };

            if let Some(parsed) = parsed {
                let mut hidden_content = None;
                let annotation = call_annotations.get(&seq);
                let call_info = annotation.map(|ann: &CallAnnotation| {
                    let summary = ann.summary();
                    let tooltip = ann.tooltip();
                    // 前端 UI 将 summary 截断到 80 字符显示，
                    // 因此用截断后的 summary 判断匹配是否在可见区域内
                    let display_summary = if summary.len() > 80 {
                        let mut end_idx = 80;
                        while !summary.is_char_boundary(end_idx) && end_idx > 0 {
                            end_idx -= 1;
                        }
                        &summary[..end_idx]
                    } else {
                        &summary
                    };
                    let rendered_text = rendered_search_text(
                        &parsed.address,
                        &parsed.disasm,
                        &parsed.changes,
                        parsed.mem_rw.as_deref(),
                        Some(display_summary),
                    );
                    let annotation_match = call_search_texts
                        .get(&seq)
                        .map_or(false, |text| matches_mode_str(&mode, text));
                    if annotation_match
                        && !matches_mode_str(&mode, &rendered_text)
                        && !tooltip.is_empty()
                    {
                        hidden_content = Some(tooltip.clone());
                    }
                    CallInfoDto {
                        func_name: ann.func_name.clone(),
                        is_jni: ann.is_jni,
                        summary,
                        tooltip,
                    }
                });

                matches.push(SearchMatch {
                    seq: parsed.seq,
                    address: parsed.address,
                    so_offset: parsed.so_offset,
                    so_name: parsed.so_name,
                    disasm: parsed.disasm,
                    changes: parsed.changes,
                    reg_before: parsed.reg_before,
                    mem_rw: parsed.mem_rw,
                    call_info,
                    hidden_content,
                });
            }
        }

        Ok(matches)
    }
}
