import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  EvidenceRef,
  HandlerCluster,
  Hypothesis,
  IndexStatus,
  AnalysisJob,
  LineRange,
  TraceAlignment,
  VmAnalysisResult,
  VmRegion,
} from "../types/trace";

interface Props {
  sessionId: string | null;
  isPhase2Ready: boolean;
  onJumpToSeq: (seq: number) => void;
  sessions?: Array<{ sessionId: string; fileName: string }>;
}

type Section = "regions" | "handlers" | "guest" | "state" | "ir" | "cfg" | "compare" | "hypotheses" | "jobs";

function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function confidenceColor(value: number): string {
  if (value >= 0.75) return "#4caf50";
  if (value >= 0.5) return "#e6a23c";
  return "#e06c75";
}

function rangeLabel(range: LineRange | null | undefined): string {
  if (!range) return "unknown";
  return `${range.start.toLocaleString()}–${Math.max(range.start, range.end - 1).toLocaleString()}`;
}

function firstEvidenceLine(evidence: EvidenceRef[]): number | null {
  const line = evidence.find(item => item.lines.end > item.lines.start)?.lines.start;
  return line ?? null;
}

function Chip({ children, tone = "neutral" }: { children: React.ReactNode; tone?: "neutral" | "warn" | "accent" }) {
  const color = tone === "warn" ? "#e6a23c" : tone === "accent" ? "#61afef" : "var(--text-secondary)";
  return (
    <span style={{
      border: `1px solid ${color}`,
      color,
      borderRadius: 10,
      padding: "1px 7px",
      fontSize: 10,
      lineHeight: "16px",
      whiteSpace: "nowrap",
    }}>{children}</span>
  );
}

function RegionCard({ region, onJumpToSeq }: { region: VmRegion; onJumpToSeq: (seq: number) => void }) {
  const evidenceLine = firstEvidenceLine(region.evidence);
  return (
    <div style={{
      border: "1px solid var(--border-color)",
      borderRadius: 6,
      padding: 10,
      background: "var(--bg-secondary)",
      display: "flex",
      flexDirection: "column",
      gap: 7,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <strong style={{ fontSize: 12 }}>{region.id}</strong>
        <Chip tone="accent">confidence {pct(region.confidence)}</Chip>
        <Chip>{region.indirect_dispatches} indirect dispatches</Chip>
        <Chip>{region.repeated_instructions} repeated instructions</Chip>
      </div>
      <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
        Addresses 0x{region.address_start.toString(16)}–0x{region.address_end.toString(16)}
        {" · "}lines {rangeLabel(region.lines)}
      </div>
      <div style={{
        height: 5,
        borderRadius: 3,
        background: "var(--border-color)",
        overflow: "hidden",
      }}>
        <div style={{
          width: pct(region.confidence),
          height: "100%",
          background: confidenceColor(region.confidence),
        }} />
      </div>
      {region.warnings.map(warning => (
        <div key={warning} style={{ fontSize: 11, color: "#e6a23c" }}>{warning}</div>
      ))}
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
          {region.evidence.length} native evidence references
        </span>
        {evidenceLine != null && (
          <button
            onClick={() => onJumpToSeq(evidenceLine)}
            style={{ fontSize: 11, cursor: "pointer" }}
          >Jump to evidence</button>
        )}
      </div>
    </div>
  );
}

function HandlerCard({
  cluster,
  selected,
  onSelect,
  onJumpToSeq,
}: {
  cluster: HandlerCluster;
  selected: boolean;
  onSelect: () => void;
  onJumpToSeq: (seq: number) => void;
}) {
  const representative = cluster.representative_lines[0] ?? null;
  return (
    <button
      onClick={onSelect}
      style={{
        textAlign: "left",
        border: selected ? "1px solid #61afef" : "1px solid var(--border-color)",
        borderRadius: 6,
        padding: 10,
        background: selected ? "rgba(97,175,239,0.10)" : "var(--bg-secondary)",
        color: "var(--text-primary)",
        cursor: "pointer",
      }}
    >
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <strong style={{ fontSize: 12 }}>{cluster.id}</strong>
        <Chip tone="accent">{cluster.instance_count} executions</Chip>
        <Chip tone={cluster.confidence < 0.6 ? "warn" : "neutral"}>
          {pct(cluster.confidence)}
        </Chip>
      </div>
      <div style={{ marginTop: 5, fontSize: 11, color: "var(--text-secondary)" }}>
        {cluster.semantics.operations.join(", ") || "unknown"}
        {" · "}{rangeLabel(representative)}
      </div>
      {cluster.semantics.unknown_effects.length > 0 && (
        <div style={{ marginTop: 4, fontSize: 11, color: "#e6a23c" }}>
          Partial semantics: {cluster.semantics.unknown_effects.length} unknown effects
        </div>
      )}
      {cluster.conflicts.length > 0 && (
        <div style={{ marginTop: 4, fontSize: 11, color: "#e06c75" }}>
          Conflicts: {cluster.conflicts.join("; ")}
        </div>
      )}
      {representative && (
        <div
          role="button"
          tabIndex={0}
          onClick={event => { event.stopPropagation(); onJumpToSeq(representative.start); }}
          style={{ marginTop: 5, fontSize: 11, color: "#61afef" }}
        >Native lines {rangeLabel(representative)}</div>
      )}
    </button>
  );
}

function JobList({ jobs }: { jobs: AnalysisJob[] }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
      <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
        Persistent MCP jobs · {jobs.length} total
      </div>
      {jobs.map(job => (
        <div key={job.id} style={{
          border: "1px solid var(--border-color)",
          borderRadius: 6,
          padding: 8,
          background: "var(--bg-secondary)",
          fontSize: 11,
        }}>
          <div style={{ display: "flex", gap: 7, flexWrap: "wrap", alignItems: "center" }}>
            <strong>{job.kind}</strong>
            <Chip tone={job.status === "failed" ? "warn" : "accent"}>{job.status}</Chip>
            <Chip>{Math.round(job.progress * 100)}%</Chip>
            <span style={{ color: "var(--text-secondary)" }}>{job.id}</span>
          </div>
          <div style={{
            height: 4, borderRadius: 2, background: "var(--border-color)",
            marginTop: 6, overflow: "hidden",
          }}>
            <div style={{
              width: `${Math.round(job.progress * 100)}%`,
              height: "100%",
              background: job.status === "failed" ? "#e06c75" : "#61afef",
            }} />
          </div>
          {job.message && <div style={{ marginTop: 4, color: "var(--text-secondary)" }}>{job.message}</div>}
          {job.error && <div style={{ marginTop: 4, color: "#e06c75" }}>{job.error}</div>}
        </div>
      ))}
    </div>
  );
}

export default function VmAnalysisPanel({ sessionId, isPhase2Ready, onJumpToSeq, sessions = [] }: Props) {
  const [result, setResult] = useState<VmAnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<Section>("regions");
  const [selectedCluster, setSelectedCluster] = useState<string | null>(null);
  const [startLine, setStartLine] = useState("");
  const [endLine, setEndLine] = useState("");
  const [hypotheses, setHypotheses] = useState<Hypothesis[]>([]);
  const [indexStatus, setIndexStatus] = useState<IndexStatus | null>(null);
  const [rightSessionId, setRightSessionId] = useState("");
  const [alignment, setAlignment] = useState<TraceAlignment | null>(null);
  const [compareLoading, setCompareLoading] = useState(false);
  const [compareError, setCompareError] = useState<string | null>(null);
  const [selectedInstanceIds, setSelectedInstanceIds] = useState<Set<string>>(new Set());
  const [lockedLabel, setLockedLabel] = useState("");
  const [editingHypothesis, setEditingHypothesis] = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");
  const [jobs, setJobs] = useState<AnalysisJob[]>([]);
  const [analyzeStartedAt, setAnalyzeStartedAt] = useState<number | null>(null);
  const [analyzeElapsedMs, setAnalyzeElapsedMs] = useState(0);
  const sessionKey = sessions
    .map(item => `${item.sessionId}:${item.fileName}`)
    .join("|");

  const refreshHypotheses = async () => {
    if (!sessionId) return;
    const items = await invoke<Hypothesis[]>("get_vm_hypotheses", { sessionId });
    setHypotheses(items);
  };

  useEffect(() => {
    setResult(null);
    setHypotheses([]);
    setError(null);
    setSelectedCluster(null);
    setRightSessionId(sessions.find(item => item.sessionId !== sessionId)?.sessionId ?? "");
    setAlignment(null);
    setCompareError(null);
    setSelectedInstanceIds(new Set());
    setLockedLabel("");
    setEditingHypothesis(null);
    setEditValue("");
    if (sessionId) {
      invoke<IndexStatus>("get_index_status", { sessionId })
        .then(setIndexStatus)
        .catch(() => setIndexStatus(null));
    } else {
      setIndexStatus(null);
    }
  }, [sessionId, sessionKey]);

  useEffect(() => {
    if (analyzeStartedAt == null) {
      setAnalyzeElapsedMs(0);
      return;
    }
    const timer = window.setInterval(() => {
      setAnalyzeElapsedMs(Date.now() - analyzeStartedAt);
    }, 500);
    return () => window.clearInterval(timer);
  }, [analyzeStartedAt]);

  useEffect(() => {
    let cancelled = false;
    const refresh = () => {
      invoke<AnalysisJob[]>("list_persisted_analysis_jobs")
        .then(items => { if (!cancelled) setJobs(items); })
        .catch(() => {});
    };
    refresh();
    const timer = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const compare = async () => {
    if (!sessionId || !rightSessionId) return;
    setCompareLoading(true);
    setCompareError(null);
    try {
      const result = await invoke<TraceAlignment>("compare_vm_traces", {
        leftSessionId: sessionId,
        rightSessionId,
      });
      setAlignment(result);
    } catch (cause) {
      setCompareError(String(cause));
    } finally {
      setCompareLoading(false);
    }
  };

  const applyHandlerConstraints = async (locked = false) => {
    if (!sessionId || selectedInstanceIds.size === 0) return;
    try {
      const ids = Array.from(selectedInstanceIds);
      const locked_labels = locked && lockedLabel.trim()
        ? Object.fromEntries(ids.map(id => [id, lockedLabel.trim()]))
        : {};
      const next = await invoke<VmAnalysisResult>("cluster_vm_handlers", {
        sessionId,
        mustLink: ids.slice(1).map(id => [ids[0], id]),
        cannotLink: [],
        lockedLabels: locked_labels,
      });
      setResult(next);
      setSelectedCluster(next.handler_clusters[0]?.id ?? null);
      setSelectedInstanceIds(new Set());
      await refreshHypotheses();
    } catch (cause) {
      setError(String(cause));
    }
  };

  const analyze = async () => {
    if (!sessionId || !isPhase2Ready) {
      setError("VM analysis requires at least the phase-2 function/memory index.");
      return;
    }
    setLoading(true);
    setAnalyzeStartedAt(Date.now());
    setError(null);
    try {
      const start = startLine.trim() ? Number(startLine) : null;
      const end = endLine.trim() ? Number(endLine) : null;
      if ((start != null && !Number.isFinite(start)) || (end != null && !Number.isFinite(end))) {
        throw new Error("Line ranges must be numeric");
      }
      const next = await invoke<VmAnalysisResult>("analyze_vm", {
        sessionId,
        startLine: start,
        endLine: end,
      });
      setResult(next);
      setSelectedCluster(next.handler_clusters[0]?.id ?? null);
      await refreshHypotheses();
      invoke<IndexStatus>("get_index_status", { sessionId }).then(setIndexStatus).catch(() => {});
    } catch (cause) {
      setError(String(cause));
    } finally {
      setLoading(false);
      setAnalyzeStartedAt(null);
    }
  };

  const selectedInstances = useMemo(() => {
    if (!result || !selectedCluster) return [];
    return result.handler_instances.filter(instance => instance.cluster_id === selectedCluster);
  }, [result, selectedCluster]);

  if (!sessionId) {
    return (
      <div style={{ flex: 1, display: "grid", placeItems: "center", color: "var(--text-secondary)", fontSize: 12 }}>
        Open a trace to inspect analysis jobs and VM results.
      </div>
    );
  }

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", minHeight: 0 }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 8, padding: "6px 10px",
        borderBottom: "1px solid var(--border-color)", flexWrap: "wrap",
      }}>
        <strong style={{ fontSize: 12 }}>VM Analysis</strong>
        <input value={startLine} onChange={e => setStartLine(e.target.value)} placeholder="start line"
          style={{ width: 90, fontSize: 11 }} />
        <input value={endLine} onChange={e => setEndLine(e.target.value)} placeholder="end line"
          style={{ width: 90, fontSize: 11 }} />
        <button onClick={analyze} disabled={loading || !isPhase2Ready} style={{ fontSize: 11, cursor: loading ? "wait" : "pointer" }}>
          {loading ? "Analyzing…" : "Analyze VM"}
        </button>
        <button onClick={() => setSection("jobs")} style={{ fontSize: 11, cursor: "pointer" }}>
          Jobs ({jobs.length})
        </button>
        {result && (
          <>
            <Chip tone="accent">{result.algorithm_version}</Chip>
            <Chip tone="warn">experimental</Chip>
            <Chip>{result.regions.length} regions</Chip>
            <Chip>{result.handler_clusters.length} clusters</Chip>
            <Chip>
              {result.handler_instances.length} handlers / {
                result.handler_instances.reduce((sum, instance) => sum + (instance.execution_count ?? 1), 0)
              } executions
            </Chip>
          </>
        )}
        {indexStatus && (
          <Chip tone={indexStatus.complete ? "neutral" : "warn"}>
            index {indexStatus.complete ? "complete" : "partial"} · {
              indexStatus.stages.filter(stage => stage.state === "complete").length
            }/{indexStatus.stages.length} stages
          </Chip>
        )}
      </div>

      {indexStatus && (
        <div style={{
          display: "flex", gap: 5, flexWrap: "wrap", padding: "4px 10px",
          borderBottom: "1px solid var(--border-color)", background: "var(--bg-secondary)",
        }}>
          {indexStatus.stages.map(stage => (
            <Chip
              key={stage.stage}
              tone={stage.state === "complete" ? "neutral" : stage.state === "failed" ? "warn" : "accent"}
            >{stage.stage}: {stage.state}</Chip>
          ))}
        </div>
      )}

      {error && (
        <div style={{ padding: 10, color: "#e06c75", fontSize: 12 }}>{error}</div>
      )}

      {loading && (
        <div style={{
          padding: "6px 10px",
          fontSize: 11,
          color: "var(--text-secondary)",
          borderBottom: "1px solid var(--border-color)",
        }}>
          Analyzing VM… {Math.floor(analyzeElapsedMs / 1000)}s elapsed
          {" · "}large traces extract events first, then run handler/CFG analysis
        </div>
      )}

      {!result && !loading && !error && (
        section === "jobs" ? (
          <div style={{ flex: 1, overflow: "auto", padding: 10 }}>
            <JobList jobs={jobs} />
          </div>
        ) : (
          <div style={{ flex: 1, display: "grid", placeItems: "center", color: "var(--text-secondary)", fontSize: 12 }}>
            {isPhase2Ready
              ? "Run a heuristic VM analysis. Every result links back to native trace evidence."
              : "Build phase-2 (function/memory) or full index to run VM analysis."}
          </div>
        )
      )}

      {result && (
        <>
          <div style={{ display: "flex", borderBottom: "1px solid var(--border-color)" }}>
            {(["regions", "handlers", "guest", "state", "ir", "cfg", "compare", "hypotheses", "jobs"] as const).map(name => (
              <button key={name} onClick={() => setSection(name)} style={{
                padding: "5px 12px", fontSize: 11, textTransform: "capitalize",
                background: section === name ? "var(--bg-secondary)" : "transparent",
                color: section === name ? "var(--text-primary)" : "var(--text-secondary)",
                border: "none",
                borderBottom: section === name ? "2px solid #61afef" : "2px solid transparent",
                cursor: "pointer",
              }}>{name}</button>
            ))}
          </div>

          <div style={{ flex: 1, overflow: "auto", padding: 10, display: "flex", flexDirection: "column", gap: 8 }}>
            {section === "regions" && result.regions.map(region => (
              <RegionCard key={region.id} region={region} onJumpToSeq={onJumpToSeq} />
            ))}
            {section === "regions" && result.dispatchers.length > 0 && (
              <div style={{ borderTop: "1px solid var(--border-color)", paddingTop: 8 }}>
                <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 6 }}>Dispatcher Candidates</div>
                {result.dispatchers.map(dispatcher => (
                  <div key={dispatcher.id} style={{
                    display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap",
                    padding: "5px 0", fontSize: 11,
                  }}>
                    <strong>{dispatcher.id}</strong>
                    <Chip>0x{dispatcher.address.toString(16)}</Chip>
                    <Chip>{dispatcher.kind}</Chip>
                    <Chip>{dispatcher.target_count} targets</Chip>
                    <Chip tone="accent">{pct(dispatcher.confidence)}</Chip>
                    <span style={{ color: "var(--text-secondary)" }}>{dispatcher.reason}</span>
                    <button onClick={() => onJumpToSeq(dispatcher.line)} style={{ fontSize: 11, cursor: "pointer" }}>
                      line {dispatcher.line}
                    </button>
                  </div>
                ))}
              </div>
            )}

            {section === "handlers" && (
              <div style={{ display: "grid", gridTemplateColumns: "minmax(220px, 1fr) minmax(260px, 1.4fr)", gap: 10, minHeight: 0 }}>
                <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                  {result.handler_clusters.map(cluster => (
                    <HandlerCard
                      key={cluster.id}
                      cluster={cluster}
                      selected={cluster.id === selectedCluster}
                      onSelect={() => setSelectedCluster(cluster.id)}
                      onJumpToSeq={onJumpToSeq}
                    />
                  ))}
                </div>
                <div style={{ border: "1px solid var(--border-color)", borderRadius: 6, padding: 10, background: "var(--bg-secondary)" }}>
                  <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 7 }}>
                    Instances {selectedCluster ? `· ${selectedCluster}` : ""}
                  </div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 7 }}>
                    <button disabled={selectedInstanceIds.size < 2} onClick={() => applyHandlerConstraints(false)}
                      style={{ fontSize: 10, cursor: selectedInstanceIds.size < 2 ? "not-allowed" : "pointer" }}>
                      Must-link selected
                    </button>
                    <input value={lockedLabel} onChange={event => setLockedLabel(event.target.value)}
                      placeholder="locked label" style={{ width: 100, fontSize: 10 }} />
                    <button disabled={selectedInstanceIds.size === 0 || !lockedLabel.trim()} onClick={() => applyHandlerConstraints(true)}
                      style={{ fontSize: 10, cursor: "pointer" }}>
                      Lock selected label
                    </button>
                  </div>
                  {selectedInstanceIds.size === 0 && (
                    <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>No instances for this cluster.</div>
                  )}
                  {selectedInstances.map(instance => (
                    <div key={instance.id} style={{
                      padding: "7px 0", borderTop: "1px solid var(--border-color)", fontSize: 11,
                    }}>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        <input
                          type="checkbox"
                          checked={selectedInstanceIds.has(instance.id)}
                          onChange={event => {
                            setSelectedInstanceIds(prev => {
                              const next = new Set(prev);
                              if (event.target.checked) next.add(instance.id);
                              else next.delete(instance.id);
                              return next;
                            });
                          }}
                        />
                        <strong>{instance.id}</strong>
                        <Chip>0x{instance.native_address.toString(16)}</Chip>
                        <Chip>{instance.execution_count ?? 1} executions</Chip>
                        <Chip>lines {instance.entry_line}–{Math.max(instance.entry_line, instance.end_line - 1)}</Chip>
                        {instance.unknown_effects.length > 0 && <Chip tone="warn">partial</Chip>}
                      </div>
                      <button
                        onClick={() => onJumpToSeq(instance.entry_line)}
                        style={{ marginTop: 5, fontSize: 11, cursor: "pointer" }}
                      >Jump to native handler</button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {section === "guest" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                <div style={{ display: "flex", gap: 7, flexWrap: "wrap", alignItems: "center" }}>
                  <Chip tone="accent">{result.guest_fetch_count} guest fetches</Chip>
                  <Chip>first {result.guest_fetch_first == null ? "n/a" : `0x${result.guest_fetch_first.toString(16)}`}</Chip>
                  <Chip>last {result.guest_fetch_last == null ? "n/a" : `0x${result.guest_fetch_last.toString(16)}`}</Chip>
                  <Chip>{result.guest_opcode_stats.length} opcodes</Chip>
                </div>
                {(() => {
                  const max = Math.max(1, ...result.guest_opcode_stats.map(item => item.count));
                  return result.guest_opcode_stats.map(stat => (
                    <div key={stat.opcode} style={{
                      display: "grid",
                      gridTemplateColumns: "70px 1fr 80px",
                      gap: 8,
                      alignItems: "center",
                      fontSize: 11,
                    }}>
                      <code>0x{stat.opcode.toString(16).padStart(2, "0")}</code>
                      <div style={{ height: 8, background: "var(--bg-tertiary)", borderRadius: 4, overflow: "hidden" }}>
                        <div style={{
                          width: `${Math.max(2, (stat.count / max) * 100)}%`,
                          height: "100%",
                          background: "#61afef",
                        }} />
                      </div>
                      <span style={{ color: "var(--text-secondary)", textAlign: "right" }}>{stat.count}</span>
                    </div>
                  ));
                })()}
              </div>
            )}

            {section === "state" && result.state_candidates.map(state => (
              <div key={`${state.role}-${state.location}`} style={{
                border: "1px solid var(--border-color)", borderRadius: 6, padding: 10,
                background: "var(--bg-secondary)", display: "flex", flexDirection: "column", gap: 5,
              }}>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                  <strong style={{ fontSize: 12 }}>{state.role}</strong>
                  <Chip tone="accent">{state.location}</Chip>
                  <Chip>{pct(state.confidence)}</Chip>
                  <Chip>lines {rangeLabel(state.lines)}</Chip>
                </div>
                <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                  {state.evidence.length} evidence refs · alternatives: {state.alternatives.join(", ") || "none"}
                </div>
              </div>
            ))}

            {section === "hypotheses" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                    {hypotheses.length} persisted hypotheses
                  </span>
                  <button onClick={refreshHypotheses} style={{ fontSize: 11, cursor: "pointer" }}>Refresh</button>
                  <button
                    onClick={async () => {
                      await invoke("undo_vm_override");
                      await refreshHypotheses();
                    }}
                    style={{ fontSize: 11, cursor: "pointer" }}
                  >Undo</button>
                  <button
                    onClick={async () => {
                      await invoke("redo_vm_override");
                      await refreshHypotheses();
                    }}
                    style={{ fontSize: 11, cursor: "pointer" }}
                  >Redo</button>
                </div>
                {hypotheses.map(hypothesis => (
                  <div key={hypothesis.id} style={{
                    border: "1px solid var(--border-color)",
                    borderRadius: 6,
                    padding: 9,
                    background: "var(--bg-secondary)",
                    display: "flex",
                    flexDirection: "column",
                    gap: 5,
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 7, flexWrap: "wrap" }}>
                      <strong style={{ fontSize: 11 }}>{hypothesis.kind}</strong>
                      <Chip tone="accent">{hypothesis.status}</Chip>
                      <Chip>{pct(hypothesis.confidence)}</Chip>
                      <Chip>rev {hypothesis.revision}</Chip>
                      {hypothesis.conflict && <Chip tone="warn">conflict</Chip>}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-secondary)", overflowWrap: "anywhere" }}>
                      {hypothesis.target} · {hypothesis.evidence.length} evidence refs
                    </div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <button
                        onClick={() => {
                          setEditingHypothesis(hypothesis.id);
                          setEditValue(JSON.stringify(hypothesis.inferred_value, null, 2));
                        }}
                        style={{ fontSize: 10, cursor: "pointer" }}
                      >Edit value</button>
                      {["confirmed", "locked", "rejected"].map(status => (
                        <button
                          key={status}
                          disabled={hypothesis.status === "locked"}
                          onClick={async () => {
                            try {
                              await invoke("validate_vm_hypothesis", {
                                hypothesisId: hypothesis.id,
                                status,
                                expectedRevision: hypothesis.revision,
                                note: null,
                              });
                              await refreshHypotheses();
                            } catch (cause) {
                              setError(String(cause));
                            }
                          }}
                          style={{ fontSize: 10, cursor: hypothesis.status === "locked" ? "not-allowed" : "pointer" }}
                        >{status}</button>
                      ))}
                      <button
                        onClick={async () => {
                          const impact = await invoke("dry_run_vm_impact", {
                            hypothesisId: hypothesis.id,
                            maxDepth: 32,
                          });
                          console.info("VM hypothesis impact", impact);
                        }}
                        style={{ fontSize: 10, cursor: "pointer" }}
                      >Dry-run impact</button>
                    </div>
                    {editingHypothesis === hypothesis.id && (
                      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                        <textarea
                          value={editValue}
                          onChange={event => setEditValue(event.target.value)}
                          rows={7}
                          style={{ width: "100%", fontFamily: "monospace", fontSize: 10 }}
                        />
                        <div style={{ display: "flex", gap: 6 }}>
                          <button
                            onClick={async () => {
                              try {
                                const value = JSON.parse(editValue);
                                await invoke("set_vm_override", {
                                  hypothesisId: hypothesis.id,
                                  value,
                                  status: hypothesis.status === "proposed" ? "confirmed" : hypothesis.status,
                                  expectedRevision: hypothesis.revision,
                                  note: "GUI value override",
                                });
                                setEditingHypothesis(null);
                                await refreshHypotheses();
                              } catch (cause) {
                                setError(String(cause));
                              }
                            }}
                            style={{ fontSize: 10, cursor: "pointer" }}
                          >Save override</button>
                          <button onClick={() => setEditingHypothesis(null)} style={{ fontSize: 10, cursor: "pointer" }}>
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {section === "compare" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>Compare with</span>
                  <select
                    value={rightSessionId}
                    onChange={event => setRightSessionId(event.target.value)}
                    style={{ fontSize: 11 }}
                  >
                    <option value="">Select trace</option>
                    {sessions
                      .filter(item => item.sessionId !== sessionId)
                      .map(item => (
                        <option key={item.sessionId} value={item.sessionId}>{item.fileName}</option>
                      ))}
                  </select>
                  <button disabled={!rightSessionId || compareLoading} onClick={compare} style={{ fontSize: 11, cursor: "pointer" }}>
                    {compareLoading ? "Aligning…" : "Align VM traces"}
                  </button>
                </div>
                {compareError && <div style={{ color: "#e06c75", fontSize: 11 }}>{compareError}</div>}
                {alignment && (
                  <>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <Chip tone="accent">confidence {pct(alignment.confidence)}</Chip>
                      <Chip>{alignment.summary.matched_clusters} matched</Chip>
                      <Chip tone="warn">{alignment.summary.left_only_clusters} left-only</Chip>
                      <Chip tone="warn">{alignment.summary.right_only_clusters} right-only</Chip>
                      <Chip>{alignment.summary.branch_divergences} divergences</Chip>
                      <Chip>{alignment.summary.uncertain_points} uncertain</Chip>
                    </div>
                    {alignment.summary.state_differences.map(diff => (
                      <div key={diff} style={{ fontSize: 11, color: "#e6a23c" }}>{diff}</div>
                    ))}
                    {alignment.summary.semantic_differences.map(diff => (
                      <div key={diff} style={{ fontSize: 11, color: "#e6a23c" }}>{diff}</div>
                    ))}
                    {alignment.summary.input_output_differences.map(diff => (
                      <div key={`io-${diff}`} style={{ fontSize: 11, color: "#e6a23c" }}>
                        I/O: {diff}
                      </div>
                    ))}
                    {alignment.summary.dependency_differences.map(diff => (
                      <div key={`dep-${diff}`} style={{ fontSize: 11, color: "#e6a23c" }}>
                        Dependency: {diff}
                      </div>
                    ))}
                    {alignment.points.map((point, index) => (
                      <div key={`${point.handler_cluster_left}-${point.handler_cluster_right}-${index}`} style={{
                        border: "1px solid var(--border-color)",
                        borderRadius: 6,
                        padding: 8,
                        background: "var(--bg-secondary)",
                        fontSize: 11,
                      }}>
                        <div style={{ display: "flex", gap: 7, flexWrap: "wrap", alignItems: "center" }}>
                          <strong>{point.handler_cluster_left ?? "gap"}</strong>
                          <span style={{ color: "var(--text-secondary)" }}>↔</span>
                          <strong>{point.handler_cluster_right ?? "gap"}</strong>
                          <Chip tone={point.feature_score < 0.65 ? "warn" : "neutral"}>
                            score {pct(point.feature_score)}
                          </Chip>
                        </div>
                        <div style={{ marginTop: 4, color: "var(--text-secondary)" }}>
                          left {rangeLabel(point.left_lines)} · right {rangeLabel(point.right_lines)}
                        </div>
                        {point.left_lines && point.left_lines.end > point.left_lines.start && (
                          <button onClick={() => onJumpToSeq(point.left_lines!.start)} style={{ marginTop: 4, fontSize: 10, cursor: "pointer" }}>
                            Jump to left evidence
                          </button>
                        )}
                      </div>
                    ))}
                    {alignment.warnings.map(warning => (
                      <div key={warning} style={{ fontSize: 11, color: "#e6a23c" }}>{warning}</div>
                    ))}
                  </>
                )}
              </div>
            )}

            {section === "jobs" && (
              <JobList jobs={jobs} />
            )}

            {section === "ir" && result.vm_instructions.map(instruction => (
              <div key={instruction.id} style={{
                border: "1px solid var(--border-color)",
                borderRadius: 6,
                padding: 9,
                background: "var(--bg-secondary)",
                display: "flex",
                flexDirection: "column",
                gap: 4,
              }}>
                <div style={{ display: "flex", gap: 7, flexWrap: "wrap", alignItems: "center" }}>
                  <strong style={{ fontSize: 11 }}>{instruction.operation}</strong>
                  <Chip tone="accent">{instruction.handler_instance_id}</Chip>
                  <Chip>{pct(instruction.confidence)}</Chip>
                  <Chip>{instruction.execution_count ?? 1} executions</Chip>
                  <Chip>lines {rangeLabel(instruction.native_lines)}</Chip>
                </div>
                <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                  reads: {instruction.state_reads.join(", ") || "none"}
                  {" · "}writes: {instruction.state_writes.join(", ") || "none"}
                </div>
                {instruction.memory_effects.length > 0 && (
                  <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                    memory: {instruction.memory_effects.join(", ")}
                  </div>
                )}
                {instruction.unknown_effects.length > 0 && (
                  <div style={{ fontSize: 11, color: "#e6a23c" }}>
                    unknown: {instruction.unknown_effects.join(", ")}
                  </div>
                )}
                <button onClick={() => onJumpToSeq(instruction.native_lines.start)} style={{ fontSize: 10, cursor: "pointer", alignSelf: "flex-start" }}>
                  Jump to native evidence
                </button>
              </div>
            ))}

            {section === "cfg" && result.cfg_edges.map((edge, index) => (
              <div key={`${edge.from}-${edge.to}-${index}`} style={{
                border: "1px solid var(--border-color)",
                borderRadius: 6,
                padding: 9,
                background: "var(--bg-secondary)",
                display: "flex",
                flexDirection: "column",
                gap: 4,
              }}>
                <div style={{ display: "flex", gap: 7, flexWrap: "wrap", alignItems: "center" }}>
                  <strong style={{ fontSize: 11 }}>{edge.from}</strong>
                  <span style={{ color: "var(--text-secondary)" }}>→</span>
                  <strong style={{ fontSize: 11 }}>{edge.to ?? "unresolved"}</strong>
                  <Chip tone="accent">{edge.kind}</Chip>
                  <Chip>{edge.execution_count ?? 1} executions</Chip>
                  <Chip tone={edge.confidence < 0.6 ? "warn" : "neutral"}>{pct(edge.confidence)}</Chip>
                  {edge.conditional && <Chip tone="warn">conditional</Chip>}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>{edge.reason}</div>
                {edge.evidence.length > 0 && edge.evidence[0].lines.end > edge.evidence[0].lines.start && (
                  <button onClick={() => onJumpToSeq(edge.evidence[0].lines.start)} style={{ fontSize: 10, cursor: "pointer", alignSelf: "flex-start" }}>
                    Jump to edge evidence
                  </button>
                )}
              </div>
            ))}

            {result.warnings.length > 0 && (
              <div style={{
                borderTop: "1px solid var(--border-color)", paddingTop: 8,
                color: "#e6a23c", fontSize: 11,
              }}>
                {result.warnings.map(warning => <div key={warning}>{warning}</div>)}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
