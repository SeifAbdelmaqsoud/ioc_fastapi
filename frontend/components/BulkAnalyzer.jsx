"use client";
import { useState } from "react";
import { bulkTriage, bulkAnalyze } from "@/lib/api";
import ThreatCard from "./ThreatCard";

const VERDICT_COLOR = { malicious: "#ef4444", suspicious: "#f59e0b", clean: "#22c55e" };

export default function BulkAnalyzer() {
  const [input, setInput]     = useState("");
  const [results, setResults] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(false);
  const [mode, setMode]       = useState("triage"); // "triage" | "full"
  const [error, setError]     = useState(null);
  const [expanded, setExpanded] = useState(null);

  function parseIOCs(text) {
    return text
      .split(/[\n,\s]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, mode === "full" ? 10 : 20);
  }

  async function run() {
    const iocs = parseIOCs(input);
    if (!iocs.length) return;
    setLoading(true);
    setError(null);
    setResults([]);
    setSummary(null);

    try {
      const data = mode === "triage" ? await bulkTriage(iocs) : await bulkAnalyze(iocs);
      setResults(data.results);
      setSummary({ total: data.total, malicious: data.malicious, suspicious: data.suspicious, clean: data.clean });
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  const iocCount = parseIOCs(input).length;

  return (
    <div>
      {/* Mode toggle */}
      <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
        {["triage", "full"].map((m) => (
          <button
            key={m}
            onClick={() => setMode(m)}
            style={{
              padding: "6px 16px",
              borderRadius: 6,
              border: "1px solid",
              borderColor: mode === m ? "#3b82f6" : "#1e2433",
              background: mode === m ? "#1e3a5f" : "transparent",
              color: mode === m ? "#93c5fd" : "#475569",
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            {m === "triage" ? "Triage (fast, no AI)" : "Full analysis (with AI)"}
          </button>
        ))}
      </div>

      {/* Input */}
      <div style={{ background: "#0f1117", border: "1px solid #1e2433", borderRadius: 12, padding: 16, marginBottom: 14 }}>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={"Paste IOCs — one per line or comma-separated\n\n8.8.8.8\nevil.com\nabc123def456..."}
          rows={6}
          style={{
            width: "100%", background: "#1a1f2e", border: "1px solid #2d3748",
            borderRadius: 8, padding: "12px 14px", color: "#e2e8f0", fontSize: 13,
            fontFamily: "monospace", outline: "none", resize: "vertical",
            lineHeight: 1.6,
          }}
        />
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 10 }}>
          <span style={{ fontSize: 12, color: "#475569" }}>
            {iocCount > 0 ? `${iocCount} IOC${iocCount !== 1 ? "s" : ""} detected` : "Paste IOCs above"}
            {mode === "full" && iocCount > 10 && (
              <span style={{ color: "#f59e0b", marginLeft: 8 }}>· capped at 10 for full mode</span>
            )}
          </span>
          <button
            onClick={run}
            disabled={loading || !iocCount}
            style={{
              background: loading || !iocCount ? "#1e2433" : "#3b82f6",
              color: loading || !iocCount ? "#475569" : "white",
              border: "none", borderRadius: 8, padding: "9px 20px",
              fontSize: 13, fontWeight: 600,
            }}
          >
            {loading ? "Scanning..." : `Scan ${iocCount || ""}`}
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{ background: "#1c0a0a", border: "1px solid #7f1d1d", borderRadius: 8, padding: 14, marginBottom: 14, color: "#fca5a5", fontSize: 13 }}>
          {error}
        </div>
      )}

      {/* Summary bar */}
      {summary && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 16 }}>
          {[
            { label: "Total",      value: summary.total,     color: "#94a3b8" },
            { label: "Malicious",  value: summary.malicious,  color: "#ef4444" },
            { label: "Suspicious", value: summary.suspicious, color: "#f59e0b" },
            { label: "Clean",      value: summary.clean,      color: "#22c55e" },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ background: "#0f1117", border: "1px solid #1e2433", borderRadius: 8, padding: "10px 14px", textAlign: "center" }}>
              <div style={{ fontSize: 20, fontWeight: 700, color }}>{value ?? "—"}</div>
              <div style={{ fontSize: 11, color: "#475569", marginTop: 2, textTransform: "uppercase", letterSpacing: 1 }}>{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Results list */}
      {results.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {results.map((r, i) => (
            <div key={i}>
              {r.error ? (
                <div style={{ background: "#1c0a0a", border: "1px solid #7f1d1d", borderRadius: 8, padding: "10px 14px", fontSize: 12, color: "#fca5a5" }}>
                  <span style={{ fontFamily: "monospace" }}>{r.ioc}</span> — {r.error}
                </div>
              ) : expanded === i ? (
                <div>
                  <ThreatCard result={r} />
                  <button
                    onClick={() => setExpanded(null)}
                    style={{ marginTop: 6, fontSize: 12, color: "#475569", background: "none", border: "none", padding: 0 }}
                  >
                    collapse ↑
                  </button>
                </div>
              ) : (
                <div onClick={() => setExpanded(i)} style={{ cursor: "pointer" }}>
                  <ThreatCard result={r} compact />
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
