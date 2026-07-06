"use client";
import { useState, useEffect } from "react";
import ThreatCard from "./ThreatCard";
import BulkAnalyzer from "./BulkAnalyzer";
import { analyzeIOC, getStats, checkKeys } from "@/lib/api";

function detectType(value) {
  value = value.trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value))    return "IP";
  if (/^[a-f0-9]{32,64}$/i.test(value))           return "Hash";
  if (value.startsWith("http"))                    return "URL";
  if (value.includes("."))                         return "Domain";
  return null;
}

function StatusDot({ status }) {
  const color = status === "ok" ? "#22c55e" : status === "error" ? "#ef4444" : "#475569";
  return <div style={{ width: 6, height: 6, borderRadius: "50%", background: color, boxShadow: status === "ok" ? `0 0 6px ${color}` : "none" }} />;
}

export default function ThreatDashboard() {
  const [tab, setTab]         = useState("single");  // "single" | "bulk"
  const [ioc, setIoc]         = useState("");
  const [result, setResult]   = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);
  const [stats, setStats]     = useState(null);
  const [apiStatus, setApiStatus] = useState(null);

  // Load stats and API status on mount
  useEffect(() => {
    getStats().then(setStats).catch(() => {});
    checkKeys().then(setApiStatus).catch(() => {});
  }, []);

  async function analyze() {
    if (!ioc.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await analyzeIOC(ioc.trim());
      setResult(data);
      setHistory((prev) => [data, ...prev.filter((h) => h.ioc !== data.ioc).slice(0, 9)]);
      getStats().then(setStats).catch(() => {});
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  const detectedType = detectType(ioc);

  return (
    <div style={{ minHeight: "100vh", background: "#08090d", color: "#e2e8f0", padding: "40px 20px" }}>
      <div style={{ maxWidth: 740, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 36 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <StatusDot status={apiStatus?.virustotal === "ok" && apiStatus?.openrouter === "ok" ? "ok" : apiStatus ? "error" : null} />
              <span style={{ fontSize: 11, color: "#64748b", letterSpacing: 2, textTransform: "uppercase" }}>
                Threat Intelligence
              </span>
            </div>
            <h1 style={{ fontSize: 26, fontWeight: 700, color: "#f1f5f9", margin: 0 }}>IOC Analyzer</h1>
            <p style={{ color: "#475569", marginTop: 6, fontSize: 13 }}>
              Powered by VirusTotal + AI
            </p>
          </div>

          {/* Session stats */}
          {stats && (
            <div style={{ display: "flex", gap: 12 }}>
              {[
                { label: "Analyzed", value: stats.total },
                { label: "Malicious", value: stats.malicious, color: "#ef4444" },
                { label: "Clean", value: stats.clean, color: "#22c55e" },
              ].map(({ label, value, color }) => (
                <div key={label} style={{ background: "#0f1117", border: "1px solid #1e2433", borderRadius: 8, padding: "8px 14px", textAlign: "center" }}>
                  <div style={{ fontSize: 16, fontWeight: 700, color: color || "#e2e8f0" }}>{value}</div>
                  <div style={{ fontSize: 10, color: "#475569", textTransform: "uppercase", letterSpacing: 1 }}>{label}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Tab switcher */}
        <div style={{ display: "flex", gap: 4, background: "#0f1117", border: "1px solid #1e2433", borderRadius: 10, padding: 4, marginBottom: 20, width: "fit-content" }}>
          {["single", "bulk"].map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              style={{
                padding: "7px 20px",
                borderRadius: 7,
                border: "none",
                background: tab === t ? "#1e2433" : "transparent",
                color: tab === t ? "#e2e8f0" : "#475569",
                fontSize: 13,
                fontWeight: tab === t ? 600 : 400,
              }}
            >
              {t === "single" ? "Single IOC" : "Bulk scan"}
            </button>
          ))}
        </div>

        {/* Single IOC tab */}
        {tab === "single" && (
          <>
            <div style={{ background: "#0f1117", border: "1px solid #1e2433", borderRadius: 12, padding: 18, marginBottom: 20 }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <input
                  value={ioc}
                  onChange={(e) => setIoc(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && analyze()}
                  placeholder="8.8.8.8 · evil.com · sha256hash · https://..."
                  style={{
                    flex: 1, background: "#1a1f2e", border: "1px solid #2d3748",
                    borderRadius: 8, padding: "11px 14px", color: "#e2e8f0",
                    fontSize: 13, outline: "none", fontFamily: "monospace",
                  }}
                />
                <button
                  onClick={analyze}
                  disabled={loading || !ioc.trim()}
                  style={{
                    background: loading || !ioc.trim() ? "#1e2433" : "#3b82f6",
                    color: loading || !ioc.trim() ? "#475569" : "white",
                    border: "none", borderRadius: 8, padding: "11px 22px",
                    fontSize: 13, fontWeight: 600, whiteSpace: "nowrap",
                  }}
                >
                  {loading ? "Scanning..." : "Analyze"}
                </button>
              </div>

              {detectedType && (
                <div style={{ marginTop: 8, fontSize: 12, color: "#64748b" }}>
                  Detected: <span style={{ color: "#94a3b8", fontWeight: 600 }}>{detectedType}</span>
                </div>
              )}
            </div>

            {/* API key status */}
            {apiStatus && (
              <div style={{ display: "flex", gap: 12, marginBottom: 20 }}>
                {[
                  { label: "VirusTotal", status: apiStatus.virustotal },
                  { label: "OpenRouter", status: apiStatus.openrouter },
                ].map(({ label, status }) => (
                  <div key={label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <StatusDot status={status === "ok" ? "ok" : "error"} />
                    <span style={{ fontSize: 11, color: "#475569" }}>{label}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Error */}
            {error && (
              <div style={{ background: "#1c0a0a", border: "1px solid #7f1d1d", borderRadius: 10, padding: 14, marginBottom: 18, color: "#fca5a5", fontSize: 13 }}>
                {error}
              </div>
            )}

            {/* Result */}
            {result && <div style={{ marginBottom: 24 }}><ThreatCard result={result} /></div>}

            {/* History */}
            {history.length > 0 && (
              <div>
                <div style={{ fontSize: 11, color: "#64748b", letterSpacing: 2, textTransform: "uppercase", marginBottom: 10 }}>
                  Recent lookups
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {history.map((item, i) => (
                    <div
                      key={i}
                      onClick={() => { setIoc(item.ioc); setResult(item); }}
                      style={{ cursor: "pointer" }}
                    >
                      <ThreatCard result={item} compact />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}

        {/* Bulk scan tab */}
        {tab === "bulk" && <BulkAnalyzer />}
      </div>
    </div>
  );
}
