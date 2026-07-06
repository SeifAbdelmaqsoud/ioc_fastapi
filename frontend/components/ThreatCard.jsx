"use client";

const VERDICT = {
  malicious: { color: "#ef4444", bg: "#1a0505", border: "#ef444430", label: "MALICIOUS", dot: "#ef4444" },
  suspicious: { color: "#f59e0b", bg: "#1a0f00", border: "#f59e0b30", label: "SUSPICIOUS", dot: "#f59e0b" },
  clean:      { color: "#22c55e", bg: "#031a0a", border: "#22c55e30", label: "CLEAN",     dot: "#22c55e" },
};

// visual ratio of malicious/total engines
function DetectionBar({ malicious, suspicious, total }) {
  if (!total) return null;
  const malPct = Math.round((malicious / total) * 100);
  const susPct = Math.round((suspicious / total) * 100);
  const cleanPct = 100 - malPct - susPct;
  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
        <span style={{ fontSize: 11, color: "#64748b", letterSpacing: 1, textTransform: "uppercase" }}>Engine coverage</span>
        <span style={{ fontSize: 11, color: "#64748b" }}>{total} engines</span>
      </div>
      <div style={{ display: "flex", height: 6, borderRadius: 3, overflow: "hidden", background: "#1e2433" }}>
        {malPct  > 0 && <div style={{ width: `${malPct}%`,   background: "#ef4444" }} />}
        {susPct  > 0 && <div style={{ width: `${susPct}%`,  background: "#f59e0b" }} />}
        {cleanPct > 0 && <div style={{ width: `${cleanPct}%`, background: "#22c55e22" }} />}
      </div>
    </div>
  );
}

export default function ThreatCard({ result, compact = false }) {
  if (!result) return null;
  const v = VERDICT[result.verdict] || VERDICT.clean;

  if (compact) {
    return (
      <div style={{
        background: "#0f1117",
        border: `1px solid ${v.border}`,
        borderRadius: 10,
        padding: "12px 16px",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        gap: 12,
      }}>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontFamily: "monospace", fontSize: 13, color: "#94a3b8", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {result.ioc}
          </div>
          <div style={{ fontSize: 11, color: "#475569", marginTop: 2 }}>
            {result.type?.toUpperCase()} · {result.detections}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: v.dot }} />
          <span style={{ fontSize: 11, fontWeight: 700, color: v.color, letterSpacing: 1 }}>{v.label}</span>
        </div>
      </div>
    );
  }

  return (
    <div style={{
      background: v.bg,
      border: `1px solid ${v.border}`,
      borderRadius: 12,
      overflow: "hidden",
    }}>
      {/* Header row */}
      <div style={{ padding: "16px 20px", display: "flex", justifyContent: "space-between", alignItems: "flex-start", borderBottom: `1px solid ${v.border}` }}>
        <div>
          <div style={{ fontSize: 11, color: "#64748b", letterSpacing: 2, textTransform: "uppercase", marginBottom: 4 }}>Verdict</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: v.color, boxShadow: `0 0 8px ${v.color}` }} />
            <span style={{ fontSize: 20, fontWeight: 800, color: v.color }}>{v.label}</span>
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ fontSize: 11, color: "#64748b", letterSpacing: 2, textTransform: "uppercase", marginBottom: 4 }}>Detections</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: "#e2e8f0" }}>{result.detections}</div>
        </div>
      </div>

      {/* Body */}
      <div style={{ padding: "16px 20px" }}>
        {/* Tags */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 16 }}>
          <span style={{ background: "#1e2433", padding: "3px 10px", borderRadius: 20, fontSize: 11, color: "#94a3b8", fontWeight: 600 }}>
            {result.type?.toUpperCase()}
          </span>
          <span style={{ background: "#1e2433", padding: "3px 10px", borderRadius: 20, fontSize: 11, color: "#64748b", fontFamily: "monospace", maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {result.ioc}
          </span>
          {result.tags?.map((tag) => (
            <span key={tag} style={{ background: "#1e2433", padding: "3px 10px", borderRadius: 20, fontSize: 11, color: "#64748b" }}>
              {tag}
            </span>
          ))}
        </div>

        {/* Extra metadata depending on type */}
        {(result.country || result.as_owner || result.registrar || result.file_name) && (
          <div style={{ background: "#0a0d14", border: "1px solid #1e2433", borderRadius: 8, padding: "12px 14px", marginBottom: 16, display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px 16px" }}>
            {result.country   && <Meta label="Country"    value={result.country} />}
            {result.as_owner  && <Meta label="AS owner"   value={result.as_owner} />}
            {result.registrar && <Meta label="Registrar"  value={result.registrar} />}
            {result.file_name && <Meta label="File name"  value={result.file_name} />}
            {result.file_type && <Meta label="File type"  value={result.file_type} />}
            {result.file_size && <Meta label="File size"  value={`${(result.file_size / 1024).toFixed(1)} KB`} />}
            {result.http_status && <Meta label="HTTP status" value={result.http_status} />}
            {result.final_url && <Meta label="Final URL"  value={result.final_url} />}
          </div>
        )}

        {/* Detection bar */}
        <DetectionBar malicious={result.malicious} suspicious={result.suspicious} total={result.total} />

        {/* LLM Summary */}
        {result.summary && (
          <div style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid #1e2433" }}>
            <div style={{ fontSize: 11, color: "#64748b", letterSpacing: 2, textTransform: "uppercase", marginBottom: 8 }}>
              Analyst summary
            </div>
            <p style={{ color: "#cbd5e1", fontSize: 13, lineHeight: 1.8, margin: 0 }}>{result.summary}</p>
          </div>
        )}
      </div>
    </div>
  );
}

function Meta({ label, value }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: "#475569", textTransform: "uppercase", letterSpacing: 1, marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 12, color: "#94a3b8", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</div>
    </div>
  );
}
