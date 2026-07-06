// keys stay server-side, this just talks to our own FastAPI backend
const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

function formatError(detail) {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join(", ");
  return "Request failed";
}

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, options);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Unknown error" }));
    throw new Error(formatError(err.detail) || `HTTP ${res.status}`);
  }
  return res.json();
}

export const analyzeIOC = (ioc) =>
  request(`/analyze?ioc=${encodeURIComponent(ioc)}`);

export const analyzeIP     = (ip)     => request(`/analyze/ip/${ip}`);
export const analyzeDomain = (domain) => request(`/analyze/domain/${domain}`);
export const analyzeHash   = (hash)   => request(`/analyze/hash/${hash}`);
export const analyzeURL    = (url)    => request("/analyze/url", {
  method:  "POST",
  headers: { "Content-Type": "application/json" },
  body:    JSON.stringify({ url }),
});

export const fullReport = (ioc) =>
  request(`/analyze/report/${encodeURIComponent(ioc)}`);

export const bulkAnalyze = (iocs) =>
  request("/bulk", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ iocs }),
  });

export const bulkTriage = (iocs) =>
  request("/bulk/triage", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ iocs }),
  });

export const healthCheck = () => request("/health");
export const getStats    = () => request("/health/stats");
export const checkKeys   = () => request("/health/check-keys");
