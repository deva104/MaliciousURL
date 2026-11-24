// Builds and parses the warning page address:
//   warning.html?u=<blocked url>&p=<probability>&r=<reasons as JSON>&d=<decided_by>
// The warning page is "web accessible" (needed for the instant redirect rules),
// so a website could open it with made-up parameters. Everything parsed here is
// therefore treated as untrusted text: validated, capped, and shown with textContent only.

import { MAX_REASONS_SHOWN } from "../config.js";
import { isHttpUrl } from "./urlrules.js";

const MAX_REASON_CHARS = 200;

export function cleanReasons(list) {
  if (!Array.isArray(list)) return [];
  return list
    .filter((r) => typeof r === "string")
    .map((r) => r.trim())
    .filter(Boolean)
    .slice(0, MAX_REASONS_SHOWN)
    .map((r) => (r.length > MAX_REASON_CHARS ? r.slice(0, MAX_REASON_CHARS - 1) + "…" : r));
}

// Accepts a JSON array (normal case), a JSON string, or "a|b|c" as a fallback.
export function parseReasons(raw) {
  if (raw == null || raw === "") return [];
  try {
    const value = JSON.parse(raw);
    if (Array.isArray(value)) return cleanReasons(value);
    if (typeof value === "string") return cleanReasons([value]);
    return [];
  } catch {
    return cleanReasons(String(raw).split("|"));
  }
}

export function buildWarningQuery({ url, probability, reasons, decidedBy }) {
  const q = new URLSearchParams();
  q.set("u", url);
  if (typeof probability === "number" && Number.isFinite(probability)) {
    q.set("p", String(Math.round(probability * 1000) / 1000));
  }
  q.set("r", JSON.stringify(cleanReasons(reasons)));
  q.set("d", decidedBy === "trusted_list" ? "trusted_list" : "model");
  return q.toString();
}

// Path inside the extension, e.g. for a declarativeNetRequest redirect.extensionPath.
export function buildWarningPath(info) {
  return "/warning.html?" + buildWarningQuery(info);
}

export function parseWarningQuery(search) {
  const q = new URLSearchParams(search);
  const url = q.get("u") || "";
  const pRaw = q.get("p");
  const p = pRaw === null || pRaw.trim() === "" ? NaN : Number(pRaw);
  const d = q.get("d");
  return {
    url,
    urlValid: isHttpUrl(url),
    probability: Number.isFinite(p) && p >= 0 && p <= 1 ? p : null,
    reasons: parseReasons(q.get("r")),
    decidedBy: d === "model" || d === "trusted_list" ? d : null,
  };
}

export function decidedByLabel(decidedBy) {
  if (decidedBy === "trusted_list") return "Trusted list";
  if (decidedBy === "model") return "ML model";
  return "Unknown";
}

export function formatPercent(p) {
  return typeof p === "number" && Number.isFinite(p) ? Math.round(p * 100) + "%" : "unknown";
}

// Long URLs are cut for display; the page offers "Show full address".
export function truncateUrl(url, max = 90) {
  const text = String(url);
  if (text.length <= max) return { text, truncated: false };
  return { text: text.slice(0, max - 1) + "…", truncated: true };
}
