// Which URLs get checked, and how text typed in the popup becomes a URL.
// No chrome.* here, so the Node tests can import it.

import { MAX_URL_LENGTH } from "../config.js";

export const SKIP_REASONS = {
  invalid: "Not a valid web address",
  scheme: "Browser or extension page (only http and https pages are checked)",
  local: "Local address (localhost / 127.0.0.1) is never checked",
  api: "This is the URL Guard API itself",
  too_long: "URL too long to check", // > MAX_URL_LENGTH: automatic check skipped (fail open)
};

// "a.com/x#part" -> "a.com/x". The part after # never reaches the server.
export function stripHash(url) {
  const text = String(url);
  const i = text.indexOf("#");
  return i === -1 ? text : text.slice(0, i);
}

export function isHttpUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

export function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

export function isLocalHost(hostname) {
  const h = String(hostname).toLowerCase().replace(/^\[|\]$/g, "");
  return (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h === "::1" ||
    h === "0.0.0.0" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)
  );
}

// Returns null when the URL should be checked, otherwise a key of SKIP_REASONS.
export function skipReason(url, { apiBase = "" } = {}) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return "invalid";
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return "scheme"; // chrome:, file:, about:, data:, chrome-extension: ...
  if (isLocalHost(u.hostname)) return "local";
  const apiHost = hostOf(apiBase);
  if (apiHost && u.hostname.toLowerCase() === apiHost) return "api";
  if (String(url).length > MAX_URL_LENGTH) return "too_long";
  return null;
}

const OTHER_SCHEME_WITH_SLASHES = /^[a-z][a-z0-9+.-]*:\/\//i; // ftp://, ws://, chrome://
const OTHER_SCHEME_NO_SLASHES =
  /^(javascript|data|mailto|file|about|chrome|chrome-extension|blob|vbscript|tel|sms|view-source):/i;

// Validates what the user typed in the popup.
// Returns { ok: true, url, addedScheme } or { ok: false, error }.
export function prepareUserInput(raw) {
  const text = String(raw ?? "").trim();
  if (!text) return { ok: false, error: "Please type or paste a URL first." };
  if (/\s/.test(text)) return { ok: false, error: "A URL cannot contain spaces or line breaks." };

  let candidate = text;
  let addedScheme = false;
  if (/^https?:\/\//i.test(text)) {
    // already fine
  } else if (OTHER_SCHEME_WITH_SLASHES.test(text) || OTHER_SCHEME_NO_SLASHES.test(text)) {
    return { ok: false, error: "Only http:// and https:// web addresses can be checked." };
  } else {
    candidate = "https://" + text.replace(/^\/+/, "");
    addedScheme = true;
  }

  if (candidate.length > MAX_URL_LENGTH) {
    return {
      ok: false,
      error:
        SKIP_REASONS.too_long + " (" + candidate.length + " characters, the limit is " + MAX_URL_LENGTH + ").",
    };
  }

  let u;
  try {
    u = new URL(candidate);
  } catch {
    return { ok: false, error: "That does not look like a valid web address." };
  }
  const host = u.hostname;
  if (!host || (!host.includes(".") && !host.startsWith("[") && host !== "localhost")) {
    return { ok: false, error: "That does not look like a web address (example: example.com)." };
  }
  return { ok: true, url: candidate, addedScheme };
}
