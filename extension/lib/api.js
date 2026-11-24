// ALL knowledge about the URL Guard HTTP API lives in this file:
// paths, query flags, field names and error formats.
// If the API team renames a field or a path, this is the only file to change.
//
// The rest of the extension only sees the "internal" shape made by
// normalizePrediction() and ApiError.kind:
//   not_configured | offline | timeout | waking | bad_input | server | http | bad_response
//
// "waking" covers everything a sleeping free Render server can send while it boots:
// 502/503/504, an HTML "loading" page, any non-JSON body, or JSON without the
// expected fields. Such an answer is NEVER used as a verdict.

import { TIMEOUTS, MAX_URL_LENGTH } from "../config.js";
import { isLocalHost } from "./urlrules.js";

const PATHS = { health: "/health", predict: "/predict", batch: "/predict/batch" };
const MODEL_ONLY_QUERY = { model_only: "true" };
export const BATCH_MAX = 100;
export const TOO_LONG_MESSAGE = "URL too long to check";

// Errors worth retrying while a sleeping free server boots up.
const RETRYABLE = new Set(["timeout", "waking"]);

export class ApiError extends Error {
  constructor(kind, message, { status = null, detail = null, code = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
    this.detail = detail;
    this.code = code; // the API's "error" field, e.g. "invalid_request"
  }
}

const wakingError = (why, status = null) =>
  new ApiError("waking", "The server is waking up (" + why + "). This can take up to a minute.", { status });

function tooLongError(url) {
  return new ApiError(
    "bad_input",
    TOO_LONG_MESSAGE + " (" + String(url).length + " characters, the limit is " + MAX_URL_LENGTH + ").",
  );
}

const seconds = (ms) => Math.round(ms / 100) / 10;
const now = () => (globalThis.performance ? performance.now() : Date.now());
const num01 = (x) => (typeof x === "number" && Number.isFinite(x) && x >= 0 && x <= 1 ? x : null);
const finite = (x) => (typeof x === "number" && Number.isFinite(x) ? x : null);
const str = (x) => (typeof x === "string" ? x : null);

// Trims spaces and the trailing slash ("x.onrender.com/" -> "x.onrender.com"). Used by Settings.
export function normalizeBaseUrl(input) {
  const text = String(input ?? "").trim();
  if (!text) return { ok: false, error: "Enter the API base URL." };
  let u;
  try {
    u = new URL(text);
  } catch {
    return { ok: false, error: "Not a valid URL. It must start with https:// (for example your-app.onrender.com with https:// in front)." };
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") {
    return { ok: false, error: "The API URL must start with https:// or http://" };
  }
  const path = u.pathname.replace(/\/+$/, "");
  let warning = null;
  if (/\/(health|predict)(\/batch)?$/.test(path)) {
    warning = "Enter only the base URL, without /health or /predict at the end.";
  } else if (u.protocol === "http:" && !isLocalHost(u.hostname)) {
    warning = "Plain http:// sends the URLs unencrypted. Use https:// for a public server.";
  }
  return { ok: true, url: u.origin + path, warning };
}

// The human-readable part of a 422 "detail". Supported shapes:
//   live API:        {"error": "invalid_request", "detail": [{"field": "url", "message": "..."}]}
//   FastAPI default: {"detail": [{"loc": ["body", "url"], "msg": "..."}]}  or  {"detail": "text"}
export function detailText(detail) {
  if (detail == null) return "invalid input";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => {
        if (typeof d === "string") return d;
        if (d && typeof d.message === "string") return d.message; // live API: show its message as is
        if (d && typeof d.msg === "string") {
          const where = Array.isArray(d.loc) ? d.loc.filter((x) => x !== "body").join(".") : "";
          return where ? where + ": " + d.msg : d.msg;
        }
        return JSON.stringify(d);
      })
      .join("; ");
  }
  if (typeof detail === "object" && typeof detail.message === "string") return detail.message;
  if (typeof detail === "object" && typeof detail.msg === "string") return detail.msg;
  return JSON.stringify(detail);
}

function errorFromResponse(status, data) {
  if (status === 422 || status === 400) {
    const text = data && data.detail != null ? detailText(data.detail) : "The API rejected this input.";
    return new ApiError("bad_input", text, {
      status,
      detail: data?.detail ?? null,
      code: typeof data?.error === "string" ? data.error : null,
    });
  }
  if (status === 502 || status === 503 || status === 504) return wakingError("status " + status, status);
  if (status >= 500) {
    const msg =
      data?.error === "internal_error"
        ? "The API had an internal error (500)."
        : "The API failed with status " + status + ".";
    return new ApiError("server", msg, { status, code: typeof data?.error === "string" ? data.error : null });
  }
  if (status === 404) {
    return new ApiError("http", "API endpoint not found (404). Is the API URL in Settings correct?", { status });
  }
  return new ApiError("http", "Unexpected answer from the API (status " + status + ").", { status });
}

function buildUrl(base, path, query) {
  const url = new URL(String(base).replace(/\/+$/, "") + path);
  if (query) for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
  return url.href;
}

// One HTTP call with a hard timeout. Always resolves to parsed JSON or throws ApiError.
async function request(base, path, { method = "GET", body, query, timeoutMs, fetchFn } = {}) {
  if (!base) {
    throw new ApiError("not_configured", "No API URL is set. Open Settings and enter the API URL.");
  }
  const doFetch = fetchFn || globalThis.fetch;
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const timeoutError = () =>
    new ApiError("timeout", "No answer from the API within " + seconds(timeoutMs) + " s (it may be waking up).");
  const started = now();
  try {
    let res;
    try {
      res = await doFetch(buildUrl(base, path, query), {
        method,
        headers: body === undefined ? {} : { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
        cache: "no-store",
        credentials: "omit", // never send cookies to the API
      });
    } catch {
      if (timedOut) throw timeoutError();
      throw new ApiError("offline", "Cannot reach the API. Check the internet connection and the API URL in Settings.");
    }
    let text;
    try {
      text = await res.text();
    } catch {
      if (timedOut) throw timeoutError();
      throw new ApiError("offline", "The connection to the API was lost.");
    }
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = null;
    }
    if (!res.ok) throw errorFromResponse(res.status, data);
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      // Render's wake-up page is HTML with status 200: never treat it as an answer.
      throw wakingError(/<html|<!doctype/i.test(text || "") ? "got a web page instead of data" : "the answer was not JSON", res.status);
    }
    return { data, roundTripMs: Math.round((now() - started) * 10) / 10 };
  } finally {
    clearTimeout(timer);
  }
}

// API JSON -> internal shape. The verdict is ALWAYS is_malicious (never recomputed from
// probability vs threshold). If is_malicious or probability is missing, the answer did not
// come from the model (e.g. a proxy page while the server boots): ApiError("waking").
export function normalizePrediction(data, requestedUrl) {
  if (!data || typeof data !== "object" || Array.isArray(data)) throw wakingError("empty answer");
  if (typeof data.is_malicious !== "boolean" || num01(data.probability) === null) {
    throw wakingError("the answer is missing is_malicious or probability");
  }
  return {
    url: str(data.url) ?? requestedUrl,
    normalizedUrl: str(data.normalized_url),
    malicious: data.is_malicious,
    probability: data.probability,
    threshold: num01(data.threshold),
    decidedBy: data.decided_by === "trusted_list" ? "trusted_list" : "model",
    reasons: Array.isArray(data.reasons) ? data.reasons.filter((r) => typeof r === "string") : [],
    serverLatencyMs: finite(data.latency_ms),
    modelVersion: str(data.model_version),
  };
}

function toApiError(err) {
  return err instanceof ApiError ? err : new ApiError("bad_response", String(err?.message || err));
}

// POST /predict. Throws ApiError.
export async function predict(base, url, { modelOnly = false, timeoutMs = TIMEOUTS.predictMs, fetchFn } = {}) {
  if (String(url).length > MAX_URL_LENGTH) throw tooLongError(url); // never sent to the API
  const { data, roundTripMs } = await request(base, PATHS.predict, {
    method: "POST",
    body: { url },
    query: modelOnly ? MODEL_ONLY_QUERY : null,
    timeoutMs,
    fetchFn,
  });
  return { ...normalizePrediction(data, url), roundTripMs, modelOnly, checkedAt: Date.now() };
}

// Used by the automatic protection: NEVER throws.
// { ok: true, result } or { ok: false, error } -> the caller allows the page (fail open).
export async function predictFailOpen(base, url, options = {}) {
  try {
    return { ok: true, result: await predict(base, url, options) };
  } catch (err) {
    return { ok: false, error: toApiError(err) };
  }
}

// Used by the popup: keeps retrying while the free server wakes up.
// onWaiting({ attempt, error, msLeft }) is called before each retry.
export async function predictWithRetry(
  base,
  url,
  {
    modelOnly = false,
    totalMs = TIMEOUTS.popupTotalMs,
    firstTimeoutMs = TIMEOUTS.popupFirstTryMs,
    retryTimeoutMs = TIMEOUTS.popupRetryTryMs,
    retryDelayMs = 3000, // pause after a fast "loading" page or 503 (gentle on the free server)
    onWaiting,
    fetchFn,
  } = {},
) {
  const deadline = Date.now() + totalMs;
  let attempt = 0;
  for (;;) {
    attempt += 1;
    const left = deadline - Date.now();
    const timeoutMs = Math.max(250, Math.min(attempt === 1 ? firstTimeoutMs : retryTimeoutMs, left));
    try {
      return await predict(base, url, { modelOnly, timeoutMs, fetchFn });
    } catch (err) {
      const e = toApiError(err);
      if (!RETRYABLE.has(e.kind)) throw e;
      const msLeft = deadline - Date.now();
      if (msLeft < 300) {
        throw new ApiError("timeout", "The server did not wake up within " + seconds(totalMs) + " s. Try again in a moment.");
      }
      if (onWaiting) onWaiting({ attempt, error: e, msLeft });
      // A timeout already waited; a fast 503 needs a pause before asking again.
      if (e.kind !== "timeout") await new Promise((r) => setTimeout(r, Math.min(retryDelayMs, msLeft)));
    }
  }
}

// POST /predict/batch (max 100 URLs).
export async function predictBatch(base, urls, { timeoutMs = 15000, fetchFn } = {}) {
  if (!Array.isArray(urls) || urls.length === 0) throw new ApiError("bad_input", "Give at least one URL.");
  if (urls.length > BATCH_MAX) throw new ApiError("bad_input", "At most " + BATCH_MAX + " URLs per batch.");
  const tooLong = urls.find((u) => String(u).length > MAX_URL_LENGTH);
  if (tooLong !== undefined) throw tooLongError(tooLong);
  const { data, roundTripMs } = await request(base, PATHS.batch, { method: "POST", body: { urls }, timeoutMs, fetchFn });
  if (!Array.isArray(data.results)) throw wakingError("the batch answer has no results list");
  return {
    results: data.results.map((r, i) => normalizePrediction(r, urls[i])),
    count: finite(data.count) ?? data.results.length,
    serverLatencyMs: finite(data.latency_ms),
    roundTripMs,
  };
}

// GET /health. NEVER throws. state: online | waking | offline | not_configured | error
export async function checkHealth(base, { timeoutMs = TIMEOUTS.healthMs, fetchFn } = {}) {
  try {
    const { data, roundTripMs } = await request(base, PATHS.health, { timeoutMs, fetchFn });
    if (typeof data.status !== "string") throw wakingError("the health answer has no status");
    const ready = data.status === "ok" && data.model_loaded !== false;
    return {
      state: ready ? "online" : "waking",
      message: ready ? "Online" : "Server is up but the model is still loading",
      model: str(data.model),
      version: str(data.model_version) ?? str(data.version), // live API sends model_version
      uptimeS: finite(data.uptime_s),
      roundTripMs,
    };
  } catch (err) {
    const e = toApiError(err);
    if (e.kind === "timeout" || e.kind === "waking") {
      return { state: "waking", message: "Waking up (free server, can take up to a minute)", error: e };
    }
    if (e.kind === "offline") return { state: "offline", message: "Offline (cannot reach the API)", error: e };
    if (e.kind === "not_configured") return { state: "not_configured", message: e.message, error: e };
    return { state: "error", message: e.message, error: e };
  }
}

// Settings page "Test connection": polls /health for up to totalMs while the server wakes.
export async function waitForHealth(base, { totalMs = TIMEOUTS.popupTotalMs, onWaiting, fetchFn } = {}) {
  const deadline = Date.now() + totalMs;
  let attempt = 0;
  for (;;) {
    attempt += 1;
    const left = deadline - Date.now();
    const health = await checkHealth(base, {
      timeoutMs: Math.max(250, Math.min(attempt === 1 ? TIMEOUTS.healthMs : TIMEOUTS.popupRetryTryMs, left)),
      fetchFn,
    });
    if (health.state !== "waking" || deadline - Date.now() < 300) return health;
    if (onWaiting) onWaiting({ attempt, health, msLeft: deadline - Date.now() });
    // A fast "loading" page or 503 gets a 3 s pause, so a waking free server is asked
    // at most ~20 times a minute.
    if (health.error?.kind !== "timeout") await new Promise((r) => setTimeout(r, 3000));
  }
}
