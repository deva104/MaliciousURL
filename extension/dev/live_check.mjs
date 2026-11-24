// Live smoke test against the deployed API. NOT a load test: hard cap of 10 requests.
// It uses the extension's own lib/api.js, so it also checks that our parsing matches the live API.
//
//   node extension/dev/live_check.mjs                  (uses RENDER_API_BASE from config.js)
//   node extension/dev/live_check.mjs --base https://other.onrender.com
//
// Calls: /health (repeated only while the free server wakes up, max 4 times),
//        /predict google.com, /predict IP + login style URL, /predict?model_only=true,
//        /predict with invalid (empty) input.   Exit code 1 if a contract check fails.

import { RENDER_API_BASE, MAX_URL_LENGTH } from "../config.js";
import { checkHealth, predict, normalizeBaseUrl, ApiError } from "../lib/api.js";

const MAX_REQUESTS = 10;
const MAX_HEALTH_TRIES = 4;
const WAKE_PAUSE_MS = 10_000;
const TIMEOUT_MS = 30_000;

// ---------- arguments ----------
let base = RENDER_API_BASE;
const argv = process.argv.slice(2);
if (argv[0] === "--base" && argv[1]) base = argv[1];
const checkedBase = normalizeBaseUrl(base);
if (!checkedBase.ok) {
  console.error("Bad base URL:", checkedBase.error);
  process.exit(2);
}
base = checkedBase.url;

// ---------- fetch with a hard request cap; prints every raw answer ----------
let requests = 0;
async function cappedFetch(url, init = {}) {
  if (requests >= MAX_REQUESTS) throw new Error("request cap of " + MAX_REQUESTS + " reached");
  requests += 1;
  const started = Date.now();
  const res = await fetch(url, init);
  const text = await res.clone().text();
  const path = new URL(url).pathname + new URL(url).search;
  console.log(
    "  [#" + requests + "] " + (init.method || "GET") + " " + path + (init.body ? " " + init.body : "") +
      "\n        -> " + res.status + " " + (res.headers.get("content-type") || "") + " (" + (Date.now() - started) + " ms)" +
      "\n        " + (text.length > 400 ? text.slice(0, 400) + "..." : text),
  );
  return res;
}

const checks = [];
function check(name, ok, info = "") {
  checks.push({ name, ok });
  console.log("  " + (ok ? "PASS" : "FAIL") + "  " + name + (info ? "  (" + info + ")" : ""));
}

const pct = (p) => (typeof p === "number" ? Math.round(p * 100) + "%" : String(p));
function show(r) {
  console.log(
    "  extension sees: " + (r.malicious ? "MALICIOUS" : "SAFE") + ", risk " + pct(r.probability) +
      ", threshold " + pct(r.threshold) + ", decided by " + r.decidedBy +
      ", reasons " + JSON.stringify(r.reasons) + ", server " + r.serverLatencyMs + " ms, round trip " +
      Math.round(r.roundTripMs) + " ms, model " + r.modelVersion,
  );
}

function contractChecks(label, r) {
  check(label + ": threshold is 0.8", r.threshold === 0.8, "got " + r.threshold);
  if (r.malicious) check(label + ": malicious has 1-3 reasons", r.reasons.length >= 1 && r.reasons.length <= 3, r.reasons.length + " reasons");
  else check(label + ": safe has no reasons", r.reasons.length === 0, r.reasons.length + " reasons");
}

async function step(title, fn) {
  console.log("\n== " + title);
  try {
    await fn();
  } catch (err) {
    const kind = err instanceof ApiError ? err.kind : "crash";
    check(title, false, kind + ": " + (err?.message || err));
  }
}

console.log("URL Guard live check against " + base + " (max " + MAX_REQUESTS + " requests)");

// 1. health, waiting for a sleeping free server (max 4 tries)
let awake = false;
await step("GET /health", async () => {
  for (let attempt = 1; attempt <= MAX_HEALTH_TRIES; attempt++) {
    const h = await checkHealth(base, { timeoutMs: TIMEOUT_MS, fetchFn: cappedFetch });
    console.log("  extension sees: state=" + h.state + (h.model ? ", model " + h.model : "") + (h.version ? " " + h.version : "") +
      (typeof h.uptimeS === "number" ? ", uptime " + h.uptimeS + " s" : "") + (h.error ? ", " + h.error.message : ""));
    if (h.state === "online") {
      awake = true;
      break;
    }
    if (h.state !== "waking" || attempt === MAX_HEALTH_TRIES) break;
    console.log("  server is waking up, waiting " + WAKE_PAUSE_MS / 1000 + " s ...");
    await new Promise((r) => setTimeout(r, WAKE_PAUSE_MS));
  }
  check("health is online", awake);
});

if (!awake) {
  console.log("\nThe API did not wake up; skipping the /predict calls to stay polite.");
} else {
  await step("POST /predict google.com", async () => {
    const r = await predict(base, "https://www.google.com/", { timeoutMs: TIMEOUT_MS, fetchFn: cappedFetch });
    show(r);
    check("google.com is safe", r.malicious === false);
    contractChecks("google.com", r);
  });

  await step("POST /predict IP + login style URL", async () => {
    // 203.0.113.0/24 is reserved for documentation: nothing real lives there.
    const r = await predict(base, "http://203.0.113.45/secure/login/verify-account.php?id=8812", {
      timeoutMs: TIMEOUT_MS,
      fetchFn: cappedFetch,
    });
    show(r);
    check("IP + login URL is malicious", r.malicious === true);
    check("decided by the model", r.decidedBy === "model", r.decidedBy);
    contractChecks("IP + login", r);
  });

  await step("POST /predict?model_only=true google.com", async () => {
    const r = await predict(base, "https://www.google.com/", { modelOnly: true, timeoutMs: TIMEOUT_MS, fetchFn: cappedFetch });
    show(r);
    check("model_only answer is decided by the model", r.decidedBy === "model", r.decidedBy);
    contractChecks("model_only", r);
  });

  await step("POST /predict with invalid (empty) input", async () => {
    try {
      await predict(base, "", { timeoutMs: TIMEOUT_MS, fetchFn: cappedFetch });
      check("empty input is rejected", false, "the API accepted an empty URL");
    } catch (err) {
      if (!(err instanceof ApiError)) throw err;
      console.log("  extension sees: kind=" + err.kind + ", status " + err.status + ", code " + err.code + ', message "' + err.message + '"');
      check("empty input -> 422", err.status === 422, "status " + err.status);
      check('422 has error "invalid_request"', err.code === "invalid_request", "code " + err.code);
      check("422 message is readable", err.kind === "bad_input" && err.message.length > 0 && !err.message.startsWith("["), err.message);
    }
  });
}

const failed = checks.filter((c) => !c.ok);
console.log(
  "\nDone: " + requests + " request(s) sent (cap " + MAX_REQUESTS + "), " + (checks.length - failed.length) + "/" +
    checks.length + " checks passed. Client-side URL limit: " + MAX_URL_LENGTH + " characters.",
);
process.exit(failed.length ? 1 : 0);
