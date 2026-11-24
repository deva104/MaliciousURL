// api.js against the real mock server, started in-process on a random free port.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { startMockServer } from "../dev/mock_api.mjs";
import {
  predict,
  predictFailOpen,
  predictWithRetry,
  predictBatch,
  checkHealth,
  normalizePrediction,
  normalizeBaseUrl,
  detailText,
  ApiError,
  TOO_LONG_MESSAGE,
} from "../lib/api.js";

let mock;
before(async () => {
  mock = await startMockServer({ port: 0, quiet: true });
});
after(async () => {
  await mock.close();
});

// A port with nothing listening on it (for "offline").
async function freePort() {
  const s = createServer();
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

async function rejectsWith(promise, kind) {
  let caught;
  await assert.rejects(promise, (err) => {
    assert.ok(err instanceof ApiError, "expected ApiError, got " + err);
    assert.equal(err.kind, kind, err.message);
    caught = err;
    return true;
  });
  return caught;
}

// fetch replacement that answers with a fixed body and counts calls.
function fakeFetch(body, { status = 200, contentType = "application/json" } = {}) {
  const fn = async () => {
    fn.calls += 1;
    return new Response(typeof body === "string" ? body : JSON.stringify(body), {
      status,
      headers: { "Content-Type": contentType },
    });
  };
  fn.calls = 0;
  return fn;
}

const GOOD = {
  url: "https://a.com/",
  normalized_url: "https://a.com/",
  verdict: "safe",
  is_malicious: false,
  probability: 0.12,
  threshold: 0.8,
  decided_by: "model",
  reasons: [],
  latency_ms: 2.5,
  model_version: "rf-1",
};

// ---------- success ----------

test("success: malicious URL is mapped to the internal shape", async () => {
  const r = await predict(mock.url, "http://paypal-login.tk/verify");
  assert.equal(r.malicious, true);
  assert.ok(r.probability >= 0.9 && r.probability <= 0.99);
  assert.equal(r.threshold, 0.8);
  assert.equal(r.decidedBy, "model");
  assert.ok(r.reasons.length >= 1 && r.reasons.length <= 3);
  assert.equal(typeof r.serverLatencyMs, "number");
  assert.equal(typeof r.roundTripMs, "number");
  assert.equal(r.modelVersion, "mock-1.0");
  assert.equal(r.normalizedUrl, "http://paypal-login.tk/verify");
});

test("success: safe verdicts have no reasons; trusted list and ?model_only=true", async () => {
  const safe = await predict(mock.url, "https://example.com/about");
  assert.equal(safe.malicious, false);
  assert.ok(safe.probability < 0.1);
  assert.deepEqual(safe.reasons, []);

  const trusted = await predict(mock.url, "https://www.google.com/");
  assert.equal(trusted.decidedBy, "trusted_list");
  assert.deepEqual(trusted.reasons, []);

  const modelOnly = await predict(mock.url, "https://www.google.com/", { modelOnly: true });
  assert.equal(modelOnly.decidedBy, "model");
  assert.equal(modelOnly.modelOnly, true);
});

test("the mock follows the contract rules", async () => {
  const cases = {
    "http://192.168.10.5/account": true,
    "https://example.com/login?verify=1": true,
    "https://paypal.com.secure-check.net/": true,
    "https://www.paypal.com/signin": false,
    "http://free-prize.tk/": true,
    "https://en.wikipedia.org/wiki/Phishing": false,
  };
  for (const [url, expected] of Object.entries(cases)) {
    assert.equal((await predict(mock.url, url, { modelOnly: true })).malicious, expected, url);
  }
  // never more than 3 reasons, even when every rule matches
  const many = await predict(mock.url, "http://1.2.3.4/paypal/login/verify");
  assert.equal(many.reasons.length, 3);
});

test("the verdict is is_malicious, even if probability is below the threshold", () => {
  const r = normalizePrediction({ ...GOOD, is_malicious: true, verdict: "safe", probability: 0.3 }, "u");
  assert.equal(r.malicious, true);
  assert.equal(r.threshold, 0.8);
  const s = normalizePrediction({ ...GOOD, is_malicious: false, probability: 0.95 }, "u");
  assert.equal(s.malicious, false);
});

// ---------- errors ----------

test("timeout -> ApiError timeout", async () => {
  const slow = await startMockServer({ port: 0, quiet: true, slowMs: 600 });
  try {
    await rejectsWith(predict(slow.url, "https://example.com/", { timeoutMs: 100 }), "timeout");
  } finally {
    await slow.close();
  }
});

test("422 live shape: the API's message is shown to the user", async () => {
  const err = await rejectsWith(predict(mock.url, "   "), "bad_input");
  assert.equal(err.status, 422);
  assert.equal(err.code, "invalid_request");
  assert.equal(err.message, "url must not be empty");
  assert.equal(detailText([{ field: "url", message: "URL must start with http" }]), "URL must start with http");
  assert.equal(detailText([{ field: "a", message: "one" }, { field: "b", message: "two" }]), "one; two");
});

test("422 FastAPI default shape is still supported", async () => {
  const fastapi = fakeFetch({ detail: [{ loc: ["body", "url"], msg: "Field required", type: "missing" }] }, { status: 422 });
  const err = await rejectsWith(predict("https://x.test", "https://a.com/", { fetchFn: fastapi }), "bad_input");
  assert.equal(err.message, "url: Field required");
  assert.equal(detailText("bad"), "bad");
  const plain = fakeFetch({ detail: "url must not be empty" }, { status: 422 });
  assert.equal((await rejectsWith(predict("https://x.test", "a", { fetchFn: plain }), "bad_input")).message, "url must not be empty");
  const empty = fakeFetch("", { status: 422, contentType: "text/plain" });
  assert.match((await rejectsWith(predict("https://x.test", "a", { fetchFn: empty }), "bad_input")).message, /rejected/);
});

test("500 {error: internal_error} -> ApiError server", async () => {
  const broken = await startMockServer({ port: 0, quiet: true, fail: true });
  try {
    const err = await rejectsWith(predict(broken.url, "https://example.com/"), "server");
    assert.equal(err.code, "internal_error");
    const health = await checkHealth(broken.url);
    assert.equal(health.state, "error");
  } finally {
    await broken.close();
  }
});

test("fail-open: predictFailOpen never throws", async () => {
  const broken = await startMockServer({ port: 0, quiet: true, fail: true });
  try {
    const a = await predictFailOpen(broken.url, "https://example.com/");
    assert.equal(a.ok, false);
    assert.equal(a.error.kind, "server");
  } finally {
    await broken.close();
  }
  const b = await predictFailOpen("http://127.0.0.1:" + (await freePort()), "https://example.com/", { timeoutMs: 2000 });
  assert.equal(b.ok, false);
  assert.equal(b.error.kind, "offline");

  const c = await predictFailOpen("", "https://example.com/");
  assert.equal(c.error.kind, "not_configured");

  const d = await predictFailOpen(mock.url, "https://example.com/");
  assert.equal(d.ok, true);
  assert.equal(d.result.malicious, false);
});

// ---------- Render wake-up: never a verdict ----------

test("502/503/504 mean the server is waking up", async () => {
  for (const status of [502, 503, 504]) {
    const fn = fakeFetch("<html>Service Unavailable</html>", { status, contentType: "text/html" });
    await rejectsWith(predict("https://x.test", "https://a.com/", { fetchFn: fn }), "waking");
  }
});

test("--html-loading: Render's HTML page (status 200) is 'waking', never a verdict", async () => {
  const loading = await startMockServer({ port: 0, quiet: true, htmlLoadingMs: Infinity });
  try {
    const raw = await fetch(loading.url + "/predict", { method: "POST", body: "{}" });
    assert.equal(raw.status, 200);
    assert.match(raw.headers.get("content-type"), /text\/html/);
    await raw.text();

    const err = await rejectsWith(predict(loading.url, "http://1.2.3.4/login"), "waking");
    assert.match(err.message, /web page instead of data/);

    const open = await predictFailOpen(loading.url, "http://1.2.3.4/login");
    assert.equal(open.ok, false); // fail open: the page would be allowed, badge "?"
    assert.equal(open.error.kind, "waking");

    assert.equal((await checkHealth(loading.url)).state, "waking");
    await rejectsWith(predictBatch(loading.url, ["https://a.com/"]), "waking");
  } finally {
    await loading.close();
  }
});

test("--html-loading then awake: predictWithRetry waits and then gets the verdict", async () => {
  const waking = await startMockServer({ port: 0, quiet: true, htmlLoadingMs: 500 });
  try {
    const seen = [];
    const r = await predictWithRetry(waking.url, "http://1.2.3.4/x", {
      totalMs: 5000,
      retryDelayMs: 150,
      onWaiting: (info) => seen.push(info.error.kind),
    });
    assert.equal(r.malicious, true);
    assert.ok(seen.length >= 1);
    assert.ok(seen.every((k) => k === "waking"));
  } finally {
    await waking.close();
  }
});

test("JSON without the expected fields is 'waking', never a verdict", async () => {
  const cases = [
    { hello: "world" },
    { verdict: "malicious" }, // no is_malicious
    { ...GOOD, is_malicious: "true" }, // wrong type
    { ...GOOD, probability: undefined }, // no probability
    { ...GOOD, probability: 2 }, // out of range
    [GOOD], // array instead of object
  ];
  for (const body of cases) {
    const fn = fakeFetch(body);
    await rejectsWith(predict("https://x.test", "https://a.com/", { fetchFn: fn }), "waking");
  }
  await rejectsWith(predict("https://x.test", "https://a.com/", { fetchFn: fakeFetch("not json", { contentType: "text/plain" }) }), "waking");
  await rejectsWith(predict("https://x.test", "https://a.com/", { fetchFn: fakeFetch("") }), "waking");
  assert.equal((await checkHealth("https://x.test", { fetchFn: fakeFetch({ foo: 1 }) })).state, "waking");
  assert.equal((await checkHealth("https://x.test", { fetchFn: fakeFetch({ status: "ok", model_loaded: false }) })).state, "waking");
  await rejectsWith(predictBatch("https://x.test", ["https://a.com/"], { fetchFn: fakeFetch({ count: 1 }) }), "waking");
});

test("health: online, waking (timeout) and offline", async () => {
  const ok = await checkHealth(mock.url);
  assert.equal(ok.state, "online");
  assert.equal(ok.version, "mock-1.0");

  const slow = await startMockServer({ port: 0, quiet: true, slowMs: 500 });
  try {
    const waking = await checkHealth(slow.url, { timeoutMs: 100 });
    assert.equal(waking.state, "waking");
  } finally {
    await slow.close();
  }

  const offline = await checkHealth("http://127.0.0.1:" + (await freePort()));
  assert.equal(offline.state, "offline");
});

test("predictWithRetry keeps trying while a cold server wakes up", async () => {
  const cold = await startMockServer({ port: 0, quiet: true, coldMs: 700 });
  try {
    const waits = [];
    const r = await predictWithRetry(cold.url, "http://1.2.3.4/x", {
      totalMs: 5000,
      firstTimeoutMs: 200,
      retryTimeoutMs: 200,
      onWaiting: (info) => waits.push(info.error.kind),
    });
    assert.equal(r.malicious, true);
    assert.ok(waits.length >= 1, "onWaiting should have been called");
    assert.ok(waits.every((k) => k === "timeout"));
  } finally {
    await cold.close();
  }
});

test("predictWithRetry gives up at the deadline and does not retry bad input", async () => {
  const slow = await startMockServer({ port: 0, quiet: true, slowMs: 2000 });
  try {
    const started = Date.now();
    await rejectsWith(
      predictWithRetry(slow.url, "https://a.com/", { totalMs: 600, firstTimeoutMs: 200, retryTimeoutMs: 200 }),
      "timeout",
    );
    assert.ok(Date.now() - started < 1500);
  } finally {
    await slow.close();
  }
  let calls = 0;
  await rejectsWith(
    predictWithRetry(mock.url, "", { onWaiting: () => calls++ }),
    "bad_input",
  );
  assert.equal(calls, 0);
});

// ---------- URL length ----------

test("URLs over 2,048 characters are never sent: 'URL too long to check'", async () => {
  const atLimit = "https://a.com/" + "x".repeat(2048 - 14);
  assert.equal(atLimit.length, 2048);
  assert.equal((await predict(mock.url, atLimit)).malicious, false); // 2,048 is accepted

  const fn = fakeFetch(GOOD);
  const err = await rejectsWith(predict("https://x.test", atLimit + "y", { fetchFn: fn }), "bad_input");
  assert.ok(err.message.startsWith(TOO_LONG_MESSAGE));
  assert.equal(fn.calls, 0, "nothing may be sent to the API");

  const open = await predictFailOpen("https://x.test", atLimit + "y", { fetchFn: fn });
  assert.equal(open.ok, false); // automatic protection: fail open
  await rejectsWith(predictBatch("https://x.test", ["https://a.com/", atLimit + "y"], { fetchFn: fn }), "bad_input");
  assert.equal(fn.calls, 0);
  // and predictWithRetry does not retry it
  await rejectsWith(predictWithRetry("https://x.test", atLimit + "y", { fetchFn: fn }), "bad_input");
});

// ---------- exact answers captured from the live API by dev/live_check.mjs ----------

const LIVE = {
  health: {
    status: "ok",
    model_loaded: true,
    model: "Soft Voting (tuned members) [noise removed]",
    model_version: "voting_tuned_noiseclean@2026-11-24",
    uptime_s: 155.5,
  },
  trusted: {
    url: "https://www.google.com/",
    normalized_url: "google.com",
    verdict: "safe",
    is_malicious: false,
    probability: 0.225335,
    threshold: 0.8,
    decided_by: "trusted_list",
    reasons: [],
    latency_ms: 39.68,
    model_version: "voting_tuned_noiseclean@2026-11-24",
  },
  malicious: {
    url: "http://203.0.113.45/secure/login/verify-account.php?id=8812",
    normalized_url: "203.0.113.45/secure/login/verify-account.php?id=8812",
    verdict: "malicious",
    is_malicious: true,
    probability: 0.974711,
    threshold: 0.8,
    decided_by: "model",
    reasons: ["Several login / verification words", "Host is an IP address, not a domain name"],
    latency_ms: 71.614,
    model_version: "voting_tuned_noiseclean@2026-11-24",
  },
  invalid: { error: "invalid_request", detail: [{ field: "url", message: "url is empty" }] },
};

test("live answers: health reads model_version", async () => {
  const h = await checkHealth("https://x.test", { fetchFn: fakeFetch(LIVE.health) });
  assert.equal(h.state, "online");
  assert.equal(h.model, "Soft Voting (tuned members) [noise removed]");
  assert.equal(h.version, "voting_tuned_noiseclean@2026-11-24");
  assert.equal(h.uptimeS, 155.5);
});

test("live answers: predict, trusted list, 422", async () => {
  const t = await predict("https://x.test", "https://www.google.com/", { fetchFn: fakeFetch(LIVE.trusted) });
  assert.deepEqual(
    { malicious: t.malicious, probability: t.probability, threshold: t.threshold, decidedBy: t.decidedBy, reasons: t.reasons },
    { malicious: false, probability: 0.225335, threshold: 0.8, decidedBy: "trusted_list", reasons: [] },
  );
  const m = await predict("https://x.test", LIVE.malicious.url, { fetchFn: fakeFetch(LIVE.malicious) });
  assert.equal(m.malicious, true);
  assert.equal(m.reasons.length, 2);
  assert.equal(m.modelVersion, "voting_tuned_noiseclean@2026-11-24");
  const err = await rejectsWith(predict("https://x.test", "", { fetchFn: fakeFetch(LIVE.invalid, { status: 422 }) }), "bad_input");
  assert.equal(err.message, "url is empty");
  assert.equal(err.code, "invalid_request");
});

// ---------- batch and helpers ----------

test("batch: results in order, client-side limit of 100", async () => {
  const r = await predictBatch(mock.url, ["https://example.com/", "http://evil.tk/"]);
  assert.equal(r.count, 2);
  assert.deepEqual(
    r.results.map((x) => x.malicious),
    [false, true],
  );
  await rejectsWith(predictBatch(mock.url, []), "bad_input");
  await rejectsWith(predictBatch(mock.url, Array(101).fill("https://a.com/")), "bad_input");
});

test("normalizeBaseUrl", () => {
  assert.deepEqual(normalizeBaseUrl(" https://x.onrender.com/ "), { ok: true, url: "https://x.onrender.com", warning: null });
  assert.equal(normalizeBaseUrl("http://localhost:8000").warning, null);
  assert.match(normalizeBaseUrl("http://my-server.com").warning, /unencrypted/);
  assert.match(normalizeBaseUrl("https://x.onrender.com/predict").warning, /base URL/);
  assert.equal(normalizeBaseUrl("x.onrender.com").ok, false);
  assert.equal(normalizeBaseUrl("ftp://x.com").ok, false);
});
