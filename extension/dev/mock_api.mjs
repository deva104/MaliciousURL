// Mock of the URL Guard API for developing and testing the extension.
// Follows the API contract exactly, using simple rules instead of the ML model.
//
//   node extension/dev/mock_api.mjs                 -> http://127.0.0.1:8765
//   node extension/dev/mock_api.mjs --slow 3000     every request takes 3 s
//   node extension/dev/mock_api.mjs --cold 20000    "sleeping free server": requests in the
//                                                   first 20 s wait until it has woken up
//   node extension/dev/mock_api.mjs --fail          every request returns 500
//   node extension/dev/mock_api.mjs --html-loading  every request gets Render's HTML "waking up"
//                                                   page with status 200 (never a verdict!)
//   node extension/dev/mock_api.mjs --html-loading 20000   ... only for the first 20 s
//   node extension/dev/mock_api.mjs --port 9000
//
// Rules (malicious -> probability 0.90-0.99, otherwise safe):
//   host is an IP address | contains "login" AND "verify" | "paypal" outside paypal.com | .tk domain
// Trusted list (decided_by "trusted_list" unless ?model_only=true): google.com, paypal.com,
// wikipedia.org, github.com, microsoft.com
// Like the live API: threshold 0.8, reasons [] for safe verdicts, at most 3 for malicious,
// 422 = {"error":"invalid_request","detail":[{"field":..,"message":..}]}, 500 = {"error":"internal_error"}.

import http from "node:http";
import { pathToFileURL } from "node:url";

const THRESHOLD = 0.8;
const MAX_REASONS = 3;
const MODEL_VERSION = "mock-1.0";
const MAX_URL_LENGTH = 2048;
const MAX_BATCH = 100;
const TRUSTED = ["google.com", "paypal.com", "wikipedia.org", "github.com", "microsoft.com"];

function hashOf(text) {
  let h = 0;
  for (const ch of text) h = (h * 31 + ch.codePointAt(0)) >>> 0;
  return h;
}

function isIpHost(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[");
}

// Same response shape as the real POST /predict.
export function classify(rawUrl, { modelOnly = false } = {}) {
  const started = process.hrtime.bigint();
  const text = String(rawUrl).trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : "http://" + text;
  let host = "";
  let normalized = withScheme;
  try {
    const u = new URL(withScheme);
    host = u.hostname.toLowerCase();
    normalized = u.href;
  } catch {
    // keep the raw text; the rules below still work on it
  }
  const lower = text.toLowerCase();
  const onDomain = (d) => host === d || host.endsWith("." + d);
  const h = hashOf(normalized);

  let malicious;
  let probability;
  let decidedBy = "model";
  let reasons = [];
  const trusted = TRUSTED.find(onDomain);

  if (trusted && !modelOnly) {
    malicious = false;
    probability = 0.01;
    decidedBy = "trusted_list";
  } else {
    if (isIpHost(host)) reasons.push("The host is an IP address instead of a domain name");
    if (lower.includes("login") && lower.includes("verify")) reasons.push("The URL contains both 'login' and 'verify'");
    if (lower.includes("paypal") && !onDomain("paypal.com")) reasons.push("Mentions 'paypal' but the domain is not paypal.com");
    if (host.endsWith(".tk")) reasons.push("Uses the .tk top-level domain, common in phishing");
    malicious = reasons.length > 0;
    probability = malicious ? 0.9 + (h % 10) / 100 : 0.01 + (h % 9) / 100;
  }
  reasons = malicious ? reasons.slice(0, MAX_REASONS) : []; // live API: no reasons for safe verdicts

  return {
    url: text,
    normalized_url: normalized,
    verdict: malicious ? "malicious" : "safe",
    is_malicious: malicious,
    probability: Math.round(probability * 100) / 100,
    threshold: THRESHOLD,
    decided_by: decidedBy,
    reasons,
    latency_ms: Math.round(Number(process.hrtime.bigint() - started) / 1e4) / 100,
    model_version: MODEL_VERSION,
  };
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "600",
};

function send(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json", ...CORS });
  res.end(JSON.stringify(body));
}

function readBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const parts = [];
    req.on("data", (part) => {
      size += part.length;
      if (size > limit) {
        reject(new Error("too_large"));
        req.destroy();
      } else parts.push(part);
    });
    req.on("end", () => resolve(Buffer.concat(parts).toString("utf8")));
    req.on("error", reject);
  });
}

// The live API's validation error shape.
const invalid = (field, message) => ({ error: "invalid_request", detail: [{ field, message }] });

function validateUrl(value) {
  if (typeof value !== "string") return "url must be a string";
  if (value.trim() === "") return "url must not be empty";
  if (value.length > MAX_URL_LENGTH) return "url must be at most " + MAX_URL_LENGTH + " characters";
  return null;
}

// What a sleeping free Render service answers while it boots (status 200, HTML).
const LOADING_PAGE =
  "<!DOCTYPE html><html><head><title>Service waking up</title></head>" +
  "<body><h1>Your service is waking up</h1><p>This may take a minute.</p></body></html>";

export function startMockServer({
  port = 8765,
  host = "127.0.0.1",
  slowMs = 0,
  coldMs = 0,
  fail = false,
  htmlLoadingMs = 0, // > 0: answer with LOADING_PAGE for this long after start (Infinity = always)
  quiet = false,
} = {}) {
  const startedAt = Date.now();
  const log = (...args) => {
    if (!quiet) console.log("[mock]", ...args);
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://mock");
    if (req.method === "OPTIONS") {
      res.writeHead(204, CORS);
      return res.end();
    }

    // Simulated slowness: a fixed delay, and/or waiting until the "cold" server has woken up.
    const wait = Math.max(slowMs, coldMs ? startedAt + coldMs - Date.now() : 0);
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    if (res.destroyed || res.writableEnded) return;

    if (htmlLoadingMs > 0 && Date.now() - startedAt < htmlLoadingMs) {
      log(req.method, url.pathname, "-> 200 HTML loading page (--html-loading)");
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", ...CORS });
      return res.end(LOADING_PAGE);
    }

    if (fail) {
      log(req.method, url.pathname, "-> 500 (--fail)");
      return send(res, 500, { error: "internal_error" });
    }

    const modelOnly = ["true", "1"].includes(url.searchParams.get("model_only"));
    try {
      if (url.pathname === "/health") {
        if (req.method !== "GET") return send(res, 405, { detail: "Method Not Allowed" });
        return send(res, 200, {
          status: "ok",
          model_loaded: true,
          model: "mock-rules",
          model_version: MODEL_VERSION, // same field name as the live API
          uptime_s: Math.round((Date.now() - startedAt) / 100) / 10,
        });
      }

      if (url.pathname === "/predict" || url.pathname === "/predict/batch") {
        if (req.method !== "POST") return send(res, 405, { detail: "Method Not Allowed" });
        let body;
        try {
          body = JSON.parse((await readBody(req)) || "null");
        } catch (err) {
          if (err.message === "too_large") return send(res, 413, { detail: "Request body too large" });
          return send(res, 422, invalid("body", "request body must be valid JSON"));
        }

        if (url.pathname === "/predict") {
          if (!body || typeof body !== "object" || !("url" in body)) {
            return send(res, 422, invalid("url", "url is required"));
          }
          const problem = validateUrl(body.url);
          if (problem) return send(res, 422, invalid("url", problem));
          const result = classify(body.url, { modelOnly });
          log("POST /predict", result.verdict, result.probability, body.url);
          return send(res, 200, result);
        }

        // /predict/batch
        if (!body || typeof body !== "object" || !Array.isArray(body.urls)) {
          return send(res, 422, invalid("urls", "urls is required"));
        }
        if (body.urls.length === 0) return send(res, 422, invalid("urls", "urls must not be empty"));
        if (body.urls.length > MAX_BATCH) return send(res, 422, invalid("urls", "at most " + MAX_BATCH + " urls per batch"));
        for (const [i, item] of body.urls.entries()) {
          const problem = validateUrl(item);
          if (problem) return send(res, 422, invalid("urls[" + i + "]", problem));
        }
        const started = Date.now();
        const results = body.urls.map((u) => classify(u, { modelOnly }));
        log("POST /predict/batch", results.length, "urls");
        return send(res, 200, { results, count: results.length, latency_ms: Date.now() - started });
      }

      return send(res, 404, { detail: "Not Found" });
    } catch (err) {
      log("crash:", err);
      return send(res, 500, { error: "internal_error" });
    }
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const actualPort = server.address().port;
      resolve({
        server,
        port: actualPort,
        url: "http://" + host + ":" + actualPort,
        close: () =>
          new Promise((done) => {
            server.closeAllConnections?.();
            server.close(() => done());
          }),
      });
    });
  });
}

function parseArgs(argv) {
  const opts = { port: 8765, slowMs: 0, coldMs: 0, fail: false, htmlLoadingMs: 0 };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--fail") opts.fail = true;
    else if (arg === "--slow") opts.slowMs = Number(argv[++i] ?? 3000);
    else if (arg === "--cold") opts.coldMs = Number(argv[++i] ?? 20000);
    else if (arg === "--port") opts.port = Number(argv[++i]);
    else if (arg === "--html-loading") {
      // optional duration in ms; without one the server never "wakes up"
      opts.htmlLoadingMs = /^[0-9]+$/.test(argv[i + 1] ?? "") ? Number(argv[++i]) : Infinity;
    }
    else if (arg === "--help" || arg === "-h") {
      console.log("usage: node mock_api.mjs [--port 8765] [--slow ms] [--cold ms] [--fail] [--html-loading [ms]]");
      process.exit(0);
    } else {
      console.error("unknown option:", arg);
      process.exit(2);
    }
  }
  return opts;
}

// Run as a program (not when imported by the tests).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.port === 8000 || opts.port === 10000) {
    console.error("Ports 8000 and 10000 are reserved for the real API. Pick another port.");
    process.exit(2);
  }
  const { url } = await startMockServer(opts);
  console.log("[mock] URL Guard mock API on " + url);
  console.log(
    "[mock] slow=" + opts.slowMs + "ms cold=" + opts.coldMs + "ms fail=" + opts.fail +
      " html-loading=" + (opts.htmlLoadingMs === Infinity ? "always" : opts.htmlLoadingMs + "ms") + "  (Ctrl+C to stop)",
  );
}
