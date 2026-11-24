// Warning page parameters and reason parsing.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildWarningQuery,
  buildWarningPath,
  parseWarningQuery,
  parseReasons,
  cleanReasons,
  decidedByLabel,
  formatPercent,
  truncateUrl,
} from "../lib/warnlink.js";

test("build -> parse round trip keeps special characters", () => {
  const url = "https://päypal.example.tk/login?next=/a&b=c d#x";
  const q = buildWarningQuery({
    url,
    probability: 0.9712,
    reasons: ["Uses .tk & 'login'", "Contains <script>"],
    decidedBy: "model",
  });
  const p = parseWarningQuery("?" + q);
  assert.equal(p.url, url);
  assert.equal(p.urlValid, true);
  assert.equal(p.probability, 0.971);
  assert.deepEqual(p.reasons, ["Uses .tk & 'login'", "Contains <script>"]);
  assert.equal(p.decidedBy, "model");
  assert.ok(buildWarningPath({ url }).startsWith("/warning.html?u="));
});

test("only the first 3 reasons are kept", () => {
  const p = parseWarningQuery(buildWarningQuery({ url: "http://a.tk/", reasons: ["1", "2", "3", "4", "5"] }));
  assert.deepEqual(p.reasons, ["1", "2", "3"]);
});

test("reason parsing is defensive", () => {
  assert.deepEqual(parseReasons(null), []);
  assert.deepEqual(parseReasons(""), []);
  assert.deepEqual(parseReasons('"single reason"'), ["single reason"]);
  assert.deepEqual(parseReasons('{"a":1}'), []);
  assert.deepEqual(parseReasons('["ok", 5, null, "  ", "fine "]'), ["ok", "fine"]);
  assert.deepEqual(parseReasons("not json|second"), ["not json", "second"]);
  const long = cleanReasons(["x".repeat(500)])[0];
  assert.equal(long.length, 200);
  assert.ok(long.endsWith("…"));
});

test("bad parameters from a crafted link are neutralised", () => {
  const p = parseWarningQuery("?u=javascript:alert(1)&p=7&d=hacker&r=%5B%22x%22%5D");
  assert.equal(p.urlValid, false);
  assert.equal(p.probability, null);
  assert.equal(p.decidedBy, null);
  assert.equal(decidedByLabel(p.decidedBy), "Unknown");
  assert.equal(parseWarningQuery("?u=http://a.com&p=").probability, null);
  assert.equal(parseWarningQuery("").url, "");
});

test("labels and formatting", () => {
  assert.equal(decidedByLabel("model"), "ML model");
  assert.equal(decidedByLabel("trusted_list"), "Trusted list");
  assert.equal(formatPercent(0.974), "97%");
  assert.equal(formatPercent(null), "unknown");
  assert.deepEqual(truncateUrl("short"), { text: "short", truncated: false });
  const t = truncateUrl("https://a.com/" + "x".repeat(200), 50);
  assert.equal(t.truncated, true);
  assert.equal(t.text.length, 50);
});
