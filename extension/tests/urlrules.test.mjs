import { test } from "node:test";
import assert from "node:assert/strict";
import { skipReason, stripHash, isLocalHost, prepareUserInput, isHttpUrl, SKIP_REASONS } from "../lib/urlrules.js";

const API = "https://url-guard.onrender.com";

test("non-http(s) schemes are skipped", () => {
  for (const url of [
    "chrome://settings/",
    "chrome-extension://abcdefghijklmnop/warning.html?u=x",
    "file:///C:/Users/me/page.html",
    "about:blank",
    "data:text/html,<h1>hi</h1>",
    "javascript:alert(1)",
    "edge://flags",
    "view-source:https://example.com",
    "ftp://files.example.com/a.txt",
  ]) {
    assert.equal(skipReason(url, { apiBase: API }), "scheme", url);
  }
});

test("local addresses are skipped", () => {
  for (const url of [
    "http://localhost:3000/",
    "http://LOCALHOST/",
    "http://127.0.0.1:8000/docs",
    "http://127.5.5.5/",
    "http://[::1]:8080/",
    "http://0.0.0.0/",
    "http://app.localhost/",
  ]) {
    assert.equal(skipReason(url, { apiBase: API }), "local", url);
  }
});

test("the API's own host is skipped, other hosts are not", () => {
  assert.equal(skipReason("https://url-guard.onrender.com/docs", { apiBase: API }), "api");
  assert.equal(skipReason("https://URL-GUARD.onrender.com/", { apiBase: API }), "api");
  assert.equal(skipReason("https://other.onrender.com/", { apiBase: API }), null);
});

test("normal web pages are checked", () => {
  assert.equal(skipReason("https://www.google.com/", { apiBase: API }), null);
  assert.equal(skipReason("http://192.168.1.10/login", { apiBase: API }), null); // LAN IPs are checked
  assert.equal(skipReason("http://example.tk/", {}), null);
});

test("invalid and over-long URLs", () => {
  assert.equal(skipReason("not a url", {}), "invalid");
  assert.equal(skipReason("https://a.com/" + "x".repeat(3000), {}), "too_long");
});

test("URL length: 2,048 is checked, 2,049 is skipped (fail open) as 'URL too long to check'", () => {
  const atLimit = "https://a.com/" + "x".repeat(2048 - 14);
  assert.equal(atLimit.length, 2048);
  assert.equal(skipReason(atLimit, { apiBase: API }), null);
  assert.equal(skipReason(atLimit + "y", { apiBase: API }), "too_long");
  assert.equal(SKIP_REASONS.too_long, "URL too long to check");
  // the popup's text box uses the same wording
  const typed = prepareUserInput(atLimit + "y");
  assert.equal(typed.ok, false);
  assert.equal(typed.error, "URL too long to check (2049 characters, the limit is 2048).");
  assert.equal(prepareUserInput(atLimit).ok, true);
});

test("stripHash removes only the fragment", () => {
  assert.equal(stripHash("https://a.com/x?q=1#top"), "https://a.com/x?q=1");
  assert.equal(stripHash("https://a.com/x"), "https://a.com/x");
});

test("isLocalHost and isHttpUrl", () => {
  assert.ok(isLocalHost("[::1]"));
  assert.ok(!isLocalHost("128.0.0.1"));
  assert.ok(isHttpUrl("HTTPS://A.COM"));
  assert.ok(!isHttpUrl("mailto:me@a.com"));
});

test("popup input: empty, spaces, too long", () => {
  assert.equal(prepareUserInput("").ok, false);
  assert.equal(prepareUserInput("   ").ok, false);
  assert.match(prepareUserInput("").error, /type or paste/);
  assert.match(prepareUserInput("a.com/has space").error, /spaces/);
  const long = prepareUserInput("example.com/" + "a".repeat(2100));
  assert.equal(long.ok, false);
  assert.match(long.error, /too long/);
});

test("popup input: missing scheme gets https://", () => {
  assert.deepEqual(prepareUserInput("example.com"), { ok: true, url: "https://example.com", addedScheme: true });
  assert.deepEqual(prepareUserInput("  paypal-login.tk/verify "), {
    ok: true,
    url: "https://paypal-login.tk/verify",
    addedScheme: true,
  });
  assert.equal(prepareUserInput("localhost:8000").url, "https://localhost:8000");
  assert.equal(prepareUserInput("192.168.0.1/admin").url, "https://192.168.0.1/admin");
});

test("popup input: http/https kept as typed, other schemes rejected", () => {
  assert.deepEqual(prepareUserInput("HTTP://Example.com/A"), {
    ok: true,
    url: "HTTP://Example.com/A",
    addedScheme: false,
  });
  for (const bad of ["javascript:alert(1)", "ftp://x.com", "file:///etc/passwd", "mailto:a@b.com", "data:text/html,x"]) {
    const r = prepareUserInput(bad);
    assert.equal(r.ok, false, bad);
    assert.match(r.error, /Only http/);
  }
});

test("popup input: words that are not addresses are rejected", () => {
  assert.equal(prepareUserInput("hello").ok, false);
  assert.match(prepareUserInput("hello").error, /does not look like a web address/);
});
