import { test } from "node:test";
import assert from "node:assert/strict";
import { createCache } from "../lib/cache.js";
import { createMemoryArea } from "../lib/storage.js";

// A fake clock lets us test a 30-minute TTL without waiting 30 minutes.
function clock(start = 1_000_000) {
  let t = start;
  return { now: () => t, advance: (ms) => (t += ms) };
}

const MIN = 60_000;

test("value is returned within the TTL and gone after it", async () => {
  const c = clock();
  const area = createMemoryArea();
  const cache = createCache(area, { ttlMs: 30 * MIN, now: c.now });
  await cache.set("https://a.com/", { malicious: false });
  c.advance(29 * MIN);
  assert.deepEqual(await cache.get("https://a.com/"), { malicious: false });
  c.advance(2 * MIN);
  assert.equal(await cache.get("https://a.com/"), null);
  // the expired entry was also deleted from storage
  assert.deepEqual(await area.get(null), {});
});

test("exactly at the TTL is still fresh, 1 ms later is not", async () => {
  const c = clock();
  const cache = createCache(createMemoryArea(), { ttlMs: 1000, now: c.now });
  await cache.set("https://a.com/", 1);
  c.advance(1000);
  assert.equal(await cache.get("https://a.com/"), 1);
  c.advance(1);
  assert.equal(await cache.get("https://a.com/"), null);
});

test("keys are per URL and ignore the #fragment", async () => {
  const cache = createCache(createMemoryArea());
  await cache.set("https://a.com/x#one", "A");
  await cache.set("https://b.com/", "B");
  assert.equal(await cache.get("https://a.com/x#two"), "A");
  assert.equal(await cache.get("https://a.com/x"), "A");
  assert.equal(await cache.get("https://b.com/"), "B");
  assert.equal(await cache.get("https://c.com/"), null);
});

test("prune removes expired entries and keeps other storage keys", async () => {
  const c = clock();
  const area = createMemoryArea({ "allow:https://x.com/": 1, settings: { protection: true } });
  const cache = createCache(area, { ttlMs: 10 * MIN, now: c.now });
  await cache.set("https://old.com/", 1);
  c.advance(11 * MIN);
  await cache.set("https://new.com/", 2);
  assert.equal(await cache.prune(), 1);
  assert.equal(await cache.size(), 1);
  const all = await area.get(null);
  assert.ok("allow:https://x.com/" in all);
  assert.ok("settings" in all);
});

test("prune caps the number of entries, oldest first", async () => {
  const c = clock();
  const cache = createCache(createMemoryArea(), { maxEntries: 3, now: c.now, pruneEvery: 1000 });
  for (let i = 0; i < 5; i++) {
    await cache.set("https://site" + i + ".com/", i);
    c.advance(1000);
  }
  assert.equal(await cache.prune(), 2);
  assert.equal(await cache.get("https://site0.com/"), null);
  assert.equal(await cache.get("https://site1.com/"), null);
  assert.equal(await cache.get("https://site4.com/"), 4);
});

test("clear removes only cache entries", async () => {
  const area = createMemoryArea({ apiStatus: { state: "online" } });
  const cache = createCache(area);
  await cache.set("https://a.com/", 1);
  await cache.set("https://b.com/", 2);
  assert.equal(await cache.clear(), 2);
  assert.deepEqual(Object.keys(await area.get(null)), ["apiStatus"]);
});
