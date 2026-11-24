// Verdict cache with a time-to-live, stored in chrome.storage.session.
// Why not a normal JS object? An MV3 service worker can be stopped at any time,
// and every global variable disappears with it. Session storage survives that
// (but is cleared when the browser closes).
// One key per URL ("c:" + url) so two checks finishing together never clash.

import { CACHE_TTL_MS, CACHE_MAX_ENTRIES } from "../config.js";
import { stripHash } from "./urlrules.js";

const PREFIX = "c:";

export function createCache(
  area,
  { ttlMs = CACHE_TTL_MS, maxEntries = CACHE_MAX_ENTRIES, now = () => Date.now(), pruneEvery = 50 } = {},
) {
  let writes = 0;
  const keyOf = (url) => PREFIX + stripHash(url);
  const isFresh = (entry) => entry && typeof entry.t === "number" && now() - entry.t <= ttlMs;

  async function get(url) {
    const key = keyOf(url);
    const got = await area.get(key);
    const entry = got[key];
    if (!entry) return null;
    if (!isFresh(entry)) {
      await area.remove(key);
      return null;
    }
    return entry.v;
  }

  async function set(url, value) {
    await area.set({ [keyOf(url)]: { v: value, t: now() } });
    writes += 1;
    if (writes % pruneEvery === 0) await prune();
  }

  async function remove(url) {
    await area.remove(keyOf(url));
  }

  async function entries() {
    const all = await area.get(null);
    return Object.entries(all).filter(([k]) => k.startsWith(PREFIX));
  }

  // Deletes expired entries, then the oldest ones if there are more than maxEntries.
  async function prune() {
    const list = await entries();
    const expired = list.filter(([, e]) => !isFresh(e)).map(([k]) => k);
    const live = list.filter(([, e]) => isFresh(e)).sort((a, b) => a[1].t - b[1].t);
    const overflow = live.length > maxEntries ? live.slice(0, live.length - maxEntries).map(([k]) => k) : [];
    const doomed = [...expired, ...overflow];
    if (doomed.length) await area.remove(doomed);
    return doomed.length;
  }

  async function clear() {
    const keys = (await entries()).map(([k]) => k);
    if (keys.length) await area.remove(keys);
    return keys.length;
  }

  async function size() {
    return (await entries()).length;
  }

  return { get, set, remove, prune, clear, size };
}
