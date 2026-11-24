// Small helpers around chrome.storage.
// Every function takes the storage "area" as its first argument:
//   chrome.storage.local   - kept on this computer (settings, blocked history)
//   chrome.storage.session - in memory, cleared when the browser closes (allowlist, status)
// The Node tests pass createMemoryArea() instead, which behaves the same way.

import { DEFAULT_SETTINGS, HISTORY_MAX, MAX_REASONS_SHOWN } from "../config.js";
import { withLock } from "./lock.js";

// ---------- in-memory area with the same API as chrome.storage.* ----------
export function createMemoryArea(initial = {}) {
  let data = structuredClone(initial);
  const has = (k) => Object.prototype.hasOwnProperty.call(data, k);
  return {
    async get(keys) {
      if (keys == null) return structuredClone(data);
      if (typeof keys === "string") keys = [keys];
      const out = {};
      if (Array.isArray(keys)) {
        for (const k of keys) if (has(k)) out[k] = structuredClone(data[k]);
      } else {
        for (const [k, fallback] of Object.entries(keys)) out[k] = has(k) ? structuredClone(data[k]) : fallback;
      }
      return out;
    },
    async set(items) {
      for (const [k, v] of Object.entries(items)) data[k] = structuredClone(v);
    },
    async remove(keys) {
      for (const k of [].concat(keys)) delete data[k];
    },
    async clear() {
      data = {};
    },
  };
}

// ---------- settings (local) ----------
// Only the keys the user actually changed are saved, so editing a default in
// config.js still takes effect for everything the user never touched.
export async function getSavedSettings(area) {
  const { settings } = await area.get("settings");
  return settings && typeof settings === "object" ? settings : {};
}

export async function getSettings(area) {
  return { ...DEFAULT_SETTINGS, ...(await getSavedSettings(area)) };
}

// patch values set to undefined are removed (= back to the default).
export function saveSettings(area, patch) {
  return withLock("settings", async () => {
    const next = { ...(await getSavedSettings(area)) };
    for (const [k, v] of Object.entries(patch)) {
      if (v === undefined) delete next[k];
      else next[k] = v;
    }
    await area.set({ settings: next });
    return { ...DEFAULT_SETTINGS, ...next };
  });
}

// ---------- blocked history (local, newest first) ----------
export async function getHistory(area) {
  const { history } = await area.get("history");
  return Array.isArray(history) ? history : [];
}

export function addHistory(area, entry, { max = HISTORY_MAX, now = Date.now() } = {}) {
  return withLock("history", async () => {
    const list = await getHistory(area);
    const item = {
      url: String(entry.url),
      probability: typeof entry.probability === "number" ? entry.probability : null,
      reasons: (Array.isArray(entry.reasons) ? entry.reasons : []).slice(0, MAX_REASONS_SHOWN),
      decidedBy: entry.decidedBy || "model",
      time: entry.time ?? now,
    };
    // The same page blocked twice within a minute (e.g. double redirect) is one event.
    if (list[0] && list[0].url === item.url && item.time - list[0].time < 60_000) list.shift();
    list.unshift(item);
    const trimmed = list.slice(0, max);
    await area.set({ history: trimmed });
    return trimmed;
  });
}

export async function clearHistory(area) {
  await area.remove("history");
}

// ---------- "proceed anyway" allowlist (session) ----------
// One key per URL, so no read-modify-write and no lock needed.
const ALLOW = "allow:";

export async function allowlistAdd(area, url, now = Date.now()) {
  await area.set({ [ALLOW + url]: now });
}

export async function allowlistHas(area, url) {
  const key = ALLOW + url;
  const got = await area.get(key);
  return Object.prototype.hasOwnProperty.call(got, key);
}

export async function allowlistRemove(area, url) {
  await area.remove(ALLOW + url);
}

// ---------- last API status seen by the service worker (session) ----------
export async function setApiStatus(area, status, now = Date.now()) {
  await area.set({ apiStatus: { ...status, at: now } });
}

export async function getApiStatus(area) {
  const { apiStatus } = await area.get("apiStatus");
  return apiStatus || null;
}
