// Per-tab navigation state, kept in chrome.storage.session (the service worker
// can be restarted between two events of the same navigation).
//
// nav:<tabId>   { url, committed, prevCommitted, t }
//   url           latest URL this tab started or committed (used by the race guard)
//   committed     last URL that actually committed (= became a history entry)
//   prevCommitted the committed URL before that
// block:<tabId> { url, probability, reasons, decidedBy, threshold, at }  what we blocked in this tab
// guard:<tabId> { url, until }  set by "Go back to safety"; see consumeBackGuard()

import { withLock } from "./lock.js";

const NAV = "nav:";
const BLOCK = "block:";
const GUARD = "guard:";
export const BACK_GUARD_MS = 15_000;

// ---------- pure logic (unit tested) ----------

// Race guard: the API answered for `url`. Only redirect if the tab is still on it.
export function isStillCurrent(navState, url) {
  return !!navState && navState.url === url;
}

export function nextNavState(prev, url, committed, now = Date.now()) {
  const state = {
    url,
    committed: prev?.committed ?? null,
    prevCommitted: prev?.prevCommitted ?? null,
    t: now,
  };
  if (committed) {
    state.prevCommitted = prev?.committed ?? null;
    state.committed = url;
  }
  return state;
}

// Did the blocked page become a history entry before we redirected?
// If yes, "back 1" from the warning would land on it again, so we must go back 2.
// When we do not know, assume yes (the safe choice).
export function blockedPageCommitted(navState, blockedUrl, isWarningUrl) {
  if (!navState) return true;
  if (navState.committed === blockedUrl) return true;
  if (navState.committed && isWarningUrl(navState.committed) && navState.prevCommitted === blockedUrl) return true;
  if (navState.committed == null) return true;
  return false;
}

export function backStepsFor(committed) {
  return committed === false ? 1 : 2;
}

export function guardMatches(guard, url, now = Date.now()) {
  return !!guard && guard.url === url && now <= guard.until;
}

// ---------- storage helpers ----------

async function getKey(area, key) {
  const got = await area.get(key);
  return got[key] ?? null;
}

export function getNav(area, tabId) {
  return getKey(area, NAV + tabId);
}

export function recordNavigation(area, tabId, url, { committed = false, now = Date.now() } = {}) {
  const key = NAV + tabId;
  return withLock(key, async () => {
    const next = nextNavState(await getKey(area, key), url, committed, now);
    await area.set({ [key]: next });
    return next;
  });
}

export async function setBlockRecord(area, tabId, record) {
  await area.set({ [BLOCK + tabId]: record });
}

export function getBlockRecord(area, tabId) {
  return getKey(area, BLOCK + tabId);
}

export async function clearBlockRecord(area, tabId) {
  await area.remove(BLOCK + tabId);
}

export async function setBackGuard(area, tabId, url, now = Date.now()) {
  await area.set({ [GUARD + tabId]: { url, until: now + BACK_GUARD_MS } });
}

// One-shot: the FIRST navigation in the tab after "Go back to safety" (= the
// history navigation itself) always uses the guard up. Returns true if that
// navigation leads back to the URL the user just escaped from; the caller then
// sends the tab to the new tab page instead of showing the warning again, so
// "Go back" can never loop. Because it is one-shot, typing the blocked URL again
// later still shows the normal warning.
export async function consumeBackGuard(area, tabId, url, now = Date.now()) {
  const key = GUARD + tabId;
  const guard = await getKey(area, key);
  if (!guard) return false;
  await area.remove(key);
  return guardMatches(guard, url, now);
}

export async function forgetTab(area, tabId) {
  await area.remove([NAV + tabId, BLOCK + tabId, GUARD + tabId]);
}
