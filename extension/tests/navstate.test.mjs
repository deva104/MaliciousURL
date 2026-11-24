// Race guard and "Go back to safety" logic.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createMemoryArea } from "../lib/storage.js";
import {
  isStillCurrent,
  nextNavState,
  blockedPageCommitted,
  backStepsFor,
  guardMatches,
  recordNavigation,
  getNav,
  setBackGuard,
  consumeBackGuard,
  forgetTab,
  setBlockRecord,
  getBlockRecord,
  BACK_GUARD_MS,
} from "../lib/navstate.js";

const W = "chrome-extension://id/warning.html";
const isWarning = (u) => u.startsWith(W);

test("race guard: redirect only if the tab is still on the checked URL", async () => {
  const area = createMemoryArea();
  await recordNavigation(area, 7, "https://evil.tk/");
  assert.ok(isStillCurrent(await getNav(area, 7), "https://evil.tk/"));

  // While the API was thinking, the user typed another address.
  await recordNavigation(area, 7, "https://good.com/");
  assert.ok(!isStillCurrent(await getNav(area, 7), "https://evil.tk/"));

  // Unknown tab -> never redirect.
  assert.ok(!isStillCurrent(await getNav(area, 99), "https://evil.tk/"));
  assert.ok(!isStillCurrent(null, "x"));
});

test("race guard: tabs are independent", async () => {
  const area = createMemoryArea();
  await recordNavigation(area, 1, "https://evil.tk/");
  await recordNavigation(area, 2, "https://good.com/");
  assert.ok(isStillCurrent(await getNav(area, 1), "https://evil.tk/"));
  assert.ok(!isStillCurrent(await getNav(area, 2), "https://evil.tk/"));
});

test("concurrent updates of one tab are not lost", async () => {
  const area = createMemoryArea();
  await Promise.all([
    recordNavigation(area, 3, "https://a.com/", { committed: true }),
    recordNavigation(area, 3, "https://b.com/", { committed: true }),
  ]);
  const s = await getNav(area, 3);
  assert.equal(s.committed, "https://b.com/");
  assert.equal(s.prevCommitted, "https://a.com/");
});

test("nextNavState tracks committed and previous committed URLs", () => {
  let s = nextNavState(null, "https://a.com/", true, 1);
  s = nextNavState(s, "https://evil.tk/", false, 2); // started, not committed
  assert.equal(s.url, "https://evil.tk/");
  assert.equal(s.committed, "https://a.com/");
  s = nextNavState(s, "https://evil.tk/", true, 3);
  assert.equal(s.committed, "https://evil.tk/");
  assert.equal(s.prevCommitted, "https://a.com/");
});

test("blockedPageCommitted decides how far 'Go back' goes", () => {
  const evil = "https://evil.tk/";
  // A -> evil (redirected before it committed) -> warning: back 1 is safe
  const notCommitted = { url: W + "?u=x", committed: W + "?u=x", prevCommitted: "https://a.com/" };
  assert.equal(blockedPageCommitted(notCommitted, evil, isWarning), false);
  assert.equal(backStepsFor(false), 1);

  // A -> evil (committed) -> warning: must go back 2
  const committedThenWarning = { url: W, committed: W + "?u=x", prevCommitted: evil };
  assert.equal(blockedPageCommitted(committedThenWarning, evil, isWarning), true);
  // same, but the warning page's own commit was not recorded yet
  assert.equal(blockedPageCommitted({ url: evil, committed: evil, prevCommitted: "https://a.com/" }, evil, isWarning), true);
  assert.equal(backStepsFor(true), 2);

  // unknown -> assume the worst (back 2)
  assert.equal(blockedPageCommitted(null, evil, isWarning), true);
  assert.equal(backStepsFor(null), 2);
});

test("back guard: history leads back to the blocked URL -> caught once", async () => {
  const area = createMemoryArea();
  const t0 = 1_000_000;
  await setBackGuard(area, 5, "https://evil.tk/", t0);
  assert.equal(await consumeBackGuard(area, 5, "https://evil.tk/", t0 + 10), true);
  assert.equal(await consumeBackGuard(area, 5, "https://evil.tk/", t0 + 20), false); // used up
});

test("back guard: one-shot, so typing the blocked URL again later shows the warning", async () => {
  const area = createMemoryArea();
  const t0 = 1_000_000;
  await setBackGuard(area, 5, "https://evil.tk/", t0);
  // "Go back" landed on a safe page: that navigation uses the guard up ...
  assert.equal(await consumeBackGuard(area, 5, "https://good.com/", t0 + 10), false);
  // ... so a deliberate new visit a few seconds later is NOT sent to the new tab page.
  assert.equal(await consumeBackGuard(area, 5, "https://evil.tk/", t0 + 3000), false);
  // other tabs are unaffected
  await setBackGuard(area, 6, "https://evil.tk/", t0);
  assert.equal(await consumeBackGuard(area, 5, "https://evil.tk/", t0 + 10), false);
  assert.equal(await consumeBackGuard(area, 6, "https://evil.tk/", t0 + 10), true);
});

test("back guard: expires", async () => {
  const area = createMemoryArea();
  const t0 = 1_000_000;
  await setBackGuard(area, 5, "https://evil.tk/", t0);
  assert.equal(await consumeBackGuard(area, 5, "https://evil.tk/", t0 + BACK_GUARD_MS + 1), false);
  assert.deepEqual(await area.get(null), {}); // and is cleaned up

  assert.ok(guardMatches({ url: "a", until: 10 }, "a", 10));
  assert.ok(!guardMatches({ url: "a", until: 10 }, "a", 11));
  assert.ok(!guardMatches(null, "a", 0));
});

test("forgetTab removes everything about a closed tab", async () => {
  const area = createMemoryArea();
  await recordNavigation(area, 9, "https://a.com/");
  await setBlockRecord(area, 9, { url: "https://evil.tk/" });
  await setBackGuard(area, 9, "https://evil.tk/");
  assert.ok(await getBlockRecord(area, 9));
  await forgetTab(area, 9);
  assert.deepEqual(await area.get(null), {});
});
