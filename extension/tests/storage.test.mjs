import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_SETTINGS } from "../config.js";
import {
  createMemoryArea,
  getSettings,
  getSavedSettings,
  saveSettings,
  addHistory,
  getHistory,
  clearHistory,
  allowlistAdd,
  allowlistHas,
  allowlistRemove,
} from "../lib/storage.js";

test("settings: defaults, partial saves, reset to default", async () => {
  const area = createMemoryArea();
  assert.deepEqual(await getSettings(area), DEFAULT_SETTINGS);
  await saveSettings(area, { protection: false });
  // Only the changed key is stored, so the API default from config.js still applies.
  assert.deepEqual(await getSavedSettings(area), { protection: false });
  assert.equal((await getSettings(area)).apiBase, DEFAULT_SETTINGS.apiBase);
  await saveSettings(area, { apiBase: "https://x.onrender.com" });
  assert.equal((await getSettings(area)).apiBase, "https://x.onrender.com");
  await saveSettings(area, { apiBase: undefined });
  assert.equal((await getSettings(area)).apiBase, DEFAULT_SETTINGS.apiBase);
  assert.equal((await getSettings(area)).protection, false);
});

test("history: newest first, max 50, reasons capped at 3", async () => {
  const area = createMemoryArea();
  for (let i = 0; i < 55; i++) {
    await addHistory(area, { url: "https://bad" + i + ".tk/", probability: 0.9, reasons: ["a", "b", "c", "d"] }, { now: i * 120_000 });
  }
  const list = await getHistory(area);
  assert.equal(list.length, 50);
  assert.equal(list[0].url, "https://bad54.tk/");
  assert.equal(list[49].url, "https://bad5.tk/");
  assert.deepEqual(list[0].reasons, ["a", "b", "c"]);
  assert.equal(list[0].decidedBy, "model");
  await clearHistory(area);
  assert.deepEqual(await getHistory(area), []);
});

test("history: the same URL twice within a minute is one entry", async () => {
  const area = createMemoryArea();
  await addHistory(area, { url: "https://evil.tk/" }, { now: 0 });
  await addHistory(area, { url: "https://evil.tk/" }, { now: 30_000 });
  assert.equal((await getHistory(area)).length, 1);
  await addHistory(area, { url: "https://evil.tk/" }, { now: 200_000 });
  assert.equal((await getHistory(area)).length, 2);
});

test("history: parallel adds are not lost", async () => {
  const area = createMemoryArea();
  await Promise.all([1, 2, 3, 4, 5].map((i) => addHistory(area, { url: "https://x" + i + ".tk/" })));
  assert.equal((await getHistory(area)).length, 5);
});

test("allowlist add / has / remove", async () => {
  const area = createMemoryArea();
  assert.equal(await allowlistHas(area, "https://evil.tk/"), false);
  await allowlistAdd(area, "https://evil.tk/");
  assert.equal(await allowlistHas(area, "https://evil.tk/"), true);
  assert.equal(await allowlistHas(area, "https://evil.tk/other"), false);
  await allowlistRemove(area, "https://evil.tk/");
  assert.equal(await allowlistHas(area, "https://evil.tk/"), false);
});
