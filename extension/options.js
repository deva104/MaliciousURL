// Settings page: API URL (+ presets, test), clear cache/history, blocked history table.

import { API_PRESETS, DEFAULT_API_BASE, MAX_BLOCK_RULES } from "./config.js";
import { normalizeBaseUrl, waitForHealth } from "./lib/api.js";
import { createCache } from "./lib/cache.js";
import { getSettings, getSavedSettings, saveSettings, getHistory, clearHistory } from "./lib/storage.js";
import { createRuleManager } from "./lib/rules.js";
import { decidedByLabel, formatPercent, truncateUrl } from "./lib/warnlink.js";

const $ = (id) => document.getElementById(id);
const local = chrome.storage.local;
const session = chrome.storage.session;
const cache = createCache(session);
const rules = createRuleManager(chrome.declarativeNetRequest);

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function msg(id, text, isError = false) {
  $(id).textContent = text || "";
  $(id).className = "msg" + (isError ? " error" : "");
}

// ---------- API URL ----------
async function showApiBase() {
  const saved = await getSavedSettings(local);
  const settings = await getSettings(local);
  $("api-base").value = settings.apiBase;
  $("current-base").textContent = settings.apiBase + (saved.apiBase ? " (saved in Settings)" : " (default)");
  $("default-base").textContent = DEFAULT_API_BASE;
}

for (const preset of API_PRESETS) {
  const button = el("button", preset.label);
  button.type = "button";
  if (!preset.url) {
    button.disabled = true;
    button.title = "Not known yet: set RENDER_API_BASE in config.js, or type the URL above";
  }
  button.addEventListener("click", () => {
    $("api-base").value = preset.url;
    msg("api-msg", "Preset filled in. Press Save to use it.");
  });
  $("presets").append(button);
}

$("save").addEventListener("click", async () => {
  const checked = normalizeBaseUrl($("api-base").value);
  if (!checked.ok) return msg("api-msg", checked.error, true);
  await saveSettings(local, { apiBase: checked.url });
  await showApiBase();
  msg("api-msg", "Saved." + (checked.warning ? " Warning: " + checked.warning : ""), !!checked.warning);
});

$("use-default").addEventListener("click", async () => {
  await saveSettings(local, { apiBase: undefined }); // removes the saved value
  await showApiBase();
  msg("api-msg", "Back to the default from config.js.");
});

$("test").addEventListener("click", async () => {
  const checked = normalizeBaseUrl($("api-base").value);
  if (!checked.ok) return msg("api-msg", checked.error, true);
  $("test").disabled = true;
  msg("api-msg", "Testing " + checked.url + "/health ...");
  try {
    const health = await waitForHealth(checked.url, {
      onWaiting: () => msg("api-msg", "Server is waking up, this can take up to a minute..."),
    });
    if (health.state === "online") {
      const about = [health.model, health.version].filter(Boolean).join(" ");
      msg(
        "api-msg",
        "Connected" + (about ? " to " + about : "") + " in " + Math.round(health.roundTripMs) + " ms." +
          (typeof health.uptimeS === "number" ? " Server uptime " + Math.round(health.uptimeS) + " s." : ""),
      );
    } else {
      msg("api-msg", "Not connected: " + health.message, true);
    }
  } finally {
    $("test").disabled = false;
  }
});

// ---------- stored data ----------
async function showStats() {
  const [cached, blocks] = await Promise.all([cache.size(), rules.countBlocks()]);
  $("stats").textContent =
    "Cached verdicts: " + cached + ". Instant-block rules: " + blocks + " of " + MAX_BLOCK_RULES + ".";
}

$("clear-cache").addEventListener("click", async () => {
  const removed = await cache.clear();
  const ruleCount = await rules.clearBlocks();
  msg("data-msg", "Cleared " + removed + " cached verdicts and " + ruleCount + " instant-block rules.");
  await showStats();
});

$("clear-history").addEventListener("click", async () => {
  await clearHistory(local);
  msg("data-msg", "History cleared.");
});

// ---------- history table ----------
async function showHistory() {
  const items = await getHistory(local);
  const body = $("history-body");
  body.replaceChildren();
  for (const item of items) {
    const tr = el("tr");
    tr.append(el("td", new Date(item.time).toLocaleString()));
    const urlCell = el("td", truncateUrl(item.url, 100).text, "url");
    urlCell.title = item.url; // full address on hover; shown as text, never as a link
    tr.append(urlCell);
    tr.append(el("td", formatPercent(item.probability), "danger"));
    tr.append(el("td", decidedByLabel(item.decidedBy)));
    const reasons = el("td");
    const list = el("ul");
    for (const reason of item.reasons || []) list.append(el("li", reason));
    reasons.append(list);
    tr.append(reasons);
    body.append(tr);
  }
  $("history-table").hidden = items.length === 0;
  $("history-empty").hidden = items.length > 0;
}

// Keep the page current while it is open (e.g. a site gets blocked in another tab).
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes.history) showHistory();
  if (areaName === "local" && changes.settings) showApiBase();
});

await showApiBase();
await showHistory();
await showStats();
