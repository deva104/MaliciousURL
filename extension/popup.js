// Popup: API status, verdict for the current tab, manual URL check, protection switch.

import { MAX_URL_LENGTH } from "./config.js";
import { checkHealth, predictWithRetry } from "./lib/api.js";
import { createCache } from "./lib/cache.js";
import { getSettings, saveSettings, getApiStatus } from "./lib/storage.js";
import { prepareUserInput, skipReason, stripHash, SKIP_REASONS } from "./lib/urlrules.js";
import { parseWarningQuery, decidedByLabel, formatPercent, truncateUrl } from "./lib/warnlink.js";

const $ = (id) => document.getElementById(id);
const local = chrome.storage.local;
const session = chrome.storage.session;
const cache = createCache(session);
const WARNING_PAGE = chrome.runtime.getURL("warning.html");
const WAKING_TEXT = "Server is waking up, this can take up to a minute...";

let settings = await getSettings(local);
let apiState = null; // last /health result: online | waking | offline | ...

// ---------- small DOM helpers (textContent only, never innerHTML) ----------
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function showMsg(msg, text, isError = false) {
  msg.textContent = text || "";
  msg.className = "msg small" + (isError ? " error" : "");
  msg.hidden = !text;
}

// Draws one verdict box. `result` is the internal shape from lib/api.js (or the cache).
function renderResult(container, result, { note } = {}) {
  const box = el("div", null, "result");
  box.append(
    el("p", result.malicious ? "Malicious" : "Safe", "verdict " + (result.malicious ? "danger" : "safe")),
  );

  const table = el("table", null, "kv small");
  const row = (label, value) => {
    const tr = el("tr");
    tr.append(el("th", label), el("td", value));
    table.append(tr);
  };
  let risk = formatPercent(result.probability);
  if (typeof result.threshold === "number") risk += " (threshold " + formatPercent(result.threshold) + ")";
  row("Risk", risk);
  row("Decided by", decidedByLabel(result.decidedBy) + (result.modelOnly ? " (model only)" : ""));
  if (typeof result.serverLatencyMs === "number" || typeof result.roundTripMs === "number") {
    const parts = [];
    if (typeof result.serverLatencyMs === "number") parts.push(result.serverLatencyMs + " ms on server");
    if (typeof result.roundTripMs === "number") parts.push(Math.round(result.roundTripMs) + " ms total");
    row("Latency", parts.join(", "));
  }
  if (result.modelVersion) row("Model", result.modelVersion);
  box.append(table);

  if (result.reasons && result.reasons.length) {
    const list = el("ul", null, "reasons small");
    for (const reason of result.reasons.slice(0, 5)) list.append(el("li", reason));
    box.append(list);
  }
  if (note) box.append(el("p", note, "small muted"));
  container.replaceChildren(box);
}

// ---------- API status line ----------
async function showApiStatus() {
  const last = await getApiStatus(session);
  if (last && last.state === "unreachable") {
    $("api-last").textContent =
      "Last automatic check (" + new Date(last.at).toLocaleTimeString() + "): API offline / waking up";
    $("api-last").hidden = false;
  }
  const health = await checkHealth(settings.apiBase);
  let text = "API: " + health.message.charAt(0).toLowerCase() + health.message.slice(1);
  if (health.state === "online") text = "API: online";
  apiState = health.state;
  $("api-status").textContent = text;
  // The live model name is long, so model + version go in the tooltip, not the 340 px line.
  $("api-status").title = [settings.apiBase || "(no API URL set)", health.model, health.version]
    .filter(Boolean)
    .join("\n");
  if (health.state === "online") $("api-last").hidden = true;
}

// ---------- one check with "waking up" retries ----------
async function runCheck(url, { modelOnly, container, button, msg }) {
  button.disabled = true;
  container.replaceChildren();
  showMsg(msg, "Checking...");
  try {
    const result = await predictWithRetry(settings.apiBase, url, {
      modelOnly,
      onWaiting: () => showMsg(msg, WAKING_TEXT),
    });
    if (!modelOnly) {
      // Same cache the automatic protection uses (model-only answers are not cached).
      await cache.set(url, {
        malicious: result.malicious,
        probability: result.probability,
        threshold: result.threshold,
        decidedBy: result.decidedBy,
        reasons: result.reasons,
        modelVersion: result.modelVersion,
        checkedAt: result.checkedAt,
      });
    }
    showMsg(msg, "");
    // The server answered, so it is awake now: refresh a stale "waking up" status line.
    if (apiState !== "online") showApiStatus().catch(() => {});
    return result;
  } catch (err) {
    showMsg(msg, err?.message || String(err), true);
    return null;
  } finally {
    button.disabled = false;
  }
}

// ---------- "This tab" ----------
async function showThisTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || "";
  const target = $("tab-result");

  if (url.startsWith(WARNING_PAGE)) {
    const info = parseWarningQuery(url.slice(url.indexOf("?") + 1));
    $("tab-url").textContent = truncateUrl(info.url, 80).text;
    renderResult(target, { ...info, malicious: true }, { note: "Blocked by URL Guard." });
    return;
  }

  $("tab-url").textContent = url ? truncateUrl(url, 80).text : "(no address)";
  const skip = skipReason(url, { apiBase: settings.apiBase });
  if (skip === "too_long") {
    // Not sent to the API; the page was allowed (fail open).
    target.replaceChildren(
      el("p", SKIP_REASONS.too_long, "verdict"),
      el("p", "This address has " + url.length + " characters (limit " + MAX_URL_LENGTH + "), so automatic protection did not check it.", "small muted"),
    );
    return;
  }
  if (skip) {
    target.replaceChildren(el("p", "Not checked: " + SKIP_REASONS[skip] + ".", "small muted"));
    return;
  }

  const cached = await cache.get(url);
  if (cached) {
    renderResult(target, cached, {
      note: cached.checkedAt ? "From cache, checked at " + new Date(cached.checkedAt).toLocaleTimeString() + "." : "From cache.",
    });
    return;
  }
  target.replaceChildren(el("p", "Not checked yet.", "small muted"));
  const button = $("tab-check");
  button.hidden = false;
  button.addEventListener("click", async () => {
    const result = await runCheck(stripHash(url), { modelOnly: false, container: target, button, msg: $("tab-msg") });
    if (result) {
      button.hidden = true;
      renderResult(target, result, {
        note: result.malicious && settings.protection ? "Reload the page to let URL Guard block it." : null,
      });
    }
  });
}

// ---------- manual check ----------
$("check-form").addEventListener("submit", async (event) => {
  event.preventDefault(); // Enter in the text box also lands here
  const prepared = prepareUserInput($("url-input").value);
  if (!prepared.ok) {
    $("check-result").replaceChildren();
    showMsg($("check-msg"), prepared.error, true);
    return;
  }
  const modelOnly = $("model-only").checked;
  const result = await runCheck(prepared.url, {
    modelOnly,
    container: $("check-result"),
    button: $("check-btn"),
    msg: $("check-msg"),
  });
  if (result) {
    const note = prepared.addedScheme ? "No scheme given, checked as " + prepared.url : null;
    renderResult($("check-result"), result, { note });
  }
});

// ---------- protection switch ----------
function showProtection() {
  $("protection").checked = settings.protection;
  $("protection-label").textContent = settings.protection ? "On" : "Off";
}

$("protection").addEventListener("change", async () => {
  // The service worker sees this change (storage.onChanged) and updates rules + badge.
  settings = await saveSettings(local, { protection: $("protection").checked });
  showProtection();
});

$("open-settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
$("open-history").addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("options.html#history") });
});

showProtection();
showThisTab().catch((err) => $("tab-result").replaceChildren(el("p", String(err), "small error")));
showApiStatus().catch((err) => ($("api-status").textContent = "API: " + String(err)));
