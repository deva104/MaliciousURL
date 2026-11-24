// URL Guard service worker (Manifest V3).
//
// Flow for every main-frame navigation while protection is ON:
//   onBeforeNavigate -> skip list -> allowlist -> cache -> API (5 s timeout)
//     safe       -> nothing
//     malicious  -> race guard -> redirect the tab to warning.html + add an instant DNR rule
//     no answer  -> FAIL OPEN (page loads), badge "?"
//   onCommitted with a different URL (shorteners, server redirects) -> same check again.
//
// MV3 can stop this worker whenever it is idle, so every listener is registered
// at the top level and all state lives in chrome.storage, never in globals.

import { TIMEOUTS } from "./config.js";
import { predictFailOpen } from "./lib/api.js";
import { createCache } from "./lib/cache.js";
import { skipReason, stripHash, isHttpUrl, SKIP_REASONS } from "./lib/urlrules.js";
import { getSettings, addHistory, allowlistHas, allowlistAdd, setApiStatus } from "./lib/storage.js";
import { createRuleManager, urlFromRule } from "./lib/rules.js";
import { buildWarningPath, parseWarningQuery, cleanReasons } from "./lib/warnlink.js";
import * as nav from "./lib/navstate.js";

const local = chrome.storage.local;
const session = chrome.storage.session;
const cache = createCache(session);
const rules = createRuleManager(chrome.declarativeNetRequest);

const WARNING_PAGE = chrome.runtime.getURL("warning.html");
const isWarningUrl = (url) => typeof url === "string" && url.startsWith(WARNING_PAGE);
const COLOR = { danger: "#c62828", grey: "#6b6b6b" };

// Only de-duplicates API calls that are running right now (two events for the
// same URL). Losing it when the worker stops is harmless.
const inFlight = new Map();

// ---------------- listeners (top level!) ----------------

chrome.runtime.onInstalled.addListener(() => {
  init().catch(logError);
});
chrome.runtime.onStartup.addListener(() => {
  init().catch(logError);
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes.settings) {
    const before = changes.settings.oldValue?.protection;
    const after = changes.settings.newValue?.protection;
    if (before !== after) applyProtectionState().catch(logError);
  }
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0 || details.tabId < 0) return; // main frame of a real tab only
  onBeforeNavigate(details.tabId, details.url).catch(logError);
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || details.tabId < 0) return;
  onCommitted(details.tabId, details.url).catch(logError);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  nav.forgetTab(session, tabId).catch(logError);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false; // only our own pages
  handleMessage(message, sender).then(sendResponse, (err) =>
    sendResponse({ ok: false, error: String(err?.message || err) }),
  );
  return true; // we answer asynchronously
});

// ---------------- setup ----------------

async function init() {
  await applyProtectionState();
  await cache.prune();
}

// Protection ON/OFF: toggles the master DNR allow rule and the global badge.
async function applyProtectionState() {
  const { protection } = await getSettings(local);
  await rules.setProtection(protection);
  await chrome.action.setBadgeBackgroundColor({ color: COLOR.grey });
  await chrome.action.setBadgeText({ text: protection ? "" : "OFF" });
  await chrome.action.setTitle({ title: protection ? "URL Guard: protection on" : "URL Guard: protection OFF" });
  // A tab-specific badge would hide the global one, so reset them (warning tabs keep "!").
  for (const tab of await chrome.tabs.query({})) {
    if (protection && isWarningUrl(tab.url)) await setTabBadge(tab.id, "!", "URL Guard blocked a dangerous site");
    else await setTabBadge(tab.id, null);
  }
}

// ---------------- navigation handling ----------------

async function onBeforeNavigate(tabId, rawUrl) {
  const url = stripHash(rawUrl);
  await nav.recordNavigation(session, tabId, url, { committed: false });
  if (isWarningUrl(url)) return; // our own warning page sets its badge itself
  await setTabBadge(tabId, null);
  await checkAndProtect(tabId, url);
}

async function onCommitted(tabId, rawUrl) {
  const url = stripHash(rawUrl);
  const before = await nav.getNav(session, tabId);
  await nav.recordNavigation(session, tabId, url, { committed: true });
  if (isWarningUrl(url)) return;
  if (before && before.url === url) return; // already checked in onBeforeNavigate
  // The committed URL differs from what we checked: a shortener or a server redirect.
  await setTabBadge(tabId, null);
  await checkAndProtect(tabId, url);
}

async function checkAndProtect(tabId, url) {
  const settings = await getSettings(local);
  if (!settings.protection) return;

  // The user pressed "Go back to safety" and history led back to the blocked page:
  // send the tab to the new tab page instead of showing the warning again.
  if (await nav.consumeBackGuard(session, tabId, url)) {
    await openNewTabPage(tabId);
    return;
  }

  const skip = skipReason(url, { apiBase: settings.apiBase });
  if (skip) {
    if (skip === "too_long") await setTabBadge(tabId, "?", "URL Guard: " + SKIP_REASONS.too_long);
    return;
  }
  if (await allowlistHas(session, url)) return; // "Proceed anyway" earlier in this session

  let verdict = await cache.get(url);
  if (!verdict) verdict = await verdictFromRule(url); // known bad URL, no API call needed
  if (!verdict) {
    const outcome = await checkOnce(settings.apiBase, url);
    if (!outcome.ok) {
      // FAIL OPEN: we never block a page just because the API is unreachable.
      await setApiStatus(session, {
        state: "unreachable",
        message: "API offline / waking up",
        detail: outcome.error.message,
      });
      if (nav.isStillCurrent(await nav.getNav(session, tabId), url)) {
        await setTabBadge(tabId, "?", "URL Guard: API offline / waking up. This page was not checked.");
      }
      return;
    }
    verdict = slimVerdict(outcome.result);
    await cache.set(url, verdict);
    await setApiStatus(session, { state: "online", message: "Online" });
  }

  if (!verdict.malicious) return;

  // Race guard: the user may have moved on while we waited for the API.
  if (!nav.isStillCurrent(await nav.getNav(session, tabId), url)) return;
  await blockTab(tabId, url, verdict);
}

function checkOnce(apiBase, url) {
  const key = apiBase + " " + url;
  if (!inFlight.has(key)) {
    const job = predictFailOpen(apiBase, url, { timeoutMs: TIMEOUTS.predictMs }).finally(() => inFlight.delete(key));
    inFlight.set(key, job);
  }
  return inFlight.get(key);
}

// What we keep in the cache (no need to store everything the API sends).
function slimVerdict(r) {
  return {
    malicious: r.malicious,
    probability: r.probability,
    threshold: r.threshold,
    decidedBy: r.decidedBy,
    reasons: cleanReasons(r.reasons),
    modelVersion: r.modelVersion,
    checkedAt: r.checkedAt,
  };
}

// A DNR rule exists for this URL, so it was found malicious before. Rebuild the
// verdict from the rule's warning link. (The rule normally redirects by itself,
// but a page restored from the back/forward cache makes no request, so the rule
// never fires. This catches it.)
async function verdictFromRule(url) {
  const rule = await rules.findForUrl(url);
  if (!rule || urlFromRule(rule) !== url) return null;
  const path = rule.action?.redirect?.extensionPath || "";
  const info = parseWarningQuery(path.slice(path.indexOf("?") + 1));
  return {
    malicious: true,
    probability: info.probability,
    threshold: null,
    decidedBy: info.decidedBy || "model",
    reasons: info.reasons,
    modelVersion: null,
    checkedAt: null,
  };
}

async function blockTab(tabId, url, verdict) {
  const info = { url, probability: verdict.probability, reasons: verdict.reasons, decidedBy: verdict.decidedBy };
  const path = buildWarningPath(info);
  await nav.setBlockRecord(session, tabId, { ...info, threshold: verdict.threshold, at: Date.now() });
  try {
    await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(path.slice(1)) });
  } catch {
    return; // the tab was closed meanwhile
  }
  await setTabBadge(tabId, "!", "URL Guard blocked a dangerous site");
  await addHistory(local, info);
  await rules.addBlock(url, path).catch(logError); // instant block next time
}

async function openNewTabPage(tabId) {
  try {
    await chrome.tabs.update(tabId, { url: "chrome://newtab/" });
  } catch {
    await chrome.tabs.update(tabId, { url: "about:blank" }).catch(() => {});
  }
}

// text: "!" (blocked, red), "?" (not checked, grey), null (back to the global badge)
async function setTabBadge(tabId, text, title) {
  try {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: text === "!" ? COLOR.danger : COLOR.grey });
    await chrome.action.setBadgeText({ tabId, text });
    await chrome.action.setTitle({ tabId, title: title || "URL Guard" });
  } catch {
    // tab already closed, or an old Chrome that does not accept null: ignore
  }
}

// ---------------- messages from the warning page ----------------

async function handleMessage(message, sender) {
  const tabId = sender.tab?.id;
  const url = typeof message?.url === "string" ? stripHash(message.url) : "";

  switch (message?.type) {
    case "warning:opened": {
      if (tabId == null) return { ok: false, error: "no tab" };
      await setTabBadge(tabId, "!", "URL Guard blocked a dangerous site");
      const record = await nav.getBlockRecord(session, tabId);
      let verified = !!record && record.url === url;
      if (!verified && isHttpUrl(url) && (await rules.findForUrl(url))) {
        // Opened by an instant DNR rule (repeat visit): the worker did not see it, log it now.
        verified = true;
        await addHistory(local, {
          url,
          probability: message.probability,
          reasons: cleanReasons(message.reasons),
          decidedBy: message.decidedBy,
        });
      }
      const navState = await nav.getNav(session, tabId);
      return {
        ok: true,
        verified,
        record: verified && record && record.url === url ? record : null,
        committed: nav.blockedPageCommitted(navState, url, isWarningUrl),
      };
    }

    case "warning:goBack": {
      if (tabId == null) return { ok: false };
      await nav.setBackGuard(session, tabId, url);
      return { ok: true };
    }

    case "warning:newTab": {
      if (tabId == null) return { ok: false };
      await openNewTabPage(tabId);
      return { ok: true };
    }

    case "warning:proceed": {
      if (tabId == null) return { ok: false, error: "no tab" };
      if (!isHttpUrl(url)) return { ok: false, error: "This is not an http(s) address." };
      await allowlistAdd(session, url); // for this browser session only
      await rules.removeForUrl(url);
      await nav.clearBlockRecord(session, tabId);
      await setTabBadge(tabId, null);
      await chrome.tabs.update(tabId, { url });
      return { ok: true };
    }

    default:
      return { ok: false, error: "unknown message" };
  }
}

function logError(err) {
  console.warn("[URL Guard]", err);
}
