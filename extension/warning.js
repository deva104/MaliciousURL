// Warning page. Everything comes from the address (?u=&p=&r=&d=), which a
// website could also fake, so values are validated and shown with textContent only.

import { parseWarningQuery, decidedByLabel, formatPercent, truncateUrl } from "./lib/warnlink.js";
import { hostOf } from "./lib/urlrules.js";
import { backStepsFor } from "./lib/navstate.js";

const $ = (id) => document.getElementById(id);
const params = parseWarningQuery(location.search);
const state = { committed: null, showFull: false, info: { ...params, threshold: null } };

function render() {
  const info = state.info;
  $("host").textContent = info.urlValid ? hostOf(info.url) : "(invalid address)";

  const short = truncateUrl(info.url || "(none)");
  $("url").textContent = state.showFull ? info.url : short.text;
  $("toggle-url").hidden = !short.truncated;
  $("toggle-url").textContent = state.showFull ? "Show less" : "Show full address";

  let risk = formatPercent(info.probability);
  if (info.probability != null) risk += " chance of being malicious";
  if (typeof info.threshold === "number") risk += " (blocking threshold " + formatPercent(info.threshold) + ")";
  $("risk").textContent = risk;
  $("decided").textContent = decidedByLabel(info.decidedBy);

  const list = $("reasons");
  list.replaceChildren();
  const reasons = info.reasons.length ? info.reasons : ["No reason was given."];
  for (const reason of reasons) {
    const li = document.createElement("li");
    li.textContent = reason;
    list.append(li);
  }

  $("proceed").disabled = !info.urlValid;
}

function showError(text) {
  $("error").textContent = text;
  $("error").hidden = false;
}

function send(message) {
  return chrome.runtime.sendMessage(message).catch((err) => ({ ok: false, error: String(err?.message || err) }));
}

render();

// Tell the service worker we are showing; it sets the red "!" badge and tells us
// whether the blocked page became a history entry (decides how far "back" goes).
send({
  type: "warning:opened",
  url: params.url,
  probability: params.probability,
  reasons: params.reasons,
  decidedBy: params.decidedBy,
}).then((res) => {
  if (!res || !res.ok) return;
  state.committed = res.committed;
  if (res.record) {
    state.info = { ...state.info, threshold: res.record.threshold ?? null };
    render();
  }
  if (!res.verified) {
    $("note").textContent =
      "Note: URL Guard has no record of blocking this address in this tab (the page may have been opened " +
      "from a link or restored after a restart). Treat it as dangerous anyway.";
    $("note").hidden = false;
  }
});

$("toggle-url").addEventListener("click", () => {
  state.showFull = !state.showFull;
  render();
});

// "Go back to safety" must never land on the blocked page again:
//  - if the blocked page became a history entry, go back 2 (skip it); otherwise 1;
//  - if there is not enough history, the service worker opens the new tab page;
//  - the service worker also arms a guard: if history still leads to the blocked
//    URL, it sends the tab to the new tab page instead of showing this page again.
$("back").addEventListener("click", async () => {
  $("back").disabled = true;
  await send({ type: "warning:goBack", url: params.url });
  const steps = backStepsFor(state.committed);
  if (history.length > steps) {
    // No fallback timer here on purpose: a slow page would still be loading when
    // the timer fired, and the fallback would cancel the back navigation.
    history.go(-steps);
  } else {
    await send({ type: "warning:newTab" });
  }
});

// Back/forward cache: if this page is shown again from history, re-enable the button.
window.addEventListener("pageshow", (event) => {
  if (event.persisted) $("back").disabled = false;
});

// Two-step confirmation inside the page (no alert/confirm dialogs).
$("proceed").addEventListener("click", () => {
  $("proceed").hidden = true;
  $("confirm").hidden = false;
  $("confirm-no").focus();
});

$("confirm-no").addEventListener("click", () => {
  $("confirm").hidden = true;
  $("proceed").hidden = false;
  $("back").focus();
});

$("confirm-yes").addEventListener("click", async () => {
  $("confirm-yes").disabled = true;
  const res = await send({ type: "warning:proceed", url: params.url });
  if (!res || !res.ok) {
    $("confirm-yes").disabled = false;
    showError("Could not open the site: " + (res?.error || "unknown error"));
  }
});
