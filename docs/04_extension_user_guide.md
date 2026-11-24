# Step 4: URL Guard Chrome Extension, User Guide

**Project:** Malicious URL Detection using Machine Learning (Random Forest + Ensemble Learning)
**Code:** `extension/` (Manifest V3, plain JavaScript, no build step, no frameworks, no remote code)
**Talks to:** the Step 3 API (`GET /health`, `POST /predict`, `POST /predict/batch`)

---

## 1. What it does

URL Guard checks every page you open with our ML model:

- **Automatic protection:** when a tab starts loading a web page, the extension sends the URL to the
  API. If the model says *malicious*, the tab is sent to a warning page instead.
- **Popup:** anyone can paste a URL and check it by hand. This is how teachers can test random URLs
  on demo day.
- **Instant block on repeat visits:** a URL that was blocked once is blocked by Chrome itself the next
  time, before any byte of the page loads.

### Flow

```
 you open a page in a tab
          |
          v
 webNavigation.onBeforeNavigate  (main frame only, protection ON)
          |
          +-- chrome://, file:, about:, data:, extension page ........ skip
          +-- localhost / 127.0.0.1 / the API's own host .............. skip
          +-- "Proceed anyway" earlier in this browser session ........ allow
          |
          v
 verdict cache (chrome.storage.session, 30 min) --hit--+
          | miss                                        |
          v                                             |
 POST {API}/predict   (timeout 5 s)                     |
          |                                             |
          +-- no answer / error --> FAIL OPEN: page loads, badge "?"
          |                                             |
          v                                             v
     verdict = safe  -------------------------------> nothing (no badge)
     verdict = malicious
          |
          v
 race guard: is the tab still on this URL? --no--> do nothing
          | yes
          v
 tab -> warning.html?u=...&p=...&r=...&d=...   badge red "!"
 + add to blocked history (local)
 + add declarativeNetRequest rule: next visit to this exact URL
   is redirected by Chrome instantly (max 1,000 rules, oldest removed first)

 webNavigation.onCommitted with a DIFFERENT URL than the one checked
 (URL shorteners, server redirects) --> the same check runs again for the final URL
```

## 2. Install (Load unpacked)

1. Open Chrome and go to `chrome://extensions`.
2. Switch on **Developer mode** (top right).
3. Click **Load unpacked** and choose the `extension/` folder of this project (the folder that
   contains `manifest.json`).
4. Pin it: click the puzzle icon in the toolbar, then the pin next to **URL Guard**. You should now see
   the blue "U" icon.

After changing any file in `extension/`, press the circular **reload** arrow on the URL Guard card in
`chrome://extensions`.

## 3. First-time setup

Nothing is required: the default API is the live server
**`https://malicious-url-api.onrender.com`** (the **Render (default)** preset). To check it:

1. Right-click the URL Guard icon and choose **Options** (or open the popup and click **Settings**).
2. Click **Test connection**. You should see something like
   *"Connected to Soft Voting (tuned members) [noise removed] voting_tuned_noiseclean@2026-11-24 in 600 ms"*.
   A sleeping free Render server can take up to a minute; the page shows *"Server is waking up..."* and
   keeps trying for 60 s.

To use another server, enter its **base URL** (without `/predict`) or click a preset, then **Save**:
- **Render (default)**: the live API
- **Local (http://localhost:8000)**: the real API running on your computer
- **Mock for testing (http://127.0.0.1:8765)**: the mock server, see section 10

**Use default** goes back to the Render URL.

## 4. Using the popup

Click the URL Guard icon:

| Part | What it shows |
|---|---|
| **API status** | `online`, `waking up (free server...)`, or `offline`. Checked with `/health`, 3 s timeout. Hover over it to see the API URL, model and model version. |
| **This tab** | The address of the current tab and its verdict from the cache. If it was not checked yet, click **Check now**. Browser pages (`chrome://...`) and localhost show "Not checked" and why. An address longer than 2,048 characters shows **URL too long to check**. |
| **Check a URL** | Paste any URL and press **Check** or **Enter**. Shows verdict (red *Malicious* / green *Safe*), risk %, threshold (0.8 = 80%), decided by, server latency + round trip, model version and, for malicious URLs, up to 3 reasons (safe verdicts have none). The verdict always comes from the API's `is_malicious`. |
| **Model only** | Adds `?model_only=true`: the trusted list is skipped, so you see the model's own opinion even for google.com. Use it for honest demos. |
| **Automatic protection** | On/off switch. Off = nothing is checked or blocked, badge shows grey **OFF**. |
| **Settings / Blocked history** | Open the options page. |

Input checks in the popup: empty input, spaces, non-web schemes (`javascript:`, `ftp://`, ...), words
that are not addresses ("hello") and input longer than 2,048 characters ("URL too long to check") get a
clear message and are **not** sent. If you leave out the scheme (`example.com`), `https://` is added and
the result says so. If the API itself rejects the input (422), its own message is shown, e.g.
*"url is empty"*.

If the server is asleep, the popup shows *"Server is waking up, this can take up to a minute"* and keeps
retrying for up to 60 s (one try every few seconds). While Render boots it may answer with an HTML
"loading" page instead of data; the extension treats that (and any answer without `is_malicious` and
`probability`) as *waking up*, never as a verdict.

### Toolbar badge

| Badge | Meaning |
|---|---|
| (nothing) | page checked and safe, or not a web page |
| red **!** | this tab is showing a blocked site's warning |
| grey **?** | this page could **not** be checked (API offline / waking up, or "URL too long to check") |
| grey **OFF** | automatic protection is switched off |

## 5. The warning page

- Heading **"Dangerous site blocked"**.
- **Site** (host name) and **Address**. The address is plain text, never a clickable link. Long
  addresses are cut; **Show full address** shows all of it.
- **Risk** in % and the blocking threshold.
- **Why it was blocked**: up to 3 reasons from the API.
- **Decided by**: *ML model* or *Trusted list*.
- **Go back to safety**: goes back 2 history entries if the blocked page had become a history entry,
  otherwise 1. If there is not enough history, it opens the new tab page. It can never loop back into
  the blocked URL: the service worker arms a one-shot guard, and if that back navigation still leads to
  the blocked URL, the tab is sent to the new tab page instead. (Typing the blocked URL again later
  shows the normal warning.)
- **Proceed anyway (not recommended)**: a two-step confirmation inside the page (no pop-up dialogs).
  After **Yes, I understand the risk, open the site**, the URL is allowed until the browser is closed,
  its instant-block rule is removed, and the site opens.

## 6. Settings page

- API base URL with presets, **Save**, **Test connection**, **Use default** (goes back to the value
  from `config.js`).
- **Clear cache**: forgets all cached verdicts and removes all instant-block rules.
- **Clear history**: deletes the blocked-sites list.
- **Blocked history**: the last 50 blocked sites (time, address, risk, decided by, reasons).

## 7. Permissions and why each one is needed

| Permission | Why |
|---|---|
| `webNavigation` | To notice when a tab starts (`onBeforeNavigate`) and finishes (`onCommitted`) navigating, and to which URL. This is the core of automatic protection. Chrome shows it as "Read your browsing history". |
| `tabs` | To read the current tab's address for the popup's "This tab" section, and to redirect a tab to the warning page / the new tab page. |
| `storage` | Settings and blocked history (`storage.local`, stays on this computer); verdict cache, allowlist and per-tab state (`storage.session`, cleared when the browser closes). |
| `declarativeNetRequest` | The instant block for repeat visits (one redirect rule per blocked URL) and the master "allow" rule that disables all of them when protection is off. |
| host `https://*.onrender.com/*` | To call the deployed API on Render. |
| host `http://localhost/*`, `http://127.0.0.1/*` | To call the API or the mock running on this computer (any port). |
| host `<all_urls>` | **Needed only for the instant-block rules.** Chrome lets a declarativeNetRequest rule *redirect* a request only if the extension has host access to that site, and a blocked site can be on any domain. The extension does **not** inject scripts into pages and does **not** read page content; it only sees the URL. Without `<all_urls>`, the normal check would still work, but repeat visits would not be blocked instantly. Chrome shows this as "Read and change all your data on all websites". |
| `web_accessible_resources: warning.html` | A redirect rule may only send a page to an extension page that is web accessible. Side effect: a website could open our warning page with made-up parameters. That is handled: every parameter is validated, shown as text only, and **Proceed** is disabled for anything that is not an http(s) address. |

## 8. Privacy

- **Only the URL** of the page is sent to the API. No page content, cookies, passwords or form data
  (requests are sent with `credentials: "omit"`).
- Local addresses (localhost, 127.0.0.1) and browser pages are never sent.
- The **blocked history stays on this computer** (`chrome.storage.local`); it is never uploaded.
- Cache, allowlist and per-tab state live in memory and disappear when the browser closes.
- If you use a Render URL, the URLs you visit go to that server. Use `https://` (the Settings page
  warns about plain `http://` for non-local servers).

## 9. Limitations (be honest about these in the report)

1. **The page can start loading before it is blocked.** Manifest V3 removed *blocking* `webRequest` for
   normal extensions (only policy-installed enterprise extensions keep it), so the API call is
   asynchronous. While the API thinks (usually tens of milliseconds, up to 5 s), the page may start to
   load or even flash on screen. Repeat visits are blocked instantly by the declarativeNetRequest rule.
2. **Fail-open.** If the API does not answer within 5 s, is offline, answers with an error, or answers
   with something that is not a real verdict (Render's HTML wake-up page, JSON without `is_malicious` /
   `probability`), the page is allowed and the badge shows "?". Blocking every page when our server is
   down would make the browser unusable. The downside: during an outage nothing is protected.
3. **Free-server cold start.** The free Render server sleeps after ~15 min idle; the first request can
   take ~60 s. The automatic check gives up after 5 s (fail-open, "?"), but that request still wakes the
   server, so the following pages are checked normally. The popup waits up to 60 s.
4. **URL shorteners.** The short URL is checked first (`onBeforeNavigate`); after the server redirect,
   the final URL is checked again (`onCommitted`). The final page may therefore load a moment before
   it is blocked.
5. **Main frame only.** iframes inside a page are not checked.
6. **Not checked at all:** URLs longer than 2,048 characters (automatic check skipped = fail open,
   badge "?", popup "URL too long to check"; they are never sent to the API), localhost, browser pages.
   URLs containing `*`, `^`, `|` or non-ASCII characters are still checked on every visit, but get no
   instant-block rule (the rule syntax cannot match them exactly).
7. **Cached verdicts live 30 minutes.** A new model on the server is picked up after the cache expires
   (or after **Clear cache**).
8. **"Proceed anyway" lasts until the browser closes**; there is no permanent allowlist (by design).
9. **The browser's own Back button** (not our button) from the warning page may land on the blocked
   page, which is then blocked again. That is expected; use **Go back to safety**.
10. Pages that Chrome *prerenders* from the address bar may be reported later than normal navigations.
11. The model itself can be wrong (false positives and false negatives); see the Step 2 report.

## 10. For developers: mock API, tests, checks

All tools use only Node's built-in modules (no `npm install`). Run them from the project root.

**Mock API** (follows the API contract exactly, port 8765):

```powershell
node extension/dev/mock_api.mjs
```

Options: `--slow 3000` (every request takes 3 s), `--cold 30000` (sleeping free server: requests in
the first 30 s wait until it "wakes up"), `--html-loading` (every request gets Render's HTML "waking
up" page with status 200; `--html-loading 30000` does it only for the first 30 s), `--fail` (every
request returns 500), `--port 8770`. Ports 8000 and 10000 are refused because the real API uses them.

Mock rules: an IP-address host, a URL containing both `login` and `verify`, `paypal` outside
paypal.com, or a `.tk` domain is malicious (probability 0.90 to 0.99, at most 3 reasons); everything
else is safe with no reasons. google.com, paypal.com, wikipedia.org, github.com and microsoft.com are
on its trusted list unless `?model_only=true`. Like the live API: threshold 0.8, 422 =
`{"error":"invalid_request","detail":[{"field":"url","message":"..."}]}`, 500 =
`{"error":"internal_error"}`, `/health` sends `model_version`.

**Unit tests** (66 tests: URL rules incl. the 2,048-character limit, cache TTL, api.js against the mock
including timeout / both 422 shapes / 500 / fail-open / HTML wake-up page / JSON with missing fields /
cold-start retry, the exact answers captured from the live API, reason parsing, race guard, go-back
logic, rule cap, storage):

```powershell
node --test "extension/tests/*.test.mjs"
```

**Static extension check** (manifest, every referenced file exists, icon sizes, no inline scripts or
handlers, no eval, no remote URLs in code, no innerHTML):

```powershell
node extension/dev/check_extension.mjs
```

**Live smoke test** against the deployed API (NOT a load test: at most 10 requests; it waits politely
if the free server is asleep). It calls `/health`, `/predict` on google.com, on an IP + login style URL,
with `?model_only=true`, and with an empty URL, and prints each raw answer next to what the extension
understood:

```powershell
node extension/dev/live_check.mjs
```

Result on 2026-11-25: 5 requests, 14/14 checks passed (google.com safe via trusted list, the IP + login
URL malicious at 97% with 2 reasons, model-only decided by the model, empty URL -> 422 "url is empty").

**Icons** (plain blue square with a white U, 16/32/48/128 px):

```powershell
node extension/dev/make_icons.mjs
```

**Code layout**

```
extension/
  manifest.json      MV3 manifest
  config.js          API URLs (RENDER_API_BASE is the constant to edit), timeouts, limits
  background.js      service worker: navigation checks, redirects, badge, DNR rules
  warning.html/.css/.js   the "Dangerous site blocked" page
  popup.html/.css/.js     toolbar popup
  options.html/.css/.js   settings + blocked history
  common.css         shared plain styles
  lib/api.js         ALL API knowledge: paths, field names, timeouts, error mapping
  lib/urlrules.js    which URLs are checked; validation of popup input
  lib/cache.js       verdict cache with TTL (storage.session)
  lib/storage.js     settings, history, allowlist helpers (+ in-memory store for tests)
  lib/rules.js       declarativeNetRequest rule planning (cap 1,000, oldest first, master allow rule)
  lib/navstate.js    per-tab state: race guard, go-back logic
  lib/warnlink.js    build/parse warning page parameters, reason parsing
  lib/lock.js        tiny async lock for read-modify-write updates
  icons/             generated PNGs
  dev/               mock_api.mjs, live_check.mjs, check_extension.mjs, make_icons.mjs (not used by Chrome)
  tests/             node --test files (not used by Chrome)
```

Debugging: on `chrome://extensions`, the URL Guard card has **Errors** and a **service worker** link
(opens DevTools for `background.js`). Right-click the popup and choose **Inspect** for popup errors.

## 11. Troubleshooting

| Problem | What to do |
|---|---|
| Badge "?" on every page | The API is offline or waking up. Open the popup: the status line says which. Settings > **Test connection**. Wait a minute for a sleeping Render server. |
| "API endpoint not found (404)" | The base URL is wrong. It must not end in `/predict` or `/health`. |
| "Cannot reach the API" with the mock | Is `node extension/dev/mock_api.mjs` still running? Use the **Mock** preset (`127.0.0.1:8765`). |
| Nothing is ever blocked | Is protection **On** (no grey OFF badge)? Are you testing on `localhost` (never checked)? Was the URL cached as safe? Click **Clear cache**. |
| I edited `config.js` but nothing changed | Reload the extension on `chrome://extensions`. If a URL was saved in Settings, it wins; click **Use default**. |
| A site I trust is blocked | Use **Proceed anyway** (lasts until the browser closes). Report the false positive to the model team. |
| "Load unpacked" error | Choose the `extension/` folder itself (the one with `manifest.json`). Run `node extension/dev/check_extension.mjs` to find the problem. |
| Port 8765 already in use | `node extension/dev/mock_api.mjs --port 8770`, then enter `http://127.0.0.1:8770` in Settings. |

## 12. Manual test checklist

Setup: start the mock (`node extension/dev/mock_api.mjs`), load the extension, choose the **Mock**
preset in Settings, **Save**. The test URL `https://example.com/login?verify=1` is a real, harmless page
that the mock calls malicious (it contains "login" and "verify"). Use a new number (`verify=2`, `3`, ...)
when a step needs a URL that was not blocked before.

| # | Step | Expected result |
|---|---|---|
| 1 | Settings > **Test connection** | "Connected to mock-rules mock-1.0 in ... ms" |
| 2 | Open `https://www.google.com` | Loads normally. No badge. Popup "This tab": **Safe**, decided by *Trusted list*. |
| 3 | In the same tab, open `https://example.com/login?verify=1` | Within a moment the tab shows **Dangerous site blocked**, risk 90-99%, the reason "The URL contains both 'login' and 'verify'", decided by *ML model*. Badge red **!**. The terminal running the mock logs the request. |
| 4 | Click **Go back to safety** | You are back on google.com, **not** on the warning page again. Click it a few times on new blocked URLs: it never loops. |
| 5 | Open `https://example.com/login?verify=1` again | The warning appears **instantly** (instant-block rule); the mock terminal logs **no** new request. |
| 6 | On the warning page click **Proceed anyway**, then **Yes, I understand the risk, open the site** | The real example.com page opens. Reloading it is not blocked again (allowed for this session). |
| 7 | Settings > **Blocked history** | The blocked URLs are listed with time, risk, decided by and reasons. |
| 8 | Popup: switch **Automatic protection** off, open `https://example.com/login?verify=2` | Badge grey **OFF**; the page loads normally. Switch it back on: the OFF badge disappears. |
| 9 | Popup: paste `paypal-login.tk/verify`, press **Enter** | Red **Malicious**, risk %, 3 reasons, latency, and the note "No scheme given, checked as https://paypal-login.tk/verify". |
| 10 | Popup: check `google.com`, then tick **Model only** and check again | First *Safe, Trusted list*; then *Safe, ML model (model only)*. Empty input and `hello` show an error message instead. |
| 11 | Stop the mock (Ctrl+C), open `https://example.com/login?verify=3` | **Fail open**: the page loads, badge grey **?**. Popup says "API: offline (cannot reach the API)". |
| 12 | Start the mock with `--cold 30000`, open the popup, check `1.2.3.4/x` | "Server is waking up, this can take up to a minute..." then, after ~30 s, **Malicious**. |
| 13 | Start the mock with `--html-loading 30000` (Render's HTML wake-up page), open `https://example.com/login?verify=5`, then check `1.2.3.4/y` in the popup | The page loads with badge grey **?** (fail open, the HTML page is never taken as a verdict); the popup shows "Server is waking up..." and, after ~30 s, **Malicious**. |
| 14 | Settings > **Use default**, then **Test connection** | Connects to `https://malicious-url-api.onrender.com` (may take up to a minute if it was asleep). |

## 13. Two-minute demo script (presentation day)

Before the demo: API awake (open Settings > **Test connection** 2 minutes before), protection on,
browser open on google.com, Settings page open in a second tab.

1. **(0:00) What it is.** "URL Guard sends every address you open to our Random Forest API and blocks
   the dangerous ones. Only the URL is sent; nothing from the page."
2. **(0:15) Safe browsing.** Open a normal site (google.com, wikipedia.org). "No badge: checked and safe."
3. **(0:30) A phishing-style URL.** Open a malicious test URL from the Step 2 test set (or
   `https://example.com/login?verify=1` with the mock). The warning page appears: point out the risk %,
   the reasons and "Decided by: ML model".
4. **(0:50) Safety buttons.** Click **Go back to safety**: back on the safe page. Mention that
   **Proceed anyway** needs two clicks and only lasts for the session.
5. **(1:05) Teachers' turn.** Open the popup, ask a teacher for any URL, paste it, press Enter. Tick
   **Model only** to show the model's own verdict without the trusted list. Point out the server
   latency (a few ms).
6. **(1:35) Robustness.** "If our free server is asleep or down, the extension fails open with a grey
   '?' instead of breaking the browser; a URL blocked once is blocked instantly by Chrome next time."
7. **(1:50) Privacy.** Show **Blocked history** in Settings: "stored only on this computer".

## 14. API contract (final, checked against the live API on 2026-11-25)

All of this lives in `extension/lib/api.js`; a change on the API side is a one-file fix there.

1. Base URL `https://malicious-url-api.onrender.com`; endpoints at its root: `GET /health`,
   `POST /predict`, `POST /predict/batch`.
2. `POST /predict` body `{"url": "..."}` with `Content-Type: application/json`; model-only mode is
   the query `?model_only=true`.
3. **The verdict is `is_malicious` (boolean), always.** The extension never recomputes it from
   `probability` and `threshold`; `verdict` is ignored.
4. `probability` is a number from 0 to 1. `threshold` is **0.8**; it is displayed (as 80%) but not used
   for the decision.
5. `decided_by` is `"model"` or `"trusted_list"`.
6. `reasons` is `[]` for safe verdicts and at most 3 short strings for malicious ones.
7. `GET /health` returns `{"status": "ok", "model_loaded": true, "model": "...",
   "model_version": "...", "uptime_s": ...}`. Note: the live API sends **`model_version`** (an earlier
   draft said `version`); `model_loaded: false` is shown as "waking up".
8. Errors:
   - 422: `{"error": "invalid_request", "detail": [{"field": "url", "message": "url is empty"}]}`.
     The `message` is shown to the user as is. FastAPI's default shapes (`{"detail": "text"}` and
     `{"detail": [{"loc": [...], "msg": "..."}]}`) are still understood.
   - 500: `{"error": "internal_error"}`.
9. **Waking up, never a verdict:** 502/503/504, an HTML or other non-JSON body (Render's wake-up page,
   even with status 200), and JSON without a boolean `is_malicious` and a numeric `probability` are all
   treated as "server waking up": automatic protection fails open (badge "?"), the popup keeps retrying.
10. URLs up to **2,048 characters** (the API is being changed to accept that many). Longer URLs are
    never sent: the automatic check is skipped (fail open) and the popup shows "URL too long to check".
11. `/predict` must answer within **5 s** when warm (live: 160 to 300 ms round trip); slower answers
    fail open.
12. No authentication, no cookies (`credentials: "omit"`).
13. `POST /predict/batch` takes `{"urls": [...]}` (1 to 100) and returns
    `{"results": [<predict shape>...], "count": n, "latency_ms": x}` in the same order.

## 15. Changing the API URL

The live URL is already the default: `RENDER_API_BASE` in `extension/config.js`. If it ever changes:

- **For everyone who loads the extension:** edit `RENDER_API_BASE` (no trailing slash), then reload
  the extension on `chrome://extensions`.
- **Just on this computer:** Settings > type the URL > **Save** > **Test connection**. A saved URL wins
  over the constant; **Use default** removes it again.

`host_permissions` already cover `https://*.onrender.com/*` (and `<all_urls>` covers a custom domain).
