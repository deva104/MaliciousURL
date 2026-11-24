# Demo Script: Presentation Day

**Live API:** https://malicious-url-api.onrender.com (Swagger UI: `/docs`)
**Extension:** URL Guard (`extension/`, see `docs/04_extension_user_guide.md`)

All verdicts below were recorded from the **live API** on 2026-11-25 at 00:48–00:49 IST, in two
modes: normal (trusted list on) and `?model_only=true`. Raw results are in
`reports/metrics/demo_live_results.json` (`scripts/demo_calls.py`, 45 requests).

> ⚠️ **Rule:** open in a browser tab **only** the rows marked **SAFE TO OPEN IN A TAB**. Paste every
> **POPUP ONLY** URL into the URL Guard popup (or Swagger), and **never** open them in a tab. The
> OpenPhish URLs are real, live phishing pages.

## 1. Demo URL table

| # | URL | group | open how | verdict (normal) | decided by | model-only verdict / P(malicious) | top reason (model) |
|---|---|---|---|---|---|---|---|
| 1 | `https://www.google.com/search?q=random+forest+phishing+detection` | safe | **SAFE TO OPEN IN A TAB** | safe | trusted list | safe / 0.073 | – |
| 2 | `https://www.youtube.com/watch?v=aircAruvnKk` | safe | **SAFE TO OPEN IN A TAB** | safe | trusted list | safe / 0.018 | – |
| 3 | `https://www.mitaoe.ac.in` | safe | **SAFE TO OPEN IN A TAB** | safe | trusted list | safe / 0.107 | – |
| 4 | `https://www.onlinesbi.sbi/` | safe | **SAFE TO OPEN IN A TAB** | safe | trusted list | safe / 0.306 | – |
| 5 | `https://en.wikipedia.org/wiki/Random_forest` | safe | **SAFE TO OPEN IN A TAB** | safe | trusted list | safe / 0.051 | – |
| 6 | `https://github.com/deva104/MaliciousURL` | safe | **SAFE TO OPEN IN A TAB** | safe | trusted list | safe / 0.130 | – |
| 7 | `https://www.amazon.in/Apple-MacBook-Chip-13-inch-256GB/dp/B08N5W4NNB` | safe | **SAFE TO OPEN IN A TAB** | safe | trusted list | safe / 0.289 | – |
| 8 | `https://www.irctc.co.in` | safe | **SAFE TO OPEN IN A TAB** | safe | trusted list | safe / 0.194 | – |
| 9 | `http://203.0.113.45/secure/login/verify-account.php` | harmless-but-suspicious (RFC 5737 documentation IP, cannot host a real site) | **SAFE TO OPEN IN A TAB** | **malicious** | model | malicious / 0.990 | Several login / verification words · Host is an IP address, not a domain name |
| 10 | `http://198.51.100.7/paypal/login/verify` | harmless-but-suspicious (documentation IP) | **SAFE TO OPEN IN A TAB** | **malicious** | model | malicious / 0.994 | Several login / verification words · Brand name appears outside the real domain · Host is an IP address, not a domain name |
| 11 | `http://192.0.2.10/paypal.com/webscr/cmd=login` | harmless-but-suspicious (documentation IP) | **SAFE TO OPEN IN A TAB** | **malicious** | model | malicious / 0.979 | Several login / verification words · Brand name appears outside the real domain · Host is an IP address, not a domain name |
| 12 | `paypal.com.secure-account-verify.xyz/signin` | look-alike | POPUP ONLY | **malicious** | model | malicious / 0.989 | Top-level domain .xyz is frequently used for malicious sites · Several login / verification words · Random-looking host name |
| 13 | `http://xn--pypal-4ve.com/login` | look-alike (punycode) | POPUP ONLY | **malicious** | model | malicious / 0.856 | Internationalised (punycode) domain, possible look-alike |
| 14 | `bit.ly/3abcXYZ` | look-alike (shortener) | POPUP ONLY | **malicious** | model | malicious / 0.864 | URL shortener hides the real destination |
| 15 | `http://ptvd9-f5v-857a-15vyc-29-09-2026-aa-4t1.pages.dev/` | OpenPhish (live phishing) | POPUP ONLY | **malicious** | model | malicious / 0.989 | Top-level domain .dev is frequently used for malicious sites · Random-looking host name |
| 16 | `http://c1t77f-kehr8a7q8-arcadawebapps2.vercel.app/` | OpenPhish | POPUP ONLY | **malicious** | model | malicious / 0.998 | Top-level domain .app is frequently used for malicious sites · Random-looking host name |
| 17 | `https://vup4t-kca-8435-a67de-17-10-2026-aa.pages.dev/` | OpenPhish | POPUP ONLY | **malicious** | model | malicious / 0.992 | Top-level domain .dev is frequently used for malicious sites · Random-looking host name |
| 18 | `https://sp28ct11-mavkaro-biz-velzuni.pages.dev/` | OpenPhish | POPUP ONLY | **malicious** | model | malicious / 0.997 | Top-level domain .dev is frequently used for malicious sites · Random-looking host name |
| 19 | `http://www.ieiekkkk.weebly.com/` | OpenPhish | POPUP ONLY | safe (**missed**) | model | safe / 0.536 | – |
| 20 | `https://www.roblox.com.pt/users/898385753150/profile` | OpenPhish | POPUP ONLY | safe (**missed**) | model | safe / 0.297 | – |
| 21 | `http://lx016-yny-g2u5-qkkzc-24-09-2026-hh.pages.dev/` | OpenPhish | POPUP ONLY | **malicious** | model | malicious / 0.994 | Top-level domain .dev is frequently used for malicious sites · Random-looking host name |
| 22 | `http://xenqaro-mpt-vulzemi-p9x4me61.pages.dev/` | OpenPhish | POPUP ONLY | **malicious** | model | malicious / 0.994 | Top-level domain .dev is frequently used for malicious sites · Random-looking host name |

Threshold is **0.80**.
* **Safe sites:** 8/8 safe. The trusted list decides them, and the model alone would also say safe
  (P ≤ 0.306).
* **Documentation-IP URLs:** 3/3 malicious.
* **Look-alikes:** 3/3 malicious.
* **OpenPhish sample:** 6/8 caught. This matches the 79.2% OpenPhish recall in Step 2.

The exact "reasons" shown by the popup for rows 9–18 and 21–22 are stored per URL in
`demo_live_results.json`.

## 2. Presentation-day checklist

- [ ] **Wake the API about 2 minutes before you start.** Open https://malicious-url-api.onrender.com/health
  in a tab. The free Render instance sleeps after ~15 minutes without traffic, and the first request
  wakes it (cold start measured below). Wait until it shows `"status": "ok"`.
- [ ] **Cold start:** measured **34.1 s** for the first `/health` after 19 minutes idle (2026-11-25);
  after that ~100–150 ms. So open `/health` **at least 1–2 minutes before** you start, and keep the
  API busy (any request) if there is a long gap before your turn: it sleeps again after ~15 minutes
  without traffic.
- [ ] **Protection ON:** the URL Guard icon is pinned, and the popup shows protection enabled. Run
  **Options → Test connection** once; it should report the Soft Voting model.
- [ ] **Tabs prepared** (only the *SAFE TO OPEN IN A TAB* rows):
  - Google search (row 1), Wikipedia (row 5), MITAOE (row 3);
  - one documentation-IP URL (row 9), which shows the warning page;
  - `https://malicious-url-api.onrender.com/docs`.
- [ ] **POPUP ONLY URLs** (rows 12–22) copied into a text file, ready to paste into the popup.
- [ ] **Laptop fallback** if Render or the venue Wi-Fi fails:
  1. In the project folder, run:
     ```powershell
     .\.venv\Scripts\python.exe -m uvicorn api.main:app --port 8000
     ```
  2. In URL Guard **Settings**, click the **Local (http://localhost:8000)** preset → **Save** →
     **Test connection**.
  3. Swagger is then at http://127.0.0.1:8000/docs.
  4. Afterwards, click **Use default** to return to Render.

## 3. Two-minute demo flow

| time | action | what to say |
|---|---|---|
| 0:00 | Open the Google search tab (row 1) | "Every page I open is checked. Google is on our curated trusted list, but even the model alone gives it only 0.07." |
| 0:20 | Open MITAOE (row 3) and onlinesbi.sbi (row 4) | "Indian education and banking sites: safe." |
| 0:40 | Open the documentation-IP URL (row 9) in a tab | "This is an IP address with 'secure/login/verify-account'. URL Guard blocks it before the page loads. P(malicious) is 0.99, and the reasons appear on the warning page." |
| 1:05 | In the popup, paste the look-alike `paypal.com.secure-account-verify.xyz/signin` (row 12) | "PayPal's name is only in the *subdomain*. The real domain is secure-account-verify.xyz, so the trusted list doesn't apply. The popup shows the reasons: a frequently abused TLD (.xyz), login words, and a random-looking host (P = 0.989)." |
| 1:25 | In the popup, paste a live OpenPhish URL (row 16, vercel.app) | "This one was a live phishing page in November 2026, on free hosting. It's caught even though free hosting is never on the trusted list." |
| 1:45 | Show `/docs` → `POST /predict` → **Try it out** | "This is the API the extension calls. It's public, read-only, and stores no URLs." |

## 4. If a teacher's URL is misclassified (honest one-line answers)

| situation | one-line answer | limit it shows |
|---|---|---|
| A legitimate site is flagged | "The model only sees the URL text; this one has the shape of a phishing URL (login words, long random IDs, a rare TLD). Popular domains are covered by our trusted list, but this one isn't on it." | URL-only features; trusted list coverage |
| A phishing URL comes back "safe" (like rows 19–20) | "Brand-new phishing on a plain-looking domain looks like any small website from its URL alone. On never-seen domains our recall is only 22%." | no page content or domain-age data (by design: fast and private) |
| "Why not catch more phishing?" | "We set the threshold so that at most 1% of normal pages give a false alarm. At 0.5 we'd catch more, but warn on 7–14% of normal pages." | precision/recall trade-off (threshold 0.80) |
| "Why are your scores lower than in papers?" | "Papers usually split randomly, so the same websites appear in training and test. We test on websites the model has never seen, which is what a real user meets." (see `docs/02`, split comparison) | evaluation realism |
| First request is slow | "The free server sleeps when idle; the first request wakes it, and after that answers take ~100 ms." | free hosting tier |
| A Google Form / Drive link is flagged | "Anyone can create those, so we never trust them blindly; the model decides." | deliberate safety design |

## 5. Showing Swagger (`/docs`) live

1. Open https://malicious-url-api.onrender.com/docs.
2. Expand **POST /predict** → **Try it out** → body `{"url": "http://198.51.100.7/paypal/login/verify"}`
   → **Execute**. Show `verdict`, `probability`, `decided_by` and `reasons`.
3. Run it again with `model_only` = `true` to show the trusted list is skipped (same probability).
4. Expand **GET /model-info** → **Execute**. Show the model name, the threshold of 0.8, the 43
   features and the test metrics.
5. Optionally, **POST /predict/batch** with two URLs, to show the 100-URL batch endpoint.
