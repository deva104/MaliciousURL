# URL Guard (Chrome extension, Step 4)

Manifest V3 extension that checks every page you open with our malicious-URL API and blocks dangerous
sites. Plain JavaScript, no build step, no dependencies.

Full guide (install, permissions, limitations, manual test checklist, demo script):
[`docs/04_extension_user_guide.md`](../docs/04_extension_user_guide.md)

Quick start (from the project root):

```powershell
node extension/dev/mock_api.mjs
```

```powershell
node --test "extension/tests/*.test.mjs"
```

```powershell
node extension/dev/check_extension.mjs
```

Then `chrome://extensions` > Developer mode > **Load unpacked** > choose this `extension/` folder.

Default API: `https://malicious-url-api.onrender.com` (`RENDER_API_BASE` in [`config.js`](config.js);
another URL can be saved on the Settings page). Live smoke test, max 10 requests:

```powershell
node extension/dev/live_check.mjs
```
