// Static checks for the extension (no Chrome needed):
//  - manifest.json is valid JSON with the expected MV3 fields and permissions
//  - every file referenced by the manifest, the HTML pages and JS imports exists
//  - icons are real PNGs of the declared size
//  - MV3 CSP rules: no inline <script>, no on*= handlers, no eval / new Function
//  - no remote code: no http(s) URLs in shipped code except config.js (API base URLs)
//  - no innerHTML-style APIs (our own XSS rule: URLs are shown with textContent)
// Run:  node extension/dev/check_extension.mjs     (exit code 1 on any error)

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve, extname, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const NOT_SHIPPED = new Set(["dev", "tests"]); // tools, not loaded by Chrome
const EXPECTED_PERMISSIONS = ["webNavigation", "tabs", "storage", "declarativeNetRequest"];
const URL_ALLOWED_IN = new Set(["config.js"]);

const errors = [];
const warnings = [];
let checks = 0;
const rel = (p) => relative(ROOT, p).split(sep).join("/");
const fail = (msg) => errors.push(msg);
const warn = (msg) => warnings.push(msg);
const ok = () => (checks += 1);

function mustExist(path, from) {
  const full = resolve(ROOT, path.replace(/^\//, ""));
  if (!full.startsWith(ROOT)) return fail(from + ": path escapes the extension folder: " + path);
  if (!existsSync(full) || !statSync(full).isFile()) return fail(from + ": missing file " + path);
  ok();
  return full;
}

function listShippedFiles(dir = ROOT) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (dir === ROOT && NOT_SHIPPED.has(name)) continue;
    if (name.startsWith("_")) fail(rel(full) + ": names starting with '_' are reserved by Chrome");
    if (statSync(full).isDirectory()) out.push(...listShippedFiles(full));
    else out.push(full);
  }
  return out;
}

function pngSize(file) {
  const buf = readFileSync(file);
  const sig = "89504e470d0a1a0a";
  if (buf.subarray(0, 8).toString("hex") !== sig || buf.subarray(12, 16).toString("ascii") !== "IHDR") return null;
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}

// ---------------- manifest ----------------
let manifest;
try {
  manifest = JSON.parse(readFileSync(join(ROOT, "manifest.json"), "utf8"));
  ok();
} catch (err) {
  fail("manifest.json is not valid JSON: " + err.message);
}

if (manifest) {
  if (manifest.manifest_version !== 3) fail("manifest_version must be 3");
  else ok();
  for (const key of ["name", "version", "description"]) {
    if (typeof manifest[key] !== "string" || !manifest[key]) fail("manifest." + key + " is missing");
    else ok();
  }
  if (!/^\d+(\.\d+){0,3}$/.test(manifest.version || "")) fail("manifest.version must look like 1.0.0");

  const bg = manifest.background || {};
  if (!bg.service_worker) fail("background.service_worker is missing");
  else mustExist(bg.service_worker, "background.service_worker");
  if (bg.type !== "module") fail('background.type must be "module"');
  else ok();

  if (!manifest.action?.default_popup) fail("action.default_popup is missing");
  else mustExist(manifest.action.default_popup, "action.default_popup");
  const optionsPage = manifest.options_page || manifest.options_ui?.page;
  if (!optionsPage) fail("options page is missing");
  else mustExist(optionsPage, "options_page");

  for (const [label, icons] of [
    ["icons", manifest.icons],
    ["action.default_icon", manifest.action?.default_icon],
  ]) {
    if (!icons) {
      fail(label + " is missing");
      continue;
    }
    for (const [size, path] of Object.entries(icons)) {
      const full = mustExist(path, label);
      if (!full) continue;
      const dims = pngSize(full);
      if (!dims) fail(path + " is not a PNG");
      else if (dims.width !== Number(size) || dims.height !== Number(size)) {
        fail(path + " is " + dims.width + "x" + dims.height + ", expected " + size + "x" + size);
      } else ok();
    }
  }

  for (const entry of manifest.web_accessible_resources || []) {
    for (const res of entry.resources || []) mustExist(res, "web_accessible_resources");
    if (!Array.isArray(entry.matches) || entry.matches.length === 0) fail("web_accessible_resources needs matches");
  }

  const perms = manifest.permissions || [];
  for (const p of perms) {
    if (!EXPECTED_PERMISSIONS.includes(p)) fail("unexpected permission: " + p);
    else ok();
  }
  for (const p of EXPECTED_PERMISSIONS) if (!perms.includes(p)) fail("missing permission: " + p);

  const hosts = manifest.host_permissions || [];
  if (hosts.includes("<all_urls>")) warn("host_permissions has <all_urls> (needed for DNR redirect rules; see the user guide)");
  for (const h of hosts) {
    if (h !== "<all_urls>" && !/^(https?|\*):\/\/[^/]+\/.*$/.test(h)) fail("odd host permission: " + h);
    else ok();
  }

  const csp = JSON.stringify(manifest.content_security_policy || "");
  if (/unsafe-eval|unsafe-inline|https?:/.test(csp)) fail("content_security_policy must not allow eval, inline or remote code");
  else ok();
}

// ---------------- HTML, JS, CSS ----------------
const files = listShippedFiles();

for (const file of files.filter((f) => extname(f) === ".html")) {
  const name = rel(file);
  const html = readFileSync(file, "utf8");
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  let scriptCount = 0;
  while ((m = scriptRe.exec(html))) {
    scriptCount += 1;
    const attrs = m[1];
    const src = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(attrs)?.[1];
    if (!src) fail(name + ": inline <script> is not allowed in MV3");
    else if (/^(https?:)?\/\//i.test(src)) fail(name + ": remote script " + src);
    else mustExist(join(dirname(rel(file)), src), name);
    if (m[2].trim()) fail(name + ": <script> must be empty (no inline code)");
  }
  if (scriptCount === 0) warn(name + ": has no script");

  const handler = /<[^>]*\son[a-z]+\s*=/i.exec(html);
  if (handler) fail(name + ": inline event handler near: " + handler[0].slice(0, 60));
  else ok();
  if (/javascript:/i.test(html)) fail(name + ": javascript: URL");
  else ok();

  const refRe = /<(?:link|img|iframe|source|embed)\b[^>]*\b(?:href|src)\s*=\s*["']([^"']+)["']/gi;
  while ((m = refRe.exec(html))) {
    if (/^(https?:)?\/\//i.test(m[1])) fail(name + ": remote resource " + m[1]);
    else mustExist(join(dirname(rel(file)), m[1].split(/[?#]/)[0]), name);
  }
}

for (const file of files.filter((f) => [".js", ".mjs"].includes(extname(f)))) {
  const name = rel(file);
  const code = readFileSync(file, "utf8");
  const forbidden = [
    [/\beval\s*\(/, "eval()"],
    [/\bnew\s+Function\s*\(/, "new Function()"],
    [/\bset(?:Timeout|Interval)\s*\(\s*["'`]/, "setTimeout/setInterval with a string"],
    [/\bimportScripts\s*\(/, "importScripts()"],
    [/\bdocument\.write\s*\(/, "document.write()"],
    [/\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(/, "innerHTML-style HTML injection"],
  ];
  for (const [re, what] of forbidden) {
    if (re.test(code)) fail(name + ": uses " + what);
    else ok();
  }

  const urls = code.match(/https?:\/\/[^\s"'`)]+/g) || [];
  if (urls.length && !URL_ALLOWED_IN.has(name)) fail(name + ": contains URLs (only config.js may): " + urls.join(", "));
  else ok();

  const importRe = /(?:^|[\s;])(?:import|export)\s+(?:[^"'`;]*?\s+from\s+)?["']([^"']+)["']/g;
  let m;
  while ((m = importRe.exec(code))) {
    const spec = m[1];
    if (!spec.startsWith("./") && !spec.startsWith("../")) fail(name + ": non-relative import " + spec);
    else mustExist(join(dirname(name), spec), name);
  }
  if (/\bimport\s*\(\s*["'`]?(https?:)?\/\//.test(code)) fail(name + ": remote dynamic import");
}

for (const file of files.filter((f) => extname(f) === ".css")) {
  const css = readFileSync(file, "utf8");
  if (/url\(\s*["']?(https?:)?\/\//i.test(css) || /@import/i.test(css)) fail(rel(file) + ": remote CSS resource");
  else ok();
}

// ---------------- report ----------------
console.log("URL Guard extension check: " + files.length + " shipped files, " + checks + " checks passed");
for (const w of warnings) console.log("WARN  " + w);
for (const e of errors) console.log("ERROR " + e);
if (errors.length) {
  console.log("FAILED with " + errors.length + " error(s)");
  process.exit(1);
}
console.log("OK: no errors");
