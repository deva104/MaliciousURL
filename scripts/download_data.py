"""Download the raw datasets for the Malicious URL Detection project.

Usage (from the project root):
    python scripts/download_data.py                # download what is missing / corrupt
    python scripts/download_data.py --force        # re-download everything
    python scripts/download_data.py --verify-only  # offline: just verify checksums

What it does
------------
1. Kaggle "Malicious URLs Dataset" (sid321axn) via a public GitHub LFS mirror.
2. UCI #967 "PhiUSIIL Phishing URL Dataset" via a public GitHub mirror.
3. A snapshot of the OpenPhish public feed (live phishing URLs) -> data/external/.
   This is an *unseen* test set for Step 2 and must NEVER be used for training.

Files 1 and 2 have a known size + SHA-256; if the file already exists and the
checksum matches, it is skipped. The OpenPhish feed changes every hour, so it
has no fixed checksum: we save one dated snapshot per day and record the
download time (UTC) and its SHA-256 in data/external/openphish_manifest.json.

Only the Python standard library is used, so this runs before the venv exists.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
EXTERNAL = ROOT / "data" / "external"

DATASETS = [
    {
        "name": "Kaggle Malicious URLs (sid321axn)",
        "url": "https://media.githubusercontent.com/media/SahinMuhammetAbdullah/"
               "urldataset/HEAD/malicious_phish.csv",
        "path": RAW / "malicious_phish.csv",
        "size": 45_647_820,
        "sha256": "a500a136d4552a34e076a650ab1ea09897c24ab51053e800b2d1c3c204a1317d",
    },
    {
        "name": "PhiUSIIL Phishing URL (UCI #967)",
        "url": "https://raw.githubusercontent.com/4hc4/Advanced-Spam-Malware-URL-Detection/"
               "HEAD/data/PhiUSIIL_Phishing_URL_Dataset.csv",
        # The repo stores the CSV in Git LFS: the raw URL above only returns a
        # 133-byte LFS *pointer* file. The real bytes are served from here:
        "fallback_url": "https://media.githubusercontent.com/media/4hc4/"
                        "Advanced-Spam-Malware-URL-Detection/HEAD/data/"
                        "PhiUSIIL_Phishing_URL_Dataset.csv",
        "path": RAW / "PhiUSIIL_Phishing_URL_Dataset.csv",
        "size": 56_854_345,
        "sha256": "a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6",
    },
]

OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
USER_AGENT = "url-dataset-downloader/1.0 (course project)"


def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def download(url: str, dest: Path, retries: int = 5) -> None:
    """Stream `url` to `dest` via a .part file (a crash never leaves a half file).

    On a retry the download RESUMES from the bytes already received (HTTP Range),
    which matters on slow connections.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    if tmp.exists():
        tmp.unlink()
    for attempt in range(1, retries + 1):
        try:
            have = tmp.stat().st_size if tmp.exists() else 0
            headers = {"User-Agent": USER_AGENT}
            if have:
                headers["Range"] = f"bytes={have}-"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as r:
                resumed = have and r.status == 206
                mode = "ab" if resumed else "wb"
                done = have if resumed else 0
                total = int(r.headers.get("Content-Length") or 0) + done
                if have:
                    print(f"    resuming at {have/1e6:.1f} MB" if resumed else "    server ignored Range; restarting")
                with open(tmp, mode) as f:
                    while True:
                        block = r.read(1 << 20)
                        if not block:
                            break
                        f.write(block)
                        done += len(block)
                        if total:
                            print(f"\r    {done/1e6:7.1f} / {total/1e6:.1f} MB", end="", flush=True)
            print()
            tmp.replace(dest)
            return
        except Exception as exc:  # network hiccup -> retry
            print(f"\n    attempt {attempt} failed: {exc}")
            if attempt == retries:
                raise
            time.sleep(3 * attempt)


def is_lfs_pointer(path: Path) -> bool:
    """A Git LFS pointer is a tiny text file starting with this line."""
    if path.stat().st_size > 1024:
        return False
    return path.read_bytes().startswith(b"version https://git-lfs.github.com/spec/")


def ensure_dataset(ds: dict, force: bool, verify_only: bool = False) -> dict:
    path: Path = ds["path"]
    status = "verified" if verify_only else "skipped (checksum OK)"
    if verify_only:
        if not path.exists():
            raise FileNotFoundError(f"{path} missing; run without --verify-only")
    elif force or not path.exists() or sha256_of(path) != ds["sha256"]:
        print(f"-> downloading {ds['name']}")
        download(ds["url"], path)
        status = "downloaded"
        if is_lfs_pointer(path) and ds.get("fallback_url"):
            print("   got a Git LFS pointer instead of data -> using the LFS media URL")
            download(ds["fallback_url"], path)
            status = "downloaded (LFS fallback)"
    size = path.stat().st_size
    digest = sha256_of(path)
    ok = size == ds["size"] and digest == ds["sha256"]
    return {
        "file": str(path.relative_to(ROOT)),
        "status": status,
        "bytes": size,
        "expected_bytes": ds["size"],
        "sha256_ok": digest == ds["sha256"],
        "ok": ok,
        "sha256": digest,
    }


def ensure_openphish(force: bool, verify_only: bool = False) -> dict:
    now = datetime.now(timezone.utc)
    local_date = datetime.now().strftime("%Y-%m-%d")
    path = EXTERNAL / f"openphish_feed_{local_date}.txt"
    manifest_path = EXTERNAL / "openphish_manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}

    status = "skipped (today's snapshot exists)"
    if verify_only:
        # use the most recent snapshot that is already on disk
        snaps = sorted(EXTERNAL.glob("openphish_feed_*.txt"))
        if not snaps:
            raise FileNotFoundError("no OpenPhish snapshot on disk; run without --verify-only")
        path, status = snaps[-1], "verified (latest snapshot)"
    elif force or not path.exists():
        print("-> downloading OpenPhish public feed snapshot")
        download(OPENPHISH_URL, path)
        status = "downloaded"
        manifest[path.name] = {
            "source_url": OPENPHISH_URL,
            "downloaded_at_utc": now.isoformat(timespec="seconds"),
            "sha256": sha256_of(path),
            "bytes": path.stat().st_size,
            "num_urls": sum(1 for line in path.read_text(encoding="utf-8").splitlines()
                            if line.strip()),
            "note": "Unseen fresh phishing test set for Step 2. NEVER train on it.",
        }
        manifest_path.write_text(json.dumps(manifest, indent=2))
    info = manifest.get(path.name, {})
    return {
        "file": str(path.relative_to(ROOT)),
        "status": status,
        "bytes": path.stat().st_size,
        "expected_bytes": None,
        "sha256_ok": None,
        "ok": path.stat().st_size > 0,
        "sha256": sha256_of(path),
        "num_urls": info.get("num_urls"),
        "downloaded_at_utc": info.get("downloaded_at_utc"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--force", action="store_true", help="re-download even if checksums match")
    ap.add_argument("--verify-only", action="store_true",
                    help="no network: only verify the files already on disk")
    args = ap.parse_args()

    rows = [ensure_dataset(ds, args.force, args.verify_only) for ds in DATASETS]
    rows.append(ensure_openphish(args.force, args.verify_only))

    print("\nVerification table")
    print(f"{'file':<45} {'status':<34} {'bytes':>12} {'expected':>12} {'sha256':>7} {'ok':>4}")
    print("-" * 120)
    for r in rows:
        exp = f"{r['expected_bytes']:,}" if r["expected_bytes"] else "n/a"
        sha = {True: "match", False: "WRONG", None: "n/a"}[r["sha256_ok"]]
        print(f"{r['file']:<45} {r['status']:<34} {r['bytes']:>12,} {exp:>12} {sha:>7} "
              f"{'yes' if r['ok'] else 'NO':>4}")
    op = rows[-1]
    print(f"\nOpenPhish snapshot: {op['num_urls']} URLs, downloaded at {op['downloaded_at_utc']} UTC")
    print(f"OpenPhish sha256  : {op['sha256']}")

    if not all(r["ok"] for r in rows):
        print("\nERROR: at least one file failed verification.", file=sys.stderr)
        return 1
    print("\nAll files verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
