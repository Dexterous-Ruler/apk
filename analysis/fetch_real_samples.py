"""Fetch real Android banking-trojan samples from MalwareBazaar and analyze
them WITHOUT ever writing the decrypted malware to disk.

Flow per sample:
  1. download the password-protected zip (encrypted on the wire and on disk —
     Windows Defender does not flag an AES-encrypted archive);
  2. decrypt IN MEMORY with pyzipper (MalwareBazaar password: "infected");
  3. run the full pipeline on the APK bytes via pipeline.analyze(data=...);
  4. enrich with live VirusTotal + MalwareBazaar reputation (hash only).

The decrypted APK is never persisted and never executed — static analysis
only. Only the encrypted zip and a metadata JSON (no malware bytes) are kept.

Usage:
  python analysis/fetch_real_samples.py            # default families, 4 samples
  python analysis/fetch_real_samples.py --tag Hook --limit 3
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pipeline          # noqa: E402
import genai_report      # noqa: E402
import threat_intel      # noqa: E402
import risk              # noqa: E402

MB_API = "https://mb-api.abuse.ch/api/v1/"
ENC_DIR = ROOT / "data" / "samples" / "real_encrypted"
OUT_JSON = ROOT / "outputs" / "real_sample_results.json"
ZIP_PWD = b"infected"
# Android banking-trojan families to look for, in priority order.
FAMILIES = ["Hook", "Octo", "Coper", "Cerberus", "Anubis", "Hydra",
            "TeaBot", "Ermac", "Vultur", "SpyNote", "Hydra", "FluBit"]


def _load_env() -> None:
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _mb_post(fields: dict, key: str, retries: int = 4) -> bytes:
    data = urllib.parse.urlencode(fields).encode()
    last = b""
    for attempt in range(retries):
        req = urllib.request.Request(MB_API, data=data,
                                     headers={"Auth-Key": key})
        try:
            with urllib.request.urlopen(req, timeout=40) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = e.read()
            if e.code in (502, 503, 504):
                print(f"  MalwareBazaar {e.code}, retry in 8s "
                      f"({attempt + 1}/{retries})...")
                time.sleep(8)
                continue
            raise
        except Exception as e:
            print(f"  network error: {e}; retry in 6s")
            time.sleep(6)
    return last


def find_hashes(key: str, families: list[str], want: int) -> list[dict]:
    found: list[dict] = []
    seen = set()
    for fam in families:
        if len(found) >= want:
            break
        raw = _mb_post({"query": "get_taginfo", "tag": fam, "limit": 20}, key)
        try:
            resp = json.loads(raw)
        except Exception:
            print(f"  [{fam}] non-JSON response (API busy), skipping")
            continue
        if resp.get("query_status") != "ok":
            print(f"  [{fam}] {resp.get('query_status')}")
            continue
        for s in resp.get("data", []):
            ft = (s.get("file_type") or "").lower()
            tags = [t.lower() for t in (s.get("tags") or [])]
            if ft != "apk" and "apk" not in tags and "android" not in tags:
                continue
            h = s["sha256_hash"]
            if h in seen:
                continue
            seen.add(h)
            found.append({"sha256": h, "family": fam,
                          "signature": s.get("signature"),
                          "file_name": s.get("file_name"),
                          "tags": s.get("tags")})
            if len(found) >= want:
                break
        print(f"  [{fam}] collected {len(found)}/{want}")
    return found


def download_zip(key: str, sha256: str) -> bytes | None:
    raw = _mb_post({"query": "get_file", "sha256_hash": sha256}, key)
    if raw[:2] == b"PK":          # zip magic
        return raw
    try:
        msg = json.loads(raw).get("query_status")
    except Exception:
        msg = raw[:120]
    print(f"  download failed for {sha256[:16]}…: {msg}")
    return None


def decrypt_in_memory(zip_bytes: bytes) -> tuple[str, bytes] | None:
    import pyzipper
    try:
        with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.setpassword(ZIP_PWD)
            for name in zf.namelist():
                data = zf.read(name)
                if data[:2] == b"PK" or name.lower().endswith(".apk"):
                    return name, data
            # fall back to first entry
            name = zf.namelist()[0]
            return name, zf.read(name)
    except Exception as e:
        print(f"  decrypt failed: {type(e).__name__}: {e}")
        return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", action="append", help="family tag(s) to search")
    ap.add_argument("--limit", type=int, default=4)
    ap.add_argument("--llm", default="auto", choices=["auto", "claude", "template"])
    args = ap.parse_args()

    _load_env()
    key = os.environ.get("MWB_API_KEY")
    if not key:
        print("MWB_API_KEY not set (.env). Aborting.")
        return
    ENC_DIR.mkdir(parents=True, exist_ok=True)
    families = args.tag or FAMILIES

    print(f"Searching MalwareBazaar for {args.limit} Android samples "
          f"({', '.join(families[:6])}…)")
    targets = find_hashes(key, families, args.limit)
    if not targets:
        print("\nNo sample hashes retrieved — MalwareBazaar API may be down "
              "(502). Re-run this script later; nothing else needed.")
        return

    results = []
    for i, t in enumerate(targets, 1):
        sha = t["sha256"]
        print(f"\n[{i}/{len(targets)}] {t['family']} · {sha[:20]}… "
              f"({t.get('signature') or '?'})")
        zip_bytes = download_zip(key, sha)
        if not zip_bytes:
            continue
        (ENC_DIR / f"{sha}.zip").write_bytes(zip_bytes)  # encrypted, safe
        dec = decrypt_in_memory(zip_bytes)
        if not dec:
            continue
        _, apk_bytes = dec
        try:
            r = pipeline.analyze(data=apk_bytes, filename=f"{sha[:16]}.apk")
            r["threat_intel"] = threat_intel.enrich(sha)
            r["risk"] = risk.apply_threat_intel(r["risk"], r["threat_intel"])
            r["genai"] = genai_report.generate_report(r, prefer=args.llm)
        except Exception as e:
            # one transient failure (network/LLM) must not abort the batch
            print(f"  analysis error: {type(e).__name__}: {e}; skipping")
            continue
        rk, m, imp = r["risk"], r["static"]["manifest"], r["impersonation"]
        vt = r["threat_intel"]["virustotal"]
        esc = rk.get("escalated_by_threat_intel")
        print(f"  -> RISK {rk['score']}/100 {rk['severity']} | "
              f"pkg {m['package']} | impersonates {imp.get('claimed_bank') or '—'} "
              f"| ML {r['ml'].get('probability')} | VT "
              f"{vt.get('malicious','?')}/{vt.get('total_engines','?')} | "
              f"GenAI {r['genai']['report']['assessment']}"
              + (f" | TI-escalated {esc['from']}->{esc['to']}" if esc else ""))
        results.append({
            "sha256": sha, "family": t["family"],
            "mb_signature": t.get("signature"),
            "package": m["package"], "app_name": m["app_name"],
            "risk": rk["score"], "severity": rk["severity"],
            "escalated_by_threat_intel": rk.get("escalated_by_threat_intel"),
            "claimed_bank": imp.get("claimed_bank"),
            "ml_probability": r["ml"].get("probability"),
            "vt_malicious": vt.get("malicious"),
            "vt_total": vt.get("total_engines"),
            "genai_assessment": r["genai"]["report"]["assessment"],
            "red_flag_permissions": [x["short"] for x in r["static"]["permissions"]["red_flags"]],
            "suspicious_api_count": len(r["static"]["dex"]["suspicious_apis"]),
        })

    OUT_JSON.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nDone. {len(results)} real samples analyzed in-memory.")
    print(f"Metadata (no malware bytes): {OUT_JSON}")
    print(f"Encrypted zips kept (Defender-safe): {ENC_DIR}")


if __name__ == "__main__":
    main()
