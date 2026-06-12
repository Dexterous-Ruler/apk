"""Threat-intel enrichment: VirusTotal + MalwareBazaar hash lookups.

Both are OFF by default and degrade gracefully:
  * VirusTotal needs an API key in VT_API_KEY (free tier: 4 req/min). Without
    it, the layer reports status "no_api_key" and the pipeline continues.
  * MalwareBazaar needs an Auth-Key in MWB_API_KEY (free, from auth.abuse.ch).
  * Every lookup is cached to apk/outputs/ti_cache/<sha256>.json so repeated
    scans (and the live demo on flaky venue wifi) never re-hit the network.

We only ever send the file's SHA-256 hash — never the APK bytes — so no sample
ever leaves the machine. This is a reputation lookup, not a sample submission.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CACHE_DIR = Path(__file__).resolve().parents[1] / "outputs" / "ti_cache"
VT_URL = "https://www.virustotal.com/api/v3/files/"
MWB_URL = "https://mb-api.abuse.ch/api/v1/"
TIMEOUT = 15


def _cache_path(sha256: str) -> Path:
    return CACHE_DIR / f"{sha256}.json"


def _read_cache(sha256: str) -> dict | None:
    p = _cache_path(sha256)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return None
    return None


def _write_cache(sha256: str, data: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _cache_path(sha256).write_text(json.dumps(data, indent=2))


def _vt_lookup(sha256: str) -> dict:
    key = os.environ.get("VT_API_KEY")
    if not key:
        return {"status": "no_api_key",
                "note": "set VT_API_KEY for VirusTotal reputation"}
    req = urllib.request.Request(VT_URL + sha256, headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.loads(r.read())
        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        names = data["data"]["attributes"].get("popular_threat_classification", {})
        return {
            "status": "found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "suggested_label": names.get("suggested_threat_label"),
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not_found",
                    "note": "hash unknown to VirusTotal (new/targeted sample)"}
        return {"status": "error", "note": f"HTTP {e.code}"}
    except Exception as e:
        return {"status": "error", "note": f"{type(e).__name__}: {e}"}


def _mwb_lookup(sha256: str) -> dict:
    key = os.environ.get("MWB_API_KEY")
    if not key:
        return {"status": "no_api_key",
                "note": "set MWB_API_KEY (auth.abuse.ch) for MalwareBazaar"}
    data = urllib.parse.urlencode(
        {"query": "get_info", "hash": sha256}).encode()
    req = urllib.request.Request(MWB_URL, data=data,
                                 headers={"Auth-Key": key})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            resp = json.loads(r.read())
        if resp.get("query_status") == "ok" and resp.get("data"):
            d = resp["data"][0]
            return {
                "status": "found",
                "signature": d.get("signature"),
                "file_type": d.get("file_type"),
                "first_seen": d.get("first_seen"),
                "delivery_method": d.get("delivery_method"),
                "tags": d.get("tags"),
                "permalink": f"https://bazaar.abuse.ch/sample/{sha256}/",
            }
        return {"status": "not_found",
                "note": "hash not in MalwareBazaar"}
    except Exception as e:
        return {"status": "error", "note": f"{type(e).__name__}: {e}"}


def enrich(sha256: str, use_cache: bool = True) -> dict:
    if use_cache:
        cached = _read_cache(sha256)
        if cached is not None:
            cached["_cache"] = "hit"
            return cached
    result = {
        "sha256": sha256,
        "virustotal": _vt_lookup(sha256),
        "malwarebazaar": _mwb_lookup(sha256),
        "_fetched_epoch": int(time.time()),
        "_cache": "miss",
    }
    # only cache positive/definitive answers, not transient errors
    if (result["virustotal"]["status"] in ("found", "not_found")
            or result["malwarebazaar"]["status"] in ("found", "not_found")):
        to_cache = {k: v for k, v in result.items() if k != "_cache"}
        _write_cache(sha256, to_cache)
    return result


def enabled() -> dict:
    return {"virustotal": bool(os.environ.get("VT_API_KEY")),
            "malwarebazaar": bool(os.environ.get("MWB_API_KEY"))}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    args = ap.parse_args()
    print(json.dumps(enrich(args.sha256), indent=2))
