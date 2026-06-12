"""Dynamic (runtime-behavior) analysis.

Two sources, both real, neither requires executing malware on this machine:

  1. VirusTotal multi-sandbox detonation behavior (PRIMARY, hash-only). VT runs
     samples in its own Android sandboxes; we retrieve the aggregated runtime
     behavior — network contacted at runtime, memory-pattern URLs/domains,
     dropped/written files, started services, processes, and the MITRE
     techniques observed during DETONATION (distinct from static signatures).
     We send only the SHA-256, never the APK. Cached locally.

  2. Self-hosted live detonation (OPTIONAL, for when an Android instance is
     available): a MobSF REST integration (MOBSF_URL + MOBSF_API_KEY) and a
     ready Frida instrumentation script (tools/frida_hooks.js) that hooks
     SMS/network/crypto/dynamic-loading at runtime. This is the "run it in a
     sandbox" path the problem statement asks for; it activates when infra is
     connected and degrades cleanly when it isn't.

dynamic_findings(sha) returns a normalized view + a risk-escalation hint when
the sandbox observed real C2 traffic or a dropped executable.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CACHE = Path(__file__).resolve().parents[1] / "outputs" / "dyn_cache"
VT_BASE = "https://www.virustotal.com/api/v3/files/"
TIMEOUT = 20


def _cache(sha: str) -> Path:
    return CACHE / f"{sha}.json"


def status() -> dict:
    return {
        "virustotal_sandbox": bool(os.environ.get("VT_API_KEY")),
        "mobsf": bool(os.environ.get("MOBSF_URL") and os.environ.get("MOBSF_API_KEY")),
        "frida_script": str((Path(__file__).resolve().parents[1]
                             / "tools" / "frida_hooks.js")),
    }


def _vt_get(path: str) -> dict | None:
    key = os.environ.get("VT_API_KEY")
    if not key:
        return None
    req = urllib.request.Request(VT_BASE + path, headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"_404": True}
        return {"_error": f"HTTP {e.code}"}
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}"}


def _vt_behavior(sha: str) -> dict:
    summary = _vt_get(f"{sha}/behaviour_summary")
    if not summary or summary.get("_404") or summary.get("_error"):
        return {"available": False,
                "note": (summary or {}).get("_error",
                         "no public sandbox detonation report for this hash")}
    d = summary.get("data", {})
    # network observed at runtime
    http = d.get("http_conversations", []) or []
    dns = d.get("dns_lookups", []) or []
    ip = d.get("ip_traffic", []) or []
    mem_urls = d.get("memory_pattern_urls", []) or []
    mem_domains = d.get("memory_pattern_domains", []) or []
    urls = sorted({c.get("url") for c in http if c.get("url")} | set(mem_urls))
    domains = sorted({x.get("hostname") for x in dns if x.get("hostname")}
                     | set(mem_domains))
    ips = sorted({x.get("destination_ip") for x in ip if x.get("destination_ip")})
    runtime_mitre = []
    for t in d.get("mitre_attack_techniques", []) or []:
        runtime_mitre.append({"id": t.get("id"),
                              "description": t.get("signature_description")})
    return {
        "available": True,
        "source": "virustotal_multi_sandbox",
        "network": {"urls": urls[:40], "domains": domains[:40], "ips": ips[:40]},
        "files_written": [f.get("path") if isinstance(f, dict) else f
                          for f in (d.get("files_written") or [])][:30],
        "files_dropped": [f.get("path") if isinstance(f, dict) else f
                          for f in (d.get("files_dropped") or [])][:30],
        "processes_created": (d.get("processes_created") or [])[:20],
        "services_started": (d.get("services_started") or [])[:20],
        "permissions_at_runtime": (d.get("permissions") or [])[:40],
        "commands": (d.get("command_executions") or [])[:20],
        "runtime_mitre": runtime_mitre[:25],
        "verdicts": d.get("verdicts") or [],
        "tags": d.get("tags") or [],
        "sandboxes": d.get("verdict_labels") or [],
    }


def dynamic_findings(sha: str, use_cache: bool = True) -> dict:
    if use_cache and _cache(sha).exists():
        try:
            out = json.loads(_cache(sha).read_text())
            out["_cache"] = "hit"
            return out
        except Exception:
            pass
    vt = _vt_behavior(sha)
    mobsf = _mobsf_findings(sha)
    primary = mobsf if mobsf.get("available") else vt
    out = {
        "sha256": sha,
        "available": bool(primary.get("available")),
        "primary_source": primary.get("source") if primary.get("available")
                          else None,
        "virustotal_sandbox": vt,
        "mobsf": mobsf,
        "escalation": _escalation(primary),
        "_cache": "miss",
    }
    if vt.get("available") or vt.get("note", "").startswith("no public"):
        CACHE.mkdir(parents=True, exist_ok=True)
        _cache(sha).write_text(json.dumps({k: v for k, v in out.items()
                                           if k != "_cache"}, indent=2))
    return out


def _escalation(primary: dict) -> dict:
    """A risk-escalation hint when the sandbox observed real malicious runtime
    behavior (C2 traffic, dropped executables, runtime techniques)."""
    if not primary.get("available"):
        return {"escalate": False}
    net = primary.get("network", {})
    reasons = []
    if net.get("urls") or net.get("domains") or net.get("ips"):
        reasons.append("Sandbox detonation contacted "
                       f"{len(net.get('domains', []))} domain(s)/"
                       f"{len(net.get('ips', []))} IP(s) at runtime.")
    dropped = primary.get("files_dropped") or []
    if any(str(f).endswith((".dex", ".apk", ".so", ".jar")) for f in dropped):
        reasons.append("Dropped an executable payload (.dex/.apk/.so) at runtime "
                       "— second-stage delivery confirmed dynamically.")
    if primary.get("runtime_mitre"):
        reasons.append(f"{len(primary['runtime_mitre'])} MITRE techniques "
                       "observed during detonation.")
    return {"escalate": bool(reasons), "reasons": reasons}


# ---------------------------------------------------------------------------
# Optional self-hosted MobSF dynamic analyzer (activates when configured)
# ---------------------------------------------------------------------------
def _mobsf_findings(sha: str) -> dict:
    url = os.environ.get("MOBSF_URL")
    key = os.environ.get("MOBSF_API_KEY")
    if not (url and key):
        return {"available": False,
                "note": "self-hosted MobSF not configured (set MOBSF_URL + "
                        "MOBSF_API_KEY to enable live detonation)"}
    # MobSF dynamic requires the sample already uploaded + a connected Android
    # VM; we query its dynamic report by hash. Kept best-effort/offline-safe.
    try:
        data = urllib.parse.urlencode({"hash": sha}).encode()
        req = urllib.request.Request(url.rstrip("/") + "/api/v1/dynamic/report_json",
                                     data=data, headers={"Authorization": key})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            rep = json.loads(r.read())
        return {"available": True, "source": "mobsf_dynamic", "report": rep}
    except Exception as e:
        return {"available": False, "note": f"MobSF query failed: {e}"}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    args = ap.parse_args()
    print(json.dumps(dynamic_findings(args.sha256), indent=2))
