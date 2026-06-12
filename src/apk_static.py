"""Static analysis engine for suspicious APKs (Topic 1).

analyze_apk(path) -> StaticResult with:
  - file hashes / size
  - manifest evidence: package, app name, version, sdk levels, permissions
    (with red-flag annotations), component counts, intent actions
  - signing certificate(s): issuer/subject, SHA-256, validity, self-signed,
    signature scheme versions
  - dex evidence: suspicious API hits by category, embedded URLs/IPs/domains,
    shell command strings
  - APKiD packer/obfuscator fingerprint (high signal: packed = hiding)
  - app icon bytes (for the impersonation layer's perceptual hash)
  - Drebin-215 binary feature vector (for the ML model)

Parsing strategy: androguard's APK class for the zip/manifest/cert layer
(fast), our own dexparse for string/class/method-ref pools (fast), and NO
full bytecode analysis — keeps end-to-end extraction in single-digit seconds
even for large apps.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

logger.remove()  # androguard 4 logs via loguru; keep analysis output clean

from androguard.core.apk import APK  # noqa: E402

try:
    from . import dexparse
    from .drebin_map import DrebinMatcher, load_feature_names
except ImportError:  # imported as a plain module (sys.path points at src/)
    import dexparse
    from drebin_map import DrebinMatcher, load_feature_names

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# ---------------------------------------------------------------------------
# Red-flag permissions: the banking-trojan cheat sheet. category/why power the
# evidence UI and the GenAI report; risk fusion scores combinations of these.
# ---------------------------------------------------------------------------
RED_FLAG_PERMISSIONS = {
    "BIND_ACCESSIBILITY_SERVICE": ("device_control",
        "Accessibility service abuse: read the screen, auto-grant permissions, "
        "auto-fill taps — hallmark of SOVA/Anubis-class banking trojans"),
    "SYSTEM_ALERT_WINDOW": ("overlay",
        "Draw over other apps: overlay a fake login screen on top of the real "
        "banking app to capture credentials"),
    "RECEIVE_SMS": ("sms", "Intercept incoming SMS — OTP/2FA theft"),
    "READ_SMS": ("sms", "Read stored SMS — OTP/2FA and mTAN theft"),
    "SEND_SMS": ("sms", "Send SMS — premium-rate fraud, worm-like spread of the "
        "phishing link to contacts"),
    "RECEIVE_MMS": ("sms", "Intercept MMS messages"),
    "READ_PHONE_STATE": ("identity", "Read IMEI/device identity and call state — "
        "device fingerprinting for fraud infrastructure"),
    "READ_CONTACTS": ("exfiltration", "Harvest the contact list — used to spread "
        "scam links to victims' contacts"),
    "READ_CALL_LOG": ("exfiltration", "Read call history"),
    "PROCESS_OUTGOING_CALLS": ("device_control", "Monitor/redirect outgoing calls"),
    "CALL_PHONE": ("device_control", "Place calls without user action — call "
        "forwarding to attacker-controlled numbers"),
    "REQUEST_INSTALL_PACKAGES": ("persistence", "Install further APKs — dropper "
        "behavior, second-stage payload delivery"),
    "BIND_DEVICE_ADMIN": ("persistence", "Device-admin privileges — block "
        "uninstall, lock the device"),
    "RECEIVE_BOOT_COMPLETED": ("persistence", "Auto-start on boot — persistence "
        "across reboots"),
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": ("persistence",
        "Evade battery-based background kill — stay resident"),
    "QUERY_ALL_PACKAGES": ("recon", "Enumerate every installed app — detect "
        "which banking apps the victim uses to select the overlay"),
    "GET_TASKS": ("recon", "Inspect running tasks — detect when a banking app "
        "is in the foreground to time the overlay"),
    "READ_EXTERNAL_STORAGE": ("exfiltration", "Read shared storage"),
    "WRITE_EXTERNAL_STORAGE": ("exfiltration", "Write shared storage"),
    "RECORD_AUDIO": ("surveillance", "Record microphone audio"),
    "CAMERA": ("surveillance", "Access the camera"),
    "ACCESS_FINE_LOCATION": ("surveillance", "Precise GPS location tracking"),
    "DISABLE_KEYGUARD": ("device_control", "Dismiss the lock screen"),
    "WRITE_SETTINGS": ("device_control", "Modify system settings"),
}

# ---------------------------------------------------------------------------
# Suspicious API references: (dotted class suffix, method or None=any-use)
# Matched against dex method-ref / class pools. Categories align with the
# red-flag permission categories so the evidence reads as one story.
# ---------------------------------------------------------------------------
SUSPICIOUS_APIS = [
    ("android.telephony.SmsManager", "sendTextMessage", "sms",
     "Programmatically sends SMS"),
    ("android.telephony.SmsManager", "sendMultipartTextMessage", "sms",
     "Programmatically sends long SMS"),
    ("android.telephony.TelephonyManager", "getDeviceId", "identity",
     "Reads IMEI (device fingerprinting)"),
    ("android.telephony.TelephonyManager", "getSubscriberId", "identity",
     "Reads IMSI (SIM identity)"),
    ("android.telephony.TelephonyManager", "getSimSerialNumber", "identity",
     "Reads SIM serial"),
    ("android.telephony.TelephonyManager", "getLine1Number", "identity",
     "Reads the victim's phone number"),
    ("dalvik.system.DexClassLoader", None, "dynamic_code",
     "Loads dex code at runtime — classic payload-hiding technique"),
    ("dalvik.system.PathClassLoader", None, "dynamic_code",
     "Loads code from arbitrary paths at runtime"),
    ("dalvik.system.InMemoryDexClassLoader", None, "dynamic_code",
     "Loads dex straight from memory — leaves no file artifact"),
    ("java.lang.Runtime", "exec", "shell",
     "Executes shell commands"),
    ("java.lang.ProcessBuilder", None, "shell",
     "Builds and runs native processes"),
    ("java.lang.reflect.Method", "invoke", "reflection",
     "Reflection — hides which APIs are actually called"),
    ("javax.crypto.Cipher", None, "crypto",
     "Encryption — config/exfil encryption or ransomware behavior"),
    ("android.app.admin.DevicePolicyManager", None, "persistence",
     "Device-admin policy control"),
    ("android.accessibilityservice.AccessibilityService", None, "device_control",
     "Implements an accessibility service (screen reading / auto-clicking)"),
    ("android.view.accessibility.AccessibilityNodeInfo", "performAction",
     "device_control", "Performs taps/gestures on the victim's behalf"),
    ("android.media.MediaRecorder", None, "surveillance",
     "Records audio/video"),
    ("android.location.LocationManager", "getLastKnownLocation", "surveillance",
     "Reads device location"),
    ("android.content.pm.PackageManager", "getInstalledPackages", "recon",
     "Enumerates installed apps"),
    ("java.net.HttpURLConnection", None, "network",
     "Raw HTTP networking"),
    ("javax.net.ssl.HttpsURLConnection", None, "network",
     "Raw HTTPS networking"),
    ("java.net.URL", "openConnection", "network",
     "Opens network connections"),
    ("android.webkit.WebView", "addJavascriptInterface", "webview",
     "Bridges JS into native code — phishing-page-to-device bridge"),
    ("android.os.SystemProperties", None, "evasion",
     "Reads hidden system properties (emulator detection)"),
    ("android.app.KeyguardManager", None, "device_control",
     "Lock-screen interaction"),
]

URL_RE = re.compile(r"https?://[\w\-.]+(?::\d+)?(?:/[^\s'\"<>]*)?", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHELL_CMDS = ("su", "chmod", "chown", "mount", "remount", "pm install",
              "pm uninstall", "am start", "killall", "iptables", "getprop")
# Infra domains that appear in virtually every app — listed but de-prioritized
COMMON_DOMAINS = (
    "schemas.android.com", "www.w3.org", "xmlpull.org", "www.apache.org",
    "developer.android.com", "play.google.com", "www.google.com",
    "github.com", "goo.gl", "fonts.googleapis.com", "ns.adobe.com",
    "purl.org", "xml.org", "java.sun.com", "json.org", "momentjs.com",
    "www.example.com", "example.com", "sentry.io", "crashlytics.com",
    "firebase.google.com", "ssl.google-analytics.com", "iana.org",
)


@dataclass
class StaticResult:
    report: dict
    drebin_vector: dict[str, int]
    icon_bytes: bytes | None = None
    pools: object = None  # DexPools — internal, for downstream layers
    timings: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.report, indent=2, default=str)


def _hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _extract_icon(a: APK) -> bytes | None:
    """App icon bytes; handles adaptive-icon XML by falling back to the
    largest launcher-ish raster in res/."""
    try:
        path = a.get_app_icon()
        if path and not path.endswith(".xml"):
            data = a.get_file(path)
            if data:
                return data
    except Exception:
        pass
    best: tuple[int, bytes] | None = None
    try:
        for name in a.get_files():
            if not name.startswith("res/"):
                continue
            low = name.lower()
            if not low.endswith((".png", ".webp")):
                continue
            if not ("launcher" in low or "ic_logo" in low or "icon" in low):
                continue
            data = a.get_file(name)
            if data and (best is None or len(data) > best[0]):
                best = (len(data), data)
    except Exception:
        pass
    return best[1] if best else None


def _manifest_intent_actions(a: APK) -> set[str]:
    actions: set[str] = set()
    try:
        xml = a.get_android_manifest_xml()
        for el in xml.iter("action"):
            name = el.get(ANDROID_NS + "name")
            if name:
                actions.add(name)
    except Exception:
        pass
    return actions


def _manifest_red_flag_services(a: APK) -> list[dict]:
    """Services gated behind sensitive BIND_* permissions (accessibility,
    device admin, notification listener) declared in the manifest."""
    hits = []
    watch = {
        "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility service",
        "android.permission.BIND_DEVICE_ADMIN": "device-admin receiver",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
            "notification listener (reads every notification incl. OTPs)",
    }
    try:
        xml = a.get_android_manifest_xml()
        for el in xml.iter():
            if el.tag not in ("service", "receiver"):
                continue
            perm = el.get(ANDROID_NS + "permission")
            if perm in watch:
                hits.append({
                    "component": el.get(ANDROID_NS + "name") or "?",
                    "permission": perm,
                    "meaning": watch[perm],
                })
    except Exception:
        pass
    return hits


def _run_apkid(path: str) -> dict:
    """APKiD packer/obfuscator fingerprint via its CLI (JSON mode)."""
    exe = shutil.which("apkid")
    cmd = [exe, "-j", path] if exe else [sys.executable, "-m", "apkid", "-j", path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        data = json.loads(proc.stdout)
        merged: dict[str, list] = {}
        for f in data.get("files", []):
            for kind, names in f.get("matches", {}).items():
                merged.setdefault(kind, [])
                merged[kind].extend(n for n in names if n not in merged[kind])
        return {"ok": True, "matches": merged}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "matches": {}}


def _suspicious_api_hits(pools: "dexparse.DexPools") -> list[dict]:
    hits = []
    for cls, meth, category, why in SUSPICIOUS_APIS:
        if meth is None:
            found = cls in pools.classes
        else:
            found = f"{cls}.{meth}" in pools.method_refs
        if found:
            hits.append({"api": f"{cls}.{meth}" if meth else cls,
                         "category": category, "why": why})
    return hits


def _network_indicators(pools: "dexparse.DexPools") -> dict:
    urls, ips = set(), set()
    for s in pools.strings:
        if "://" in s:
            urls.update(m.group(0) for m in URL_RE.finditer(s))
        if "." in s and any(ch.isdigit() for ch in s):
            for m in IP_RE.finditer(s):
                octets = m.group(0).split(".")
                if all(int(o) <= 255 for o in octets) and m.group(0) not in (
                        "0.0.0.0", "127.0.0.1", "255.255.255.255"):
                    ips.add(m.group(0))
    def domain(u: str) -> str:
        return u.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    interesting, common = [], []
    for u in sorted(urls):
        (common if domain(u) in COMMON_DOMAINS else interesting).append(u)
    shell = sorted({c for c in SHELL_CMDS
                    for s in pools.strings if s.strip() == c or s.startswith(c + " ")})
    return {
        "urls_interesting": interesting[:200],
        "urls_common_infra": common[:50],
        "ips": sorted(ips)[:100],
        "shell_command_strings": shell,
        "n_urls_total": len(urls),
    }


def analyze_apk(path: str | Path | None = None, *, data: bytes | None = None,
                filename: str | None = None) -> StaticResult:
    """Analyze an APK from a file path OR from raw bytes (data=).

    Bytes mode exists for safe analysis of real malware straight from a
    password-protected archive: the decrypted APK never touches disk. APKiD
    needs a real file, so it is skipped in bytes mode (one signal lost; the
    manifest/cert/dex/Drebin layers all still run).
    """
    t_start = time.time()
    if data is None:
        if path is None:
            raise ValueError("provide either path or data")
        path = str(path)
        raw = Path(path).read_bytes()
        name = filename or Path(path).name
    else:
        raw = bytes(data)
        name = filename or "in-memory.apk"
    timings: dict[str, float] = {}

    t = time.time()
    a = APK(raw, raw=True)
    timings["manifest_cert"] = round(time.time() - t, 2)

    t = time.time()
    pools = dexparse.pools_from_dex_buffers(a.get_all_dex())
    timings["dex_tables"] = round(time.time() - t, 2)

    permissions = sorted(set(a.get_permissions()))
    perm_segments = {p.rsplit(".", 1)[-1]: p for p in permissions}
    red_flags = [
        {"permission": full, "short": seg,
         "category": RED_FLAG_PERMISSIONS[seg][0],
         "why": RED_FLAG_PERMISSIONS[seg][1]}
        for seg, full in sorted(perm_segments.items())
        if seg in RED_FLAG_PERMISSIONS
    ]

    certs = []
    try:
        for c in a.get_certificates():
            certs.append({
                "subject": c.subject.human_friendly,
                "issuer": c.issuer.human_friendly,
                "sha256": hashlib.sha256(c.dump()).hexdigest(),
                "serial": str(c.serial_number),
                "not_before": str(c["tbs_certificate"]["validity"]["not_before"].native),
                "not_after": str(c["tbs_certificate"]["validity"]["not_after"].native),
                "self_signed": c.subject == c.issuer,
            })
    except Exception as exc:
        certs.append({"error": f"cert parse failed: {exc}"})

    intent_actions = _manifest_intent_actions(a)

    t = time.time()
    if data is None:
        apkid = _run_apkid(path)
    else:
        apkid = {"ok": False, "skipped": True, "matches": {},
                 "note": "APKiD skipped (in-memory analysis; needs a file)"}
    timings["apkid"] = round(time.time() - t, 2)

    t = time.time()
    matcher = DrebinMatcher(
        permissions=permissions,
        intent_actions=intent_actions,
        dex_strings=pools.strings,
        classes=pools.classes,
        class_simple_names=pools.class_simple_names,
        method_refs=pools.method_refs,
        method_names=pools.method_names,
    )
    drebin_vector = matcher.vector(load_feature_names())
    timings["drebin_match"] = round(time.time() - t, 2)

    report = {
        "file": {
            "name": name,
            "size_bytes": len(raw),
            **_hashes(raw),
        },
        "manifest": {
            "package": a.get_package(),
            "app_name": _safe(a.get_app_name),
            "version_name": _safe(a.get_androidversion_name),
            "version_code": _safe(a.get_androidversion_code),
            "min_sdk": _safe(a.get_min_sdk_version),
            "target_sdk": _safe(a.get_target_sdk_version),
            "main_activity": _safe(a.get_main_activity),
            "n_activities": len(a.get_activities()),
            "n_services": len(a.get_services()),
            "n_receivers": len(a.get_receivers()),
            "n_providers": len(a.get_providers()),
            "intent_actions": sorted(intent_actions),
        },
        "permissions": {
            "all": permissions,
            "count": len(permissions),
            "red_flags": red_flags,
            "red_flag_categories": sorted({r["category"] for r in red_flags}),
            "sensitive_bind_components": _manifest_red_flag_services(a),
        },
        "certificate": {
            "certs": certs,
            "signed_v1": _safe(a.is_signed_v1),
            "signed_v2": _safe(a.is_signed_v2),
            "signed_v3": _safe(a.is_signed_v3),
        },
        "dex": {
            "n_dex_files": pools.n_dex,
            "n_strings": pools.n_strings,
            "n_method_refs": pools.n_method_refs,
            "suspicious_apis": _suspicious_api_hits(pools),
        },
        "network": _network_indicators(pools),
        "apkid": apkid,
        "drebin_active_features": sorted(
            [k for k, v in drebin_vector.items() if v]),
        "analysis_seconds": round(time.time() - t_start, 2),
    }

    icon = _extract_icon(a)
    timings["total"] = round(time.time() - t_start, 2)
    return StaticResult(report=report, drebin_vector=drebin_vector,
                        icon_bytes=icon, pools=pools, timings=timings)


def _safe(fn):
    try:
        return fn()
    except Exception:
        return None


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Static-analyze an APK")
    ap.add_argument("apk")
    ap.add_argument("--json", action="store_true", help="dump full report JSON")
    args = ap.parse_args()
    res = analyze_apk(args.apk)
    if args.json:
        print(res.to_json())
    else:
        r = res.report
        print(f"package : {r['manifest']['package']}")
        print(f"app     : {r['manifest']['app_name']}")
        print(f"sha256  : {r['file']['sha256']}")
        print(f"perms   : {r['permissions']['count']} "
              f"({len(r['permissions']['red_flags'])} red-flag)")
        print(f"susp api: {len(r['dex']['suspicious_apis'])}")
        print(f"drebin  : {len(r['drebin_active_features'])}/215 active")
        print(f"apkid   : {r['apkid']['matches']}")
        print(f"timings : {res.timings}")
