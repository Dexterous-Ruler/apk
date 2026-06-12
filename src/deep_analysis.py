"""Deep analysis engine: call-graph behavioral (taint-style) analysis + RE
target extraction. Shared by the reverse-engineering and behavioral layers.

This is the heavy path (builds an Androguard cross-reference graph, ~10-30s),
kept OFF the fast verdict path and run only on demand. Works from a file path
OR raw bytes, so real malware is analyzed in-memory (never written to disk).

What it produces:
  * suspicious_call_sites — every internal method that invokes a sensitive
    API, with the API, its category, and the string constants in that method
  * behavior_flows — source->sink data paths (e.g. an SMS-reading method that
    also performs network I/O = OTP exfiltration), the runtime behavior the
    bytecode encodes without executing it
  * re_targets — the most suspicious methods with their actual smali code, for
    the GenAI reverse-engineering layer to read and explain
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from loguru import logger

logger.remove()

from androguard.core.apk import APK  # noqa: E402
from androguard.core.dex import DEX  # noqa: E402
from androguard.core.analysis.analysis import Analysis  # noqa: E402

# Sensitive APIs: descriptor-substring -> (category, human label). Matched
# against the called method's "ClassName->methodName".
SENSITIVE_APIS = {
    "Landroid/telephony/SmsManager;->sendTextMessage": ("sms_send", "Sends an SMS"),
    "Landroid/telephony/SmsManager;->sendMultipartTextMessage": ("sms_send", "Sends a long SMS"),
    "Landroid/telephony/SmsManager;->getDefault": ("sms_send", "Acquires the SMS manager"),
    "Landroid/telephony/SmsMessage;->getMessageBody": ("sms_read", "Reads an SMS body (OTP source)"),
    "Landroid/telephony/SmsMessage;->createFromPdu": ("sms_read", "Parses an incoming SMS"),
    "Landroid/telephony/TelephonyManager;->getDeviceId": ("identity", "Reads IMEI"),
    "Landroid/telephony/TelephonyManager;->getSubscriberId": ("identity", "Reads IMSI"),
    "Landroid/telephony/TelephonyManager;->getLine1Number": ("identity", "Reads the phone number"),
    "Landroid/telephony/TelephonyManager;->getSimSerialNumber": ("identity", "Reads SIM serial"),
    "Ldalvik/system/DexClassLoader;": ("dynamic_code", "Loads dex code at runtime"),
    "Ldalvik/system/PathClassLoader;": ("dynamic_code", "Loads code from a path at runtime"),
    "Ldalvik/system/InMemoryDexClassLoader;": ("dynamic_code", "Loads dex from memory"),
    "Ljava/lang/Runtime;->exec": ("shell", "Executes a shell command"),
    "Ljava/lang/ProcessBuilder;": ("shell", "Runs a native process"),
    "Ljava/lang/reflect/Method;->invoke": ("reflection", "Invokes a method by reflection"),
    "Ljavax/crypto/Cipher;->doFinal": ("crypto", "Encrypts/decrypts data"),
    "Ljavax/crypto/Cipher;->getInstance": ("crypto", "Initializes a cipher"),
    "Ljava/net/URL;->openConnection": ("network", "Opens a network connection"),
    "Ljava/net/HttpURLConnection;": ("network", "Raw HTTP networking"),
    "Ljavax/net/ssl/HttpsURLConnection;": ("network", "Raw HTTPS networking"),
    "Lokhttp3/": ("network", "OkHttp networking"),
    "Lorg/apache/http/": ("network", "Apache HTTP networking"),
    "Ljava/io/FileOutputStream;": ("file_write", "Writes a file"),
    "Landroid/content/pm/PackageManager;->getInstalledPackages": ("recon", "Enumerates installed apps"),
    "Landroid/accessibilityservice/AccessibilityService;": ("device_control", "Accessibility service"),
    "Landroid/view/accessibility/AccessibilityNodeInfo;->performAction": ("device_control", "Performs taps/gestures"),
    "Landroid/app/admin/DevicePolicyManager;": ("persistence", "Device-admin control"),
    "Landroid/webkit/WebView;->loadUrl": ("webview", "Loads a URL in a WebView"),
    "Landroid/webkit/WebView;->addJavascriptInterface": ("webview", "Bridges JS to native"),
    "Landroid/media/MediaRecorder;": ("surveillance", "Records audio/video"),
    "Landroid/location/LocationManager;->getLastKnownLocation": ("surveillance", "Reads location"),
}

# Source categories (where sensitive data / triggers originate) and sink
# categories (where data leaves the device or code executes). A method that
# touches both is a data-exfiltration / command-execution path.
SOURCE_CATS = {"sms_read", "identity", "recon", "surveillance"}
SINK_CATS = {"network", "sms_send", "file_write", "dynamic_code", "shell"}

# Categories that signal banking-trojan behavior (vs generic library I/O).
HIGH_VALUE_CATS = {"sms_read", "sms_send", "identity", "dynamic_code",
                   "device_control", "shell", "crypto", "recon", "surveillance"}

# Well-known third-party SDK package prefixes — their call sites are usually
# benign library plumbing, so we rank the app's OWN code above them.
SDK_PREFIXES = (
    "Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/", "Ljava/", "Ljavax/",
    "Lcom/google/", "Lcom/android/", "Lokhttp3/", "Lokio/", "Lretrofit2/",
    "Lcom/facebook/", "Lcom/squareup/", "Lcom/bumptech/", "Lcom/unity3d/",
    "Lcom/anythink/", "Lcom/inappstory/", "Lcom/applovin/", "Lcom/mbridge/",
    "Lcom/bytedance/", "Lcom/ironsource/", "Lio/reactivex/", "Ldagger/",
    "Lcom/airbnb/", "Lorg/apache/", "Lorg/json/", "Lcom/onesignal/",
    "Lcom/yandex/", "Lcom/vungle/", "Lcom/adcolony/", "Lcom/tappx/",
)


def _is_sdk(cls: str) -> bool:
    return cls.startswith(SDK_PREFIXES)

ENTRY_METHODS = {"onreceive", "oncreate", "onstartcommand", "onaccessibilityevent",
                 "onbind", "run", "doinbackground", "onhandleintent", "onstart"}

CONST_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
URL_RE = re.compile(r"https?://[\w\-.]+(?::\d+)?(?:/[^\s'\"<>]*)?", re.I)


@dataclass
class DeepResult:
    ok: bool
    seconds: float
    n_methods: int
    suspicious_call_sites: list = field(default_factory=list)
    behavior_flows: list = field(default_factory=list)
    re_targets: list = field(default_factory=list)
    category_summary: dict = field(default_factory=dict)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "seconds": self.seconds,
            "n_methods": self.n_methods,
            "category_summary": self.category_summary,
            "suspicious_call_sites": self.suspicious_call_sites,
            "behavior_flows": self.behavior_flows,
            "re_targets": self.re_targets,
            "note": self.note,
        }


def _smali(em) -> list[str]:
    out = []
    try:
        for ins in em.get_instructions():
            out.append(f"{ins.get_name()} {ins.get_output()}".strip())
    except Exception:
        pass
    return out


def _match_api(callee_desc: str):
    for key, (cat, label) in SENSITIVE_APIS.items():
        if key in callee_desc:
            return cat, label, key
    return None


def build_analysis(path=None, data: bytes | None = None):
    a = APK(data, raw=True) if data is not None else APK(path)
    dx = Analysis()
    for raw in a.get_all_dex():
        try:
            dx.add(DEX(raw))
        except Exception:
            continue
    dx.create_xref()
    return a, dx


def analyze_deep(path=None, data: bytes | None = None,
                 max_targets: int = 12, time_budget: float = 90.0) -> DeepResult:
    t0 = time.time()
    try:
        _, dx = build_analysis(path=path, data=data)
    except Exception as exc:
        return DeepResult(ok=False, seconds=round(time.time() - t0, 1),
                          n_methods=0, note=f"analysis failed: {exc}")

    n_methods = 0
    per_method: dict = {}   # key -> {class, method, descriptor, apis:set, cats:set, strings:set, ma}
    for m in dx.get_methods():
        if m.is_external():
            continue
        n_methods += 1
        if time.time() - t0 > time_budget:
            break
        try:
            xrefs = m.get_xref_to()
        except Exception:
            continue
        hit = None
        for entry in xrefs:
            callee = entry[1] if len(entry) >= 2 else None
            if callee is None:
                continue
            desc = f"{getattr(callee, 'class_name', '')}->{getattr(callee, 'name', '')}"
            matched = _match_api(desc)
            if matched:
                cat, label, key = matched
                k = (m.class_name, m.name)
                rec = per_method.setdefault(k, {
                    "class": m.class_name, "method": m.name,
                    "descriptor": _safe(lambda: m.get_method().get_descriptor(), ""),
                    "apis": set(), "cats": set(), "ma": m})
                rec["apis"].add(f"{key.split(';->')[0].lstrip('L').replace('/', '.')}"
                                f"{('.' + key.split(';->')[1]) if ';->' in key else ''}|{label}")
                rec["cats"].add(cat)
                hit = True

    # category summary
    cat_summary: dict = {}
    for rec in per_method.values():
        for c in rec["cats"]:
            cat_summary[c] = cat_summary.get(c, 0) + 1

    # behavior flows: methods touching a source AND a sink category
    flows = []
    for rec in per_method.values():
        srcs = rec["cats"] & SOURCE_CATS
        snks = rec["cats"] & SINK_CATS
        if srcs and snks:
            flows.append({
                "method": f"{_short(rec['class'])}.{rec['method']}",
                "sources": sorted(srcs), "sinks": sorted(snks),
                "interpretation": _flow_meaning(srcs, snks),
                "apis": sorted(a.split("|")[1] for a in rec["apis"]),
            })
    # also: cross-method sink reachability from component entry points
    flows.extend(_entry_to_sink_flows(per_method))

    # suspicious call sites (compact, for the UI list) — app code first
    sites = []
    for rec in sorted(per_method.values(),
                      key=lambda r: (len(r["cats"] & HIGH_VALUE_CATS),
                                     not _is_sdk(r["class"]), len(r["cats"])),
                      reverse=True):
        sites.append({
            "method": f"{_short(rec['class'])}.{rec['method']}",
            "categories": sorted(rec["cats"]),
            "apis": sorted(a.split("|")[1] for a in rec["apis"]),
            "third_party_sdk": _is_sdk(rec["class"]),
        })

    # RE targets: prioritize the app's OWN code with high-value (banking-
    # trojan) categories and entry points over third-party SDK plumbing.
    def rank(rec):
        hv = len(rec["cats"] & HIGH_VALUE_CATS)
        entry = 1 if rec["method"].lower() in ENTRY_METHODS else 0
        app_code = 0 if _is_sdk(rec["class"]) else 1
        return (hv, app_code, entry, len(rec["apis"]))
    targets = []
    for rec in sorted(per_method.values(), key=rank, reverse=True)[:max_targets]:
        em = _safe(lambda: rec["ma"].get_method(), None)
        smali = _smali(em) if em is not None else []
        strings = sorted({s for line in smali
                          for s in CONST_STRING_RE.findall(line)} - {""})[:25]
        urls = sorted({u for s in strings for u in URL_RE.findall(s)})
        targets.append({
            "class": _short(rec["class"]),
            "full_class": rec["class"],
            "method": rec["method"],
            "descriptor": rec["descriptor"],
            "categories": sorted(rec["cats"]),
            "apis": sorted(a.split("|")[1] for a in rec["apis"]),
            "string_constants": strings,
            "urls": urls,
            "smali": smali[:120],
            "is_entry_point": rec["method"].lower() in ENTRY_METHODS,
        })

    return DeepResult(
        ok=True, seconds=round(time.time() - t0, 1), n_methods=n_methods,
        suspicious_call_sites=sites[:60], behavior_flows=flows[:30],
        re_targets=targets, category_summary=cat_summary,
        note="" if targets else "No sensitive API call sites found in the "
             "internal code (heavily packed, native, or genuinely benign).")


def _entry_to_sink_flows(per_method: dict) -> list:
    """Component entry points (onReceive/onAccessibilityEvent/...) that
    themselves reach a sink category — the runtime trigger->action chains."""
    out = []
    for rec in per_method.values():
        if rec["method"].lower() in ENTRY_METHODS and (rec["cats"] & SINK_CATS):
            trigger = {
                "onreceive": "a broadcast (often SMS/boot) is received",
                "onaccessibilityevent": "an accessibility event fires (screen content changes)",
                "oncreate": "the component starts",
                "onstartcommand": "the service starts",
                "run": "a background thread runs",
                "doinbackground": "an async task runs",
            }.get(rec["method"].lower(), "the entry point is triggered")
            out.append({
                "method": f"{_short(rec['class'])}.{rec['method']}",
                "trigger": trigger,
                "reaches": sorted(rec["cats"] & SINK_CATS),
                "interpretation": f"When {trigger}, this code performs "
                                  f"{', '.join(sorted(rec['cats'] & SINK_CATS))} "
                                  "actions — an automated trigger->action chain.",
                "kind": "trigger_chain",
            })
    return out


def _flow_meaning(srcs: set, snks: set) -> str:
    if "sms_read" in srcs and ("network" in snks or "sms_send" in snks):
        return ("Reads SMS content and exfiltrates/forwards it — OTP/2FA theft "
                "path.")
    if "identity" in srcs and "network" in snks:
        return ("Collects device identifiers and sends them over the network — "
                "device fingerprinting / victim profiling.")
    if "recon" in srcs and "network" in snks:
        return ("Enumerates installed apps and reports them — overlay-target "
                "selection / reconnaissance exfiltration.")
    if "surveillance" in srcs and "network" in snks:
        return "Captures location/media and exfiltrates it."
    return (f"Combines {', '.join(sorted(srcs))} data with "
            f"{', '.join(sorted(snks))} egress in one method.")


def _short(cls: str) -> str:
    return cls.lstrip("L").rstrip(";").replace("/", ".")


def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


if __name__ == "__main__":
    import argparse
    import json
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    args = ap.parse_args()
    r = analyze_deep(path=args.apk)
    d = r.to_dict()
    print(f"methods={d['n_methods']} seconds={d['seconds']} "
          f"categories={d['category_summary']}")
    print(f"behavior_flows={len(d['behavior_flows'])} "
          f"re_targets={len(d['re_targets'])}")
    for f in d["behavior_flows"][:6]:
        print("  FLOW", f.get("method"), "::", f["interpretation"][:90])
    for t in d["re_targets"][:4]:
        print(f"  RE {t['class']}.{t['method']} cats={t['categories']} "
              f"smali_lines={len(t['smali'])} urls={t['urls'][:2]}")
