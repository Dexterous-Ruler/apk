"""Assemble harmless demo APKs for the analyzer (NOT real malware).

Each "sample" is a real, parseable, v1-signed APK that carries the *identity
and capability signals* of a banking-fraud app — typosquat name, official-
bank package mimicry, the SOVA/Anubis permission set, suspicious API
references and an exfil URL in the dex — but contains NO executable malicious
code (the dex has reference tables only, no method bodies). It cannot run as
malware; it exists purely to exercise and demo the static pipeline safely.

Signing: v1 (JAR) signature via the JDK's jarsigner, using a throwaway
self-signed keystore generated with keytool. That self-signed cert is exactly
what the impersonation layer should flag on a bank-flavored app.

Usage: python apk/tools/build_fake_bank.py
Writes APKs into apk/data/samples/crafted/.
"""
from __future__ import annotations

import io
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from axml import Element, build_axml  # noqa: E402
from dexgen import build_dex  # noqa: E402

OUT_DIR = Path(__file__).resolve().parents[1] / "data" / "samples" / "crafted"

# Suspicious API references baked into every crafted malicious sample.
MAL_METHOD_REFS = [
    ("android.telephony.SmsManager", "sendTextMessage"),
    ("android.telephony.SmsManager", "sendMultipartTextMessage"),
    ("android.telephony.TelephonyManager", "getDeviceId"),
    ("android.telephony.TelephonyManager", "getSimSerialNumber"),
    ("android.telephony.TelephonyManager", "getLine1Number"),
    ("java.lang.Runtime", "exec"),
    ("java.net.URL", "openConnection"),
    ("android.view.accessibility.AccessibilityNodeInfo", "performAction"),
    ("android.content.pm.PackageManager", "getInstalledPackages"),
    ("javax.crypto.Cipher", "doFinal"),
]
MAL_CLASSES = [
    "dalvik.system.DexClassLoader",
    "android.app.admin.DevicePolicyManager",
    "android.accessibilityservice.AccessibilityService",
]
MAL_STRINGS = [
    "http://sbi-secure-verify.000webhostapp.com/add.php",
    "http://185.220.101.47/gate.php",
    "su",
    "pm install",
    "/system/bin/sh",
    "Your KYC is suspended. Update now to avoid account block.",
]

# 1x1 PNG (harmless placeholder icon)
_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000d49444154789c63f8cfc0f01f0005000100ff2b2f0c0000000049454e44ae426082")


def make_manifest(package: str, label: str, permissions: list[str],
                  version_code: int = 7, version_name: str = "1.0",
                  min_sdk: int = 19, target_sdk: int = 28) -> bytes:
    root = Element("manifest", [
        (False, "package", package, "str"),
        (True, "versionCode", version_code, "int"),
        (True, "versionName", version_name, "str"),
    ])
    root.add(Element("uses-sdk", [
        (True, "minSdkVersion", min_sdk, "int"),
        (True, "targetSdkVersion", target_sdk, "int"),
    ]))
    for p in permissions:
        root.add(Element("uses-permission", [
            (True, "name", "android.permission." + p, "str")]))
    app = Element("application", [
        (True, "label", label, "str"),
        (True, "icon", "@icon", "str"),
        (True, "debuggable", True, "bool"),
    ])
    root.add(app)
    act = Element("activity", [
        (True, "name", ".MainActivity", "str"),
        (True, "exported", True, "bool"),
    ])
    app.add(act)
    intent = Element("intent-filter")
    act.add(intent)
    intent.add(Element("action",
                       [(True, "name", "android.intent.action.MAIN", "str")]))
    intent.add(Element("category",
                       [(True, "name", "android.intent.category.LAUNCHER", "str")]))
    # an accessibility service component (the overlay/auto-click engine)
    if "BIND_ACCESSIBILITY_SERVICE" in permissions:
        svc = Element("service", [
            (True, "name", ".PaymentAccessibilityService", "str"),
            (True, "permission",
             "android.permission.BIND_ACCESSIBILITY_SERVICE", "str"),
            (True, "exported", True, "bool"),
        ])
        app.add(svc)
        sif = Element("intent-filter")
        svc.add(sif)
        sif.add(Element("action", [
            (True, "name",
             "android.accessibilityservice.AccessibilityService", "str")]))
    # boot receiver (persistence)
    if "RECEIVE_BOOT_COMPLETED" in permissions:
        rcv = Element("receiver", [
            (True, "name", ".BootReceiver", "str"),
            (True, "exported", True, "bool"),
        ])
        app.add(rcv)
        rif = Element("intent-filter")
        rcv.add(rif)
        rif.add(Element("action", [
            (True, "name", "android.intent.action.BOOT_COMPLETED", "str")]))
    return build_axml(root)


def _zip_with_crc(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def sign_apk(unsigned: bytes, out_path: Path) -> None:
    keytool = shutil.which("keytool")
    jarsigner = shutil.which("jarsigner")
    if not (keytool and jarsigner):
        out_path.write_bytes(unsigned)
        print(f"  [!] jarsigner/keytool not found — wrote UNSIGNED {out_path.name}")
        return
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        ks = td / "demo.keystore"
        tmp_apk = td / "tmp.apk"
        tmp_apk.write_bytes(unsigned)
        subprocess.run([keytool, "-genkeypair", "-keystore", str(ks),
                        "-storepass", "android", "-keypass", "android",
                        "-alias", "demo", "-keyalg", "RSA", "-keysize", "2048",
                        "-validity", "365", "-dname",
                        "CN=Android Debug,O=Android,C=US"],
                       check=True, capture_output=True)
        subprocess.run([jarsigner, "-keystore", str(ks), "-storepass",
                        "android", "-keypass", "android", "-sigalg",
                        "SHA256withRSA", "-digestalg", "SHA-256",
                        str(tmp_apk), "demo"],
                       check=True, capture_output=True)
        out_path.write_bytes(tmp_apk.read_bytes())
        print(f"  [+] signed {out_path.name}")


def build_sample(name: str, package: str, label: str, permissions: list[str],
                 malicious: bool) -> None:
    manifest = make_manifest(package, label, permissions)
    if malicious:
        dex = build_dex(MAL_METHOD_REFS, MAL_STRINGS, MAL_CLASSES)
    else:
        dex = build_dex([("java.lang.System", "currentTimeMillis"),
                         ("java.net.URL", "openConnection")],
                        ["https://api.example-weather.com/v1/forecast"], [])
    files = {
        "AndroidManifest.xml": manifest,
        "classes.dex": dex,
        "res/drawable/icon.png": _PNG,
        "resources.arsc": _minimal_arsc(),
    }
    unsigned = _zip_with_crc(files)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sign_apk(unsigned, OUT_DIR / f"{name}.apk")


def _minimal_arsc() -> bytes:
    # a near-empty resource table chunk (type 0x0002). androguard tolerates a
    # missing/limited arsc; we include a stub so the zip looks app-like.
    return struct.pack("<HHI", 0x0002, 12, 12) + struct.pack("<I", 0)


SAMPLES = [
    dict(name="fake_sbi_yono_rewards",
         package="com.kyc.sbi.rewards.update",
         label="SBl YONO Rewards",
         permissions=["INTERNET", "SEND_SMS", "RECEIVE_SMS", "READ_SMS",
                      "READ_PHONE_STATE", "READ_CONTACTS",
                      "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
                      "RECEIVE_BOOT_COMPLETED", "REQUEST_INSTALL_PACKAGES",
                      "QUERY_ALL_PACKAGES", "WRITE_EXTERNAL_STORAGE"],
         malicious=True),
    dict(name="fake_icici_imobile",
         package="com.icici.imobile.secure",
         label="iMobile Pay Verify",
         permissions=["INTERNET", "RECEIVE_SMS", "READ_SMS",
                      "READ_PHONE_STATE", "SYSTEM_ALERT_WINDOW",
                      "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
                      "RECEIVE_BOOT_COMPLETED", "CALL_PHONE"],
         malicious=True),
    dict(name="clean_notes_app",
         package="com.demo.simplenotes",
         label="Simple Notes",
         permissions=["INTERNET", "ACCESS_NETWORK_STATE", "VIBRATE"],
         malicious=False),
]


def main() -> None:
    print(f"building {len(SAMPLES)} crafted demo APKs into {OUT_DIR}")
    for s in SAMPLES:
        print(f"- {s['name']} ({'MALICIOUS-style' if s['malicious'] else 'benign'})")
        build_sample(**s)
    print("done.")


if __name__ == "__main__":
    main()
