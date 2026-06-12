"""Probe androguard 4.1.4 API surface against the F-Droid benign APK.

Validates the exact calls apk_static.py will rely on before we build it.
"""
import sys, time, hashlib
from loguru import logger
logger.remove()  # silence androguard's loguru spam

from androguard.core.apk import APK
from androguard.core.dex import DEX

PATH = r"C:\Users\tanis\hackathon\apk\data\samples\benign\FDroid.apk"

t0 = time.time()
a = APK(PATH)
print(f"[{time.time()-t0:6.1f}s] APK parsed")
print("package      :", a.get_package())
print("app_name     :", a.get_app_name())
print("version      :", a.get_androidversion_name(), "/", a.get_androidversion_code())
print("min/target   :", a.get_min_sdk_version(), "/", a.get_target_sdk_version())
print("perms n      :", len(a.get_permissions()))
print("perms sample :", a.get_permissions()[:5])
print("declared     :", a.get_declared_permissions()[:5])
print("activities n :", len(a.get_activities()))
print("services n   :", len(a.get_services()))
print("receivers n  :", len(a.get_receivers()))
print("providers n  :", len(a.get_providers()))
print("main activity:", a.get_main_activity())
print("signed v1/v2/v3:", a.is_signed_v1(), a.is_signed_v2(), a.is_signed_v3())

certs = a.get_certificates()
print("certs n      :", len(certs))
if certs:
    c = certs[0]
    print("  issuer     :", c.issuer.human_friendly)
    print("  subject    :", c.subject.human_friendly)
    print("  self-signed:", c.self_signed)
    print("  sha256     :", hashlib.sha256(c.dump()).hexdigest())
    print("  not_before :", c['tbs_certificate']['validity']['not_before'].native)

icon = a.get_app_icon()
print("icon path    :", icon)

t1 = time.time()
dexes = list(a.get_all_dex())
print(f"[{time.time()-t1:6.1f}s] got {len(dexes)} dex buffers, sizes={[len(d) for d in dexes]}")

t2 = time.time()
n_strings = 0
n_methods = 0
sample = []
for raw in dexes:
    d = DEX(raw)
    ss = d.get_strings()
    n_strings += len(ss)
    n_methods += len(d.get_methods())
    if not sample:
        sample = [str(s) for s in ss[:5]]
print(f"[{time.time()-t2:6.1f}s] DEX parsed: {n_strings} strings, {n_methods} methods")
print("string sample:", sample)
print(f"TOTAL {time.time()-t0:6.1f}s")
