"""Scan every downloaded encrypted sample for rich malicious STATIC code
(good GenAI-RE demo candidates) — high-value categories in the app's own code."""
import io, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import pyzipper
import deep_analysis as da

ENC = Path(__file__).resolve().parents[1] / "data" / "samples" / "real_encrypted"
rows = []
for z in sorted(ENC.glob("*.zip")):
    try:
        with pyzipper.AESZipFile(io.BytesIO(z.read_bytes())) as zf:
            zf.setpassword(b"infected")
            data = zf.read(zf.namelist()[0])
        r = da.analyze_deep(data=data, max_targets=6).to_dict()
        hv = {c: n for c, n in r["category_summary"].items()
              if c in da.HIGH_VALUE_CATS}
        app_targets = [t for t in r["re_targets"]
                       if not t["full_class"].startswith(da.SDK_PREFIXES)
                       and set(t["categories"]) & da.HIGH_VALUE_CATS]
        pkg = "?"
        try:
            from androguard.core.apk import APK
            from loguru import logger; logger.remove()
            pkg = APK(data, raw=True).get_package()
        except Exception:
            pass
        rows.append((z.stem[:12], pkg, r["n_methods"], hv,
                     len(app_targets), r["seconds"]))
        print(f"{z.stem[:12]} {pkg:34s} m={r['n_methods']:5d} "
              f"hv={hv} app_re_targets={len(app_targets)} ({r['seconds']}s)")
    except Exception as e:
        print(f"{z.stem[:12]} ERROR {type(e).__name__}: {e}")

rows.sort(key=lambda r: (r[4], sum(r[3].values())), reverse=True)
print("\n=== BEST RE DEMO CANDIDATES (most malicious static app code) ===")
for sha, pkg, m, hv, nt, s in rows[:5]:
    print(f"  {sha} {pkg:34s} app_targets={nt} hv={hv}")
