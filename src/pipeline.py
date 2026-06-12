"""End-to-end APK analysis pipeline.

analyze(path) chains: static extraction -> ML scoring -> impersonation
check -> risk fusion, and returns one JSON-serializable result dict.
The GenAI report and threat-intel layers attach onto this dict downstream
(they are network-dependent; everything here is fully offline).
"""
from __future__ import annotations

import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

try:
    from . import apk_static, impersonation, risk
except ImportError:
    import apk_static
    import impersonation
    import risk

ROOT = Path(__file__).resolve().parents[1]  # apk/
BUNDLE_PATH = ROOT / "outputs" / "apk_model_bundle.joblib"

_bundle_cache: dict = {}


def load_bundle() -> dict | None:
    """Model bundle, cached on mtime so a retrain is picked up live."""
    try:
        mtime = BUNDLE_PATH.stat().st_mtime
    except OSError:
        return None
    if _bundle_cache.get("mtime") != mtime:
        _bundle_cache["bundle"] = joblib.load(BUNDLE_PATH)
        _bundle_cache["mtime"] = mtime
    return _bundle_cache["bundle"]


def ml_probability(drebin_vector: dict[str, int]) -> tuple[float | None, dict]:
    bundle = load_bundle()
    if bundle is None:
        return None, {"available": False,
                      "note": "model bundle not found — run "
                              "apk/analysis/train_model.py"}
    X = pd.DataFrame(
        [[drebin_vector.get(f, 0) for f in bundle["feature_names"]]],
        columns=bundle["feature_names"], dtype=np.int8)
    prob = float(bundle["model"].predict_proba(X)[0, 1])
    active = [f for f in bundle["feature_names"] if drebin_vector.get(f)]
    # per-feature contributions for explainability (LightGBM/XGB/RF all
    # expose predict via importance; we report the active features ranked by
    # the model's global importance as the honest, fast approximation)
    try:
        imp = dict(zip(bundle["feature_names"],
                       bundle["model"].feature_importances_))
        top_active = sorted(active, key=lambda f: imp.get(f, 0),
                            reverse=True)[:12]
    except Exception:
        top_active = active[:12]
    return prob, {
        "available": True,
        "model_name": bundle["model_name"],
        "probability": round(prob, 4),
        "alert_threshold": bundle["threshold"],
        "flagged": prob >= bundle["threshold"],
        "n_active_features": len(active),
        "top_active_features": top_active,
    }


def analyze(path: str | Path | None = None, *, data: bytes | None = None,
            filename: str | None = None) -> dict:
    t0 = time.time()
    static = apk_static.analyze_apk(path, data=data, filename=filename)
    report = static.report

    prob, ml_info = ml_probability(static.drebin_vector)

    imp = impersonation.check_impersonation(
        package=report["manifest"]["package"],
        app_name=report["manifest"]["app_name"],
        certs=report["certificate"]["certs"],
        icon_bytes=static.icon_bytes,
    ).to_dict()

    fused = risk.fuse_risk(report, imp, prob).to_dict()

    result = {
        "schema": "apk-analysis/v1",
        "risk": fused,
        "ml": ml_info,
        "impersonation": imp,
        "static": report,
        "timings": {**static.timings,
                    "pipeline_total": round(time.time() - t0, 2)},
    }
    return result


if __name__ == "__main__":
    import argparse
    import json
    ap = argparse.ArgumentParser(description="Full APK risk analysis")
    ap.add_argument("apk")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    res = analyze(args.apk)
    if args.json:
        print(json.dumps(res, indent=2, default=str))
    else:
        r = res["risk"]
        print(f"file     : {res['static']['file']['name']}")
        print(f"package  : {res['static']['manifest']['package']} "
              f"({res['static']['manifest']['app_name']})")
        print(f"RISK     : {r['score']}/100  [{r['severity']}] "
              f"- {r['verdict_label']}")
        print(f"  ml={r['components']['ml']} "
              f"imp={r['components']['impersonation']} "
              f"static={r['components']['static']}")
        for reason in r["reasons"]:
            print(f"  +{reason['points']:5.1f} {reason['code']}: "
                  f"{reason['detail'][:100]}")
        print(f"timings  : {res['timings']}")
