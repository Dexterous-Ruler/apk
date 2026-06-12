"""Train the APK ML risk model on the Drebin-215 dataset.

Honest-evaluation rules (same discipline as the mule track):
  * 5-fold stratified CV -> out-of-fold probabilities; every reported metric
    is OOF, never train-on-test.
  * The dataset is 37% malware — wildly unrealistic. Real APK triage streams
    are ~90% benign, so precision/FPR are ALSO reported prior-shifted to a
    10% malware prevalence (Bayes adjustment from OOF TPR/FPR). Both numbers
    go in the report; the prior-shifted one is the honest headline.
  * No time-aware split is possible (the public CSV carries no timestamps) —
    disclosed as a limitation rather than hidden.
  * Model selection (RF vs XGBoost vs LightGBM) is by OOF PR-AUC only; the
    winner is refit on all rows and saved as the scoring bundle.

Usage: python apk/analysis/train_model.py
Writes: apk/outputs/apk_model_bundle.joblib, apk_model_metrics.json,
        apk_feature_importance.csv
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (average_precision_score, confusion_matrix,
                             precision_recall_curve, roc_auc_score)
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]  # apk/
DATA = ROOT / "data" / "training" / "drebin215.csv"
OUT = ROOT / "outputs"
SEED = 42
REALISTIC_MALWARE_PRIOR = 0.10


def load_dataset() -> tuple[pd.DataFrame, np.ndarray, list[str], np.ndarray, int]:
    df = pd.read_csv(DATA, low_memory=False)
    y = (df["class"].astype(str).str.strip() == "S").astype(int).to_numpy()
    X = df.drop(columns=["class"])
    # column 92 carries stray '?' rows in the public mirror — coerce to 0/1
    for c in X.columns[X.dtypes == object]:
        X[c] = pd.to_numeric(X[c], errors="coerce")
    n_bad = int(X.isna().any(axis=1).sum())
    X = X.fillna(0).astype(np.int8)
    feature_names = list(X.columns)
    # Group identical feature vectors together. The Drebin-215 binary vectors
    # collide heavily (repacked/near-duplicate apps share a vector); a plain
    # random split leaks duplicates across train/test and inflates the metric.
    # Grouping by vector hash keeps all copies of a vector in the same fold.
    groups = pd.util.hash_pandas_object(X, index=False).to_numpy()
    n_unique = len(np.unique(groups))
    n_dupes = len(X) - n_unique
    print(f"loaded {len(df)} rows, {len(feature_names)} features, "
          f"{y.sum()} malware ({y.mean():.1%}), {n_bad} junk->0; "
          f"{n_dupes} duplicate vectors ({n_dupes / len(X):.1%}), "
          f"{n_unique} unique groups")
    return X, y, feature_names, groups, n_dupes


def make_models() -> dict:
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=400, max_features="sqrt", n_jobs=-1,
            class_weight="balanced", random_state=SEED),
        "xgboost": XGBClassifier(
            n_estimators=500, learning_rate=0.08, max_depth=7,
            subsample=0.9, colsample_bytree=0.8, eval_metric="aucpr",
            tree_method="hist", n_jobs=-1, random_state=SEED),
        "lightgbm": LGBMClassifier(
            n_estimators=500, learning_rate=0.08, num_leaves=63,
            subsample=0.9, colsample_bytree=0.8, n_jobs=-1,
            random_state=SEED, verbose=-1),
    }


def oof_probabilities(model, X, y, groups=None, n_splits=5) -> np.ndarray:
    """Out-of-fold probabilities. With `groups` (identical-vector ids) we use
    StratifiedGroupKFold so duplicate vectors never straddle the split — this
    removes the duplicate-leak inflation in the headline metric."""
    oof = np.zeros(len(y))
    if groups is not None:
        splitter = StratifiedGroupKFold(n_splits=n_splits)
        split_iter = splitter.split(X, y, groups)
    else:
        splitter = StratifiedKFold(n_splits=n_splits, shuffle=True,
                                   random_state=SEED)
        split_iter = splitter.split(X, y)
    for fold, (tr, te) in enumerate(split_iter):
        m = type(model)(**model.get_params())
        m.fit(X.iloc[tr], y[tr])
        oof[te] = m.predict_proba(X.iloc[te])[:, 1]
        print(f"    fold {fold + 1}/{n_splits} done")
    return oof


def prior_shifted_precision(tpr: float, fpr: float, pi: float) -> float:
    """Precision if the same classifier ran on a stream with malware
    prevalence pi (Bayes: P(mal|alert))."""
    denom = tpr * pi + fpr * (1 - pi)
    return float(tpr * pi / denom) if denom > 0 else 0.0


def evaluate(y: np.ndarray, oof: np.ndarray) -> dict:
    roc = roc_auc_score(y, oof)
    pr = average_precision_score(y, oof)
    # operating point: max-F1 on the OOF curve
    prec, rec, thr = precision_recall_curve(y, oof)
    f1 = 2 * prec * rec / np.clip(prec + rec, 1e-9, None)
    best = int(np.nanargmax(f1[:-1]))
    threshold = float(thr[best])
    pred = (oof >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    tpr = tp / (tp + fn)
    fpr = fp / (fp + tn)
    return {
        "roc_auc": round(float(roc), 4),
        "pr_auc": round(float(pr), 4),
        "operating_point": {
            "threshold": round(threshold, 4),
            "criterion": "max-F1 on OOF",
            "confusion": {"tn": int(tn), "fp": int(fp),
                          "fn": int(fn), "tp": int(tp)},
            "precision_raw": round(float(prec[best]), 4),
            "recall_tpr": round(float(tpr), 4),
            "fpr": round(float(fpr), 4),
            "f1_raw": round(float(f1[best]), 4),
            "precision_at_10pct_prevalence": round(
                prior_shifted_precision(tpr, fpr, REALISTIC_MALWARE_PRIOR), 4),
        },
        "dataset_malware_share": round(float(np.mean(y)), 4),
        "realistic_prior_used": REALISTIC_MALWARE_PRIOR,
    }


def main() -> None:
    OUT.mkdir(exist_ok=True)
    X, y, feature_names, groups, n_dupes = load_dataset()
    results: dict[str, dict] = {}
    oofs: dict[str, np.ndarray] = {}

    for name, model in make_models().items():
        print(f"[{name}] cross-validating (group-aware, dedup-safe)...")
        t0 = time.time()
        oof = oof_probabilities(model, X, y, groups=groups)
        oofs[name] = oof
        results[name] = evaluate(y, oof)
        results[name]["cv_seconds"] = round(time.time() - t0, 1)
        print(f"  -> PR-AUC {results[name]['pr_auc']}, "
              f"ROC-AUC {results[name]['roc_auc']} "
              f"({results[name]['cv_seconds']}s)")

    winner = max(results, key=lambda k: results[k]["pr_auc"])
    print(f"winner by OOF PR-AUC: {winner}")

    final = make_models()[winner]
    final.fit(X, y)

    if hasattr(final, "feature_importances_"):
        imp = pd.DataFrame({
            "feature": feature_names,
            "importance": final.feature_importances_,
        }).sort_values("importance", ascending=False)
        imp.to_csv(OUT / "apk_feature_importance.csv", index=False)
        top = imp.head(15)[["feature", "importance"]].to_dict("records")
    else:
        top = []

    metrics = {
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": {
            "file": DATA.name,
            "n_rows": int(len(X)),
            "n_features": len(feature_names),
            "n_malware": int(y.sum()),
            "n_benign": int((1 - y).sum()),
            "n_duplicate_vectors": int(n_dupes),
            "duplicate_share": round(n_dupes / len(X), 4),
            "source": "Drebin-215 public mirror (5,560 malware / 9,476 benign)",
        },
        "cv": "StratifiedGroupKFold(5) grouping identical feature vectors "
              "(duplicate-leak-safe)",
        "models": results,
        "selected_model": winner,
        "top_features": top,
        "limitations": [
            f"The dataset has {n_dupes} duplicate 215-d vectors "
            f"({n_dupes / len(X):.0%}) from repacked/near-duplicate apps. We "
            "cross-validate with StratifiedGroupKFold so duplicates never "
            "straddle the split — these are honest dedup-safe numbers, not the "
            "inflated random-split figure.",
            "No time-aware (TESSERACT) split possible: the public CSV has no "
            "timestamps. Even dedup-safe numbers overstate robustness to "
            "concept drift; treat them as upper bounds.",
            "Live extraction approximates the original (unpublished) Drebin "
            "feature extractor; cross-checked on known samples but not "
            "bit-identical.",
            "Dataset era is older than current banking trojans; the "
            "impersonation + red-flag layers exist precisely because the ML "
            "model alone cannot carry current-threat coverage.",
            f"Precision is also reported prior-shifted to "
            f"{REALISTIC_MALWARE_PRIOR:.0%} malware prevalence; the raw "
            f"dataset is {float(np.mean(y)):.0%} malware which inflates "
            "naive precision.",
        ],
    }
    (OUT / "apk_model_metrics.json").write_text(json.dumps(metrics, indent=2))

    bundle = {
        "model": final,
        "model_name": winner,
        "feature_names": feature_names,
        "threshold": results[winner]["operating_point"]["threshold"],
        "metrics": metrics,
    }
    joblib.dump(bundle, OUT / "apk_model_bundle.joblib")
    print(f"saved bundle ({winner}) + metrics to {OUT}")
    # OOF scores for the report's score-distribution chart
    pd.DataFrame({"y": y, **{f"oof_{k}": v for k, v in oofs.items()}}).to_csv(
        OUT / "apk_oof_scores.csv", index=False)


if __name__ == "__main__":
    sys.exit(main())
