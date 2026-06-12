"""Risk fusion: ML probability + impersonation score + static red-flag
combos -> one explainable 0-100 risk score.

Design constraints:
  * monotonic and additive — every point of the final score traces to a
    visible component, so the gauge can be decomposed in the UI and the
    GenAI report can cite exact contributions;
  * capability COMBINATIONS score, single permissions don't — a benign app
    may read SMS, but accessibility+overlay+SMS+boot in one sideloaded APK
    is the SOVA/Anubis playbook;
  * degrades gracefully — if the ML bundle is missing, its weight is
    redistributed and the result says so.

Weights: ML 45, impersonation 35, static combos 20 (sum 100).
"""
from __future__ import annotations

from dataclasses import dataclass, field

W_ML = 45.0
W_IMP = 35.0
W_STATIC = 20.0

SEVERITY_BANDS = [
    (80, "CRITICAL"), (60, "HIGH"), (40, "MEDIUM"), (20, "LOW"), (0, "MINIMAL"),
]

VERDICT_LABELS = {
    "CRITICAL": "Malicious — treat as an active banking-fraud APK",
    "HIGH": "Likely malicious — block and investigate",
    "MEDIUM": "Suspicious — manual review required",
    "LOW": "Low risk — minor anomalies only",
    "MINIMAL": "No significant risk indicators",
}


def band(score: int) -> str:
    return next(s for cut, s in SEVERITY_BANDS if score >= cut)


@dataclass
class RiskResult:
    score: int
    severity: str
    verdict_label: str
    components: dict          # {"ml": x, "impersonation": y, "static": z}
    reasons: list[dict]       # [{code, points, detail}] sorted by points desc
    ml_available: bool
    ml_probability: float | None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _static_combo_points(report: dict) -> list[dict]:
    """Score capability combinations from the static report (max W_STATIC)."""
    perms = {r["short"] for r in report["permissions"]["red_flags"]}
    bind_components = report["permissions"]["sensitive_bind_components"]
    api_cats = {h["category"] for h in report["dex"]["suspicious_apis"]}
    apkid_matches = report.get("apkid", {}).get("matches", {})

    has_accessibility = ("BIND_ACCESSIBILITY_SERVICE" in perms or any(
        "ACCESSIBILITY" in c["permission"] for c in bind_components))
    has_overlay = "SYSTEM_ALERT_WINDOW" in perms
    has_sms_in = perms & {"RECEIVE_SMS", "READ_SMS"}
    has_network = "network" in api_cats or "INTERNET" in {
        p.rsplit(".", 1)[-1] for p in report["permissions"]["all"]}
    has_dropper = ("REQUEST_INSTALL_PACKAGES" in perms
                   or "dynamic_code" in api_cats)
    has_boot = "RECEIVE_BOOT_COMPLETED" in perms
    has_admin = ("BIND_DEVICE_ADMIN" in perms or any(
        "DEVICE_ADMIN" in c["permission"] for c in bind_components))
    has_packer = bool(apkid_matches.get("packer")
                      or apkid_matches.get("protector"))
    n_categories = len(report["permissions"]["red_flag_categories"])

    reasons = []
    if has_accessibility and has_overlay:
        reasons.append({"code": "OVERLAY_ATTACK_CAPABILITY", "points": 7.0,
                        "detail": "Accessibility service + draw-over-apps "
                        "permission: the exact combination used to overlay "
                        "fake login screens and auto-confirm them "
                        "(SOVA/Anubis pattern)."})
    elif has_accessibility:
        reasons.append({"code": "ACCESSIBILITY_ABUSE_RISK", "points": 4.0,
                        "detail": "Requests/implements an accessibility "
                        "service — can read the screen and act on the "
                        "user's behalf."})
    elif has_overlay:
        reasons.append({"code": "OVERLAY_PERMISSION", "points": 2.0,
                        "detail": "Can draw over other apps (phishing "
                        "overlay surface)."})
    if has_sms_in and has_network:
        reasons.append({"code": "OTP_THEFT_PATH", "points": 5.0,
                        "detail": "Intercepts/reads SMS AND talks to the "
                        "network: a complete OTP-theft-and-exfiltration "
                        "path."})
    elif has_sms_in:
        reasons.append({"code": "SMS_ACCESS", "points": 2.5,
                        "detail": "Reads or receives SMS (OTP exposure)."})
    if has_dropper:
        reasons.append({"code": "DROPPER_CAPABILITY", "points": 2.5,
                        "detail": "Can install packages or load code at "
                        "runtime — second-stage payload delivery."})
    if has_boot and has_admin:
        reasons.append({"code": "PERSISTENCE_HARDENING", "points": 2.0,
                        "detail": "Boot persistence + device-admin: survives "
                        "reboots and resists uninstall."})
    elif has_boot or has_admin:
        reasons.append({"code": "PERSISTENCE", "points": 1.0,
                        "detail": "Boot persistence or device-admin "
                        "registration."})
    if has_packer:
        names = (apkid_matches.get("packer", [])
                 + apkid_matches.get("protector", []))
        reasons.append({"code": "PACKED_BINARY", "points": 3.0,
                        "detail": f"Packer/protector detected ({names}): the "
                        "code is hiding from static analysis."})
    if n_categories >= 5:
        reasons.append({"code": "BROAD_CAPABILITY_SURFACE", "points": 1.5,
                        "detail": f"Red-flag permissions span {n_categories} "
                        "capability categories — far beyond any single-"
                        "purpose app."})
    return reasons


def fuse_risk(static_report: dict, impersonation: dict,
              ml_probability: float | None) -> RiskResult:
    reasons: list[dict] = []

    # ---- ML component ------------------------------------------------------
    ml_available = ml_probability is not None
    w_ml, w_imp, w_static = W_ML, W_IMP, W_STATIC
    if not ml_available:
        # redistribute ML weight proportionally to the other two
        w_imp = W_IMP / (W_IMP + W_STATIC) * 100
        w_static = W_STATIC / (W_IMP + W_STATIC) * 100
        w_ml = 0.0
    ml_pts = (ml_probability or 0.0) * w_ml
    if ml_available and ml_probability >= 0.5:
        reasons.append({"code": "ML_MODEL_FLAGGED", "points": round(ml_pts, 1),
                        "detail": f"Drebin-215 classifier probability "
                        f"{ml_probability:.2f} that this APK is malware "
                        "(trained on 15,036 labeled apps)."})
    elif ml_available:
        reasons.append({"code": "ML_MODEL_SCORE", "points": round(ml_pts, 1),
                        "detail": f"Classifier malware probability "
                        f"{ml_probability:.2f} (below alert threshold)."})

    # ---- impersonation component --------------------------------------------
    imp_score = impersonation.get("score", 0)
    imp_pts = imp_score / 100.0 * w_imp
    if imp_score > 0:
        sigs = ", ".join(s["signal"] for s in impersonation.get("signals", []))
        reasons.append({"code": f"IMPERSONATION_{impersonation.get('verdict', 'X').upper()}",
                        "points": round(imp_pts, 1),
                        "detail": f"Impersonation score {imp_score}/100 "
                        f"targeting {impersonation.get('claimed_bank') or 'a bank'} "
                        f"(signals: {sigs})."})

    # ---- static combos --------------------------------------------------------
    static_reasons = _static_combo_points(static_report)
    static_raw = sum(r["points"] for r in static_reasons)
    static_pts = min(static_raw, W_STATIC) / W_STATIC * w_static
    # scale individual reason points if redistribution changed the weight
    scale = (static_pts / static_raw) if static_raw > 0 else 0
    for r in static_reasons:
        r["points"] = round(r["points"] * scale, 1)
    reasons.extend(static_reasons)

    score = int(round(min(100.0, ml_pts + imp_pts + static_pts)))
    severity = band(score)
    reasons.sort(key=lambda r: r["points"], reverse=True)

    return RiskResult(
        score=score,
        severity=severity,
        verdict_label=VERDICT_LABELS[severity],
        components={"ml": round(ml_pts, 1),
                    "impersonation": round(imp_pts, 1),
                    "static": round(static_pts, 1),
                    "threat_intel": 0.0,
                    "weights": {"ml": w_ml, "impersonation": w_imp,
                                "static": w_static}},
        reasons=reasons,
        ml_available=ml_available,
        ml_probability=(round(ml_probability, 4) if ml_available else None),
    )


def apply_threat_intel(risk: dict, threat_intel: dict | None) -> dict:
    """Escalate the risk score using external multi-vendor threat intel.

    Threat intel can only RAISE the score, never lower it: absence of a
    detection is not evidence of safety (a new or targeted sample is simply
    unknown to VirusTotal). When several independent AV vendors — or a
    MalwareBazaar catalogue entry — flag the file, we floor the score so a
    static model trained on older malware cannot clear a confirmed threat.
    This is the layer that catches modern obfuscated trojans (Hook/Octo/…)
    whose malicious payload is loaded at runtime and so is invisible to
    static features.
    """
    if not threat_intel:
        return risk
    vt = threat_intel.get("virustotal", {})
    mb = threat_intel.get("malwarebazaar", {})
    floor = 0
    ti_points = 0.0
    added: list[dict] = []

    if vt.get("status") == "found" and vt.get("malicious", 0) > 0:
        mal = int(vt["malicious"])
        tot = int(vt.get("total_engines") or 0) or 1
        label = vt.get("suggested_label")
        if mal >= 10:
            floor = max(floor, 80)
        elif mal >= 5:
            floor = max(floor, 65)
        else:
            floor = max(floor, 45)
        ti_points = max(ti_points, min(35.0, mal * 1.3))
        added.append({"code": "THREAT_INTEL_VIRUSTOTAL",
                      "points": round(ti_points, 1),
                      "detail": f"{mal}/{tot} VirusTotal engines independently "
                      f"flag this file as malicious"
                      + (f" (label: {label})" if label else "") + "."})
    if mb.get("status") == "found":
        floor = max(floor, 85)
        ti_points = max(ti_points, 35.0)
        sig = mb.get("signature") or "known malware"
        added.append({"code": "THREAT_INTEL_MALWAREBAZAAR", "points": 35.0,
                      "detail": f"Catalogued on MalwareBazaar as {sig}"
                      + (f", first seen {mb['first_seen']}" if mb.get("first_seen") else "")
                      + " — a confirmed in-the-wild sample."})

    if not added:
        return risk

    risk["reasons"] = added + risk.get("reasons", [])
    risk["reasons"].sort(key=lambda r: r["points"], reverse=True)
    risk.setdefault("components", {})["threat_intel"] = round(ti_points, 1)
    if floor > risk["score"]:
        risk["escalated_by_threat_intel"] = {"from": risk["score"], "to": floor}
        risk["score"] = floor
        risk["severity"] = band(floor)
        risk["verdict_label"] = VERDICT_LABELS[risk["severity"]]
    return risk
