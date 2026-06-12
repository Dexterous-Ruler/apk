"""Impersonation detection — the fake-BANK differentiator.

A repackaged clone of a real banking app can look permission-normal; what
betrays it is identity: it *claims* to be a bank it cannot prove it is.
Signals, each contributing to a weighted 0-100 impersonation score with
per-signal evidence:

  S1 identity claim   — package equals an official banking package. With a
                        pinned cert: mismatch = critical. Without: the claim
                        is unverifiable -> strong suspicion for a sideloaded
                        file (the official app comes from the Play Store).
  S2 typosquat name   — app display name within fuzzy-match distance of an
                        official app/bank name without being the real package
                        ("YON0 SBI", "PhonPay").
  S3 package mimicry  — package id contains a bank keyword but is not the
                        official package (com.sbi.kyc.update).
  S4 lure keywords    — kyc/refund/reward/verify... in the visible name or
                        package: the social-engineering wrapper.
  S5 icon clone       — perceptual-hash distance to a pinned official icon.
  S6 junk certificate — bank-flavored identity signed by a debug/empty/
                        freshly-minted self-signed cert.

Verdicts: "official" (package+cert verified), "impersonation_critical",
"suspicious_identity", "no_identity_claim".
"""
from __future__ import annotations

import io
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from thefuzz import fuzz

try:
    import imagehash
    from PIL import Image
    HAVE_IMAGEHASH = True
except ImportError:  # pragma: no cover
    HAVE_IMAGEHASH = False

ALLOWLIST_PATH = Path(__file__).parent / "bank_allowlist.json"

ICON_PHASH_MAX_DISTANCE = 10   # <=10 bits of 64 = visually same logo family
NAME_STRONG = 85               # fuzz ratio: near-identical name
NAME_WEAK = 70                 # fuzz ratio: clearly derivative name


def load_allowlist() -> dict:
    return json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))


def icon_phash(icon_bytes: bytes) -> str | None:
    if not (HAVE_IMAGEHASH and icon_bytes):
        return None
    try:
        img = Image.open(io.BytesIO(icon_bytes)).convert("RGBA")
        return str(imagehash.phash(img))
    except Exception:
        return None


def _phash_distance(h1: str, h2: str) -> int:
    return bin(int(h1, 16) ^ int(h2, 16)).count("1")


def _norm(s: str | None) -> str:
    return re.sub(r"[^a-z0-9 ]", "", (s or "").lower()).strip()


@dataclass
class ImpersonationResult:
    score: int = 0
    verdict: str = "no_identity_claim"
    claimed_bank: str | None = None
    signals: list[dict] = field(default_factory=list)
    icon_phash: str | None = None

    def add(self, signal: str, points: int, evidence: str) -> None:
        self.signals.append(
            {"signal": signal, "points": points, "evidence": evidence})
        self.score = min(100, self.score + points)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "claimed_bank": self.claimed_bank,
            "signals": self.signals,
            "icon_phash": self.icon_phash,
        }


# Generic words that must NEVER, on their own, trigger a bank-impersonation
# claim (they appear in countless benign app names/packages).
GENERIC_TOKENS = {"google", "pay", "bank", "mobile", "app", "india", "online",
                  "secure", "plus", "lite", "wallet", "money", "chrome",
                  "update", "service", "the", "my", "go", "one"}
# Unambiguous brand tokens: if one of these appears as a whole word in the app
# name AND the package corroborates, that's a real impersonation signal.
DISTINCTIVE_TOKENS = {"yono", "phonepe", "paytm", "imobile", "bhim",
                      "indusmobile", "fedmobile", "kotak811", "imobilepay",
                      "icici", "hdfc", "kotak", "canara", "axis", "sbi"}


def _word_tokens(s: str | None) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", (s or "").lower()))


def _pkg_keyword_hits(package: str, keywords: list[str]) -> list[str]:
    """Bank keywords that appear in the package id with a real boundary:
    a short token (<4) must be an EXACT dot-segment (e.g. '...sbi...'), a
    longer token may also match a sub-token — but never a mere substring,
    so 'com.piggybank.game' does not match 'bank'."""
    pkg_l = package.lower()
    dot_segs = set(pkg_l.split("."))
    sub_tokens: set[str] = set()
    for seg in dot_segs:
        sub_tokens |= set(re.findall(r"[a-z]+", seg))
    hits = []
    for k in keywords:
        if k in dot_segs:                       # exact segment, any length
            hits.append(k)
        elif len(k) >= 4 and k in sub_tokens:   # boundary sub-token, len>=4
            hits.append(k)
    return hits


def check_impersonation(package: str | None, app_name: str | None,
                        certs: list[dict], icon_bytes: bytes | None = None,
                        allowlist: dict | None = None) -> ImpersonationResult:
    al = allowlist or load_allowlist()
    apps = al["apps"]
    res = ImpersonationResult()
    res.icon_phash = icon_phash(icon_bytes) if icon_bytes else None

    package = package or ""
    name_n = _norm(app_name)
    pkg_l = package.lower()
    cert_sha = (certs[0].get("sha256") if certs and "sha256" in certs[0]
                else None)

    official = next((a for a in apps if a["package"] == package), None)

    # ---- S1: claims an official package -----------------------------------
    if official:
        res.claimed_bank = official["bank"]
        pinned = official.get("cert_sha256")
        if pinned and cert_sha == pinned:
            res.verdict = "official"
            res.add("official_verified", 0,
                    f"Package {package} signed with the pinned official "
                    f"{official['bank']} certificate.")
            return res
        if pinned and cert_sha != pinned:
            res.add("cert_mismatch", 60,
                    f"Package claims to be official {official['bank']} app "
                    f"({package}) but is signed by a DIFFERENT certificate "
                    f"({(cert_sha or '?')[:16]}… vs pinned {pinned[:16]}…). "
                    "This is a repackaged clone.")
        else:
            # No pinned cert to compare against. The genuine app legitimately
            # uses this package, so we must NOT flag it as suspicious on the
            # package alone (that false-positives the real bank app). Record
            # the claim as unverifiable (0 points); other signals (junk cert,
            # name mismatch, lures) still escalate a real clone below.
            official_name = _norm(official["app_names"][0])
            name_matches = (name_n and official["app_names"]
                            and fuzz.ratio(name_n, official_name) >= NAME_STRONG)
            if name_matches:
                res.add("identity_plausible_official", 0,
                        f"Package and app name both match the official "
                        f"{official['bank']} app. Identity cannot be "
                        "cryptographically verified (no pinned certificate on "
                        "record); confirm via the Play Store listing.")
            else:
                res.add("official_package_name_mismatch", 25,
                        f"Package id {package} is the official "
                        f"{official['bank']} package, but the app name "
                        f"('{app_name}') is not the official one — consistent "
                        "with a repackaged clone reusing the package id.")

    # package keyword hits (boundary-aware) are reused by S2 and S3
    pkg_kw_hits = _pkg_keyword_hits(package, al["bank_keywords"]) if not official else []
    name_tokens = _word_tokens(app_name)

    # ---- S2: typosquat display name ---------------------------------------
    # Two ways to match, both requiring the package to NOT be the official one:
    #  (a) the whole name is near-identical to an official app name (full
    #      similarity), or
    #  (b) a DISTINCTIVE brand token appears as a whole word in the name AND
    #      the package corroborates (bank keyword present) — this coupling is
    #      what stops "INDIE Music Player" matching IndusInd on one token.
    best_full, best_app = 0, None
    token_app = None
    for a in apps:
        if a["package"] == package:
            continue
        for cand in a["app_names"]:
            cand_n = _norm(cand)
            full = fuzz.ratio(name_n, cand_n) if name_n else 0
            if full > best_full:
                best_full, best_app = full, a
        brand = {t for t in _word_tokens(" ".join(a["app_names"]))
                 if t in DISTINCTIVE_TOKENS} & name_tokens
        if brand and pkg_kw_hits:
            token_app = (a, sorted(brand)[0])

    # S2 only applies to NON-official packages (an official package's identity
    # is fully handled by S1 — otherwise a genuine app trips on resembling a
    # sibling app from the same bank).
    if not official and best_app and best_full >= NAME_STRONG:
        res.claimed_bank = res.claimed_bank or best_app["bank"]
        res.add("typosquat_name_strong", 30,
                f"App name '{app_name}' is near-identical ({best_full}%) to "
                f"official '{best_app['app_names'][0]}' ({best_app['bank']}) "
                f"but the package ({package or '?'}) is not the official one "
                f"({best_app['package']}).")
    elif not official and token_app:
        a, tok = token_app
        res.claimed_bank = res.claimed_bank or a["bank"]
        res.add("brand_token_in_name", 25,
                f"App name '{app_name}' carries the {a['bank']} brand token "
                f"'{tok}' and the package mimics a bank — consistent with a "
                f"fake {a['bank']} app.")
    elif not official and best_app and best_full >= NAME_WEAK:
        # weak resemblance: record it, but do NOT claim a specific bank in the
        # headline (avoids false 'impersonates X' on coincidental names).
        res.add("name_resemblance_weak", 10,
                f"App name '{app_name}' loosely resembles ({best_full}%) "
                f"'{best_app['app_names'][0]}' ({best_app['bank']}); "
                "not conclusive on its own.")

    # ---- S3: package-id mimicry -------------------------------------------
    if not official and pkg_kw_hits:
        specific = [k for k in pkg_kw_hits if k not in {"bank", "upi", "netbanking"}]
        if specific:
            res.claimed_bank = res.claimed_bank or specific[0].upper()
        res.add("package_mimicry", 18,
                f"Package id '{package}' contains banking token(s) "
                f"{pkg_kw_hits} as a path segment but is not an official "
                "banking package.")

    # ---- S4: social-engineering lure keywords ------------------------------
    lures = sorted({k for k in al["lure_keywords"]
                    if k in name_n.replace(" ", "") or k in pkg_l})
    if lures and (res.claimed_bank or res.signals):
        res.add("lure_keywords", min(20, 10 * len(lures)),
                f"Scam-lure keyword(s) {lures} in the app name/package — "
                "classic 'KYC update / reward points' social-engineering "
                "wrapper.")

    # ---- S5: icon clone -----------------------------------------------------
    if res.icon_phash:
        for a in apps:
            pinned_icon = a.get("icon_phash")
            if not pinned_icon:
                continue
            dist = _phash_distance(res.icon_phash, pinned_icon)
            if dist <= ICON_PHASH_MAX_DISTANCE and a["package"] != package:
                res.claimed_bank = res.claimed_bank or a["bank"]
                res.add("icon_clone", 25,
                        f"App icon is visually near-identical (hamming "
                        f"distance {dist}/64) to the official "
                        f"{a['bank']} icon, but this is not the official "
                        "app.")
                break

    # ---- S6: junk certificate on a bank-flavored identity ------------------
    if res.signals and certs and "subject" in certs[0]:
        subj = certs[0]["subject"] or ""
        self_signed = certs[0].get("self_signed", False)
        looks_junk = (
            "Android Debug" in subj
            or len(_norm(subj)) <= 20
            or subj.strip().lower() in ("common name: android",
                                        "common name: unknown"))
        if self_signed and looks_junk:
            res.add("junk_certificate", 15,
                    f"Bank-flavored app signed with a throwaway self-signed "
                    f"certificate ('{subj[:80]}') — no bank releases an app "
                    "signed like this.")

    # ---- verdict ------------------------------------------------------------
    scoring_signals = [s for s in res.signals if s["points"] > 0]
    if any(s["signal"] == "cert_mismatch" for s in res.signals):
        res.verdict = "impersonation_critical"
    elif res.score >= 45:
        res.verdict = "impersonation_critical"
    elif res.score >= 15:
        res.verdict = "suspicious_identity"
    elif scoring_signals:
        res.verdict = "suspicious_identity"
    elif any(s["signal"] == "identity_plausible_official" for s in res.signals):
        # genuine-looking official app, identity just not cryptographically
        # verifiable — NOT suspicious.
        res.verdict = "likely_official_unverified"
    # else: stays "no_identity_claim"
    return res


if __name__ == "__main__":
    # self-test: real impersonations must score, benign apps must NOT (the
    # false-positive negatives below were found by the audit).
    GOOD_CERT = [{"subject": "CN=State Bank of India, O=SBI",
                  "sha256": "11" * 32, "self_signed": True}]
    JUNK_CERT = [{"subject": "Common Name: Android Debug",
                  "sha256": "cd" * 32, "self_signed": True}]
    cases = [
        # (expect_flagged, package, name, certs)
        (True,  "com.kyc.sbi.rewards.update", "SBl YONO Rewards", JUNK_CERT),
        (True,  "com.icici.imobile.secure", "iMobile Pay Verify", JUNK_CERT),
        (False, "com.sbi.lotusintouch", "YONO SBI", GOOD_CERT),       # genuine
        (False, "com.indie.musicplayer", "INDIE Music Player", JUNK_CERT),
        (False, "com.piggybank.game", "Piggy Bank Game", JUNK_CERT),
        (False, "com.gayiwefahilumo.zufi", "GoogleChrome", JUNK_CERT),
        (False, "org.fdroid.fdroid", "F-Droid", GOOD_CERT),
    ]
    ok = True
    for expect, pkg, name, certs in cases:
        r = check_impersonation(pkg, name, certs)
        flagged = r.verdict in ("impersonation_critical", "suspicious_identity")
        mark = "OK " if flagged == expect else "FAIL"
        if flagged != expect:
            ok = False
        print(f"[{mark}] {pkg:30s} {name:20s} -> {r.score:3d} "
              f"{r.verdict} (claims {r.claimed_bank})")
        for s in r.signals:
            print(f"        +{s['points']:2d} {s['signal']}: {s['evidence'][:80]}")
    print("ALL PASS" if ok else "SOME FAILED")
