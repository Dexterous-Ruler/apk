"""Map a parsed APK onto the 215 Drebin-style binary features.

The training CSV's 215 columns fall into four shapes, each matched against a
different pool extracted from the APK:

1. ALL_CAPS names (SEND_SMS, NFC, /system/bin is the odd one out) ->
   manifest permission last-segments, or raw dex strings for paths/commands.
2. android.intent.action.* / intent.action.* -> manifest intent actions
   plus the dex string pool.
3. L-prefixed dotted names (Ljava.lang.Class.getMethod / Ljavax.crypto.Cipher)
   -> referenced method (class+name pair) or referenced class.
4. Short dotted names (TelephonyManager.getDeviceId, Runtime.exec,
   HttpGet.init) -> method-ref suffix match; bare identifiers (transact,
   ClassLoader, chmod) -> method-name, class-simple-name or string match.

This mirrors how the public Drebin-215 extractors behave. Exact parity with
the original dataset's (unpublished) extractor is impossible; the eval report
discloses that live extraction is an approximation of the training features.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

FEATURES_PATH = Path(__file__).parent / "drebin_features.json"

_UPPER_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def load_feature_names() -> list[str]:
    return json.loads(FEATURES_PATH.read_text())


def _last_segment(name: str) -> str:
    return name.rsplit(".", 1)[-1]


class DrebinMatcher:
    """Build once per APK from extracted pools, then evaluate all features."""

    def __init__(self, permissions: list[str], intent_actions: set[str],
                 dex_strings: set[str], classes: set[str],
                 class_simple_names: set[str], method_refs: set[str],
                 method_names: set[str]):
        # permission last segments, e.g. SEND_SMS
        self.perm_segments = {_last_segment(p) for p in permissions}
        self.intent_actions = intent_actions
        self.strings = dex_strings
        self.classes = classes
        self.class_simple = class_simple_names
        self.method_refs = method_refs
        self.method_names = method_names
        # suffix index for short-form method refs: TelephonyManager.getDeviceId
        # must match android.telephony.TelephonyManager.getDeviceId
        self._cls_meth_pairs = set()
        for ref in method_refs:
            cls, _, meth = ref.rpartition(".")
            self._cls_meth_pairs.add((_last_segment(cls), meth))

    # ---- per-shape matchers -------------------------------------------------

    def _match_permission(self, feat: str) -> bool:
        return feat in self.perm_segments

    def _match_intent(self, feat: str) -> bool:
        if feat in self.intent_actions or feat in self.strings:
            return True
        # 'intent.action.RUN' style: suffix match against full action names
        if not feat.startswith("android."):
            full = "android." + feat
            return full in self.intent_actions or full in self.strings
        return False

    def _match_l_dotted(self, feat: str) -> bool:
        body = feat[1:]  # strip leading 'L'
        last = _last_segment(body)
        if last[:1].islower():  # method: Ljava.lang.Class.getMethod
            return body in self.method_refs
        return body in self.classes  # class: Ljavax.crypto.Cipher

    def _match_short_dotted(self, feat: str) -> bool:
        head, _, last = feat.rpartition(".")
        if last[:1].islower() or last == "init":
            meth = "<init>" if last == "init" else last
            # fully-qualified class given?
            if "." in head and head[:1].islower():
                return f"{head}.{meth}" in self.method_refs
            return (_last_segment(head), meth) in self._cls_meth_pairs
        # class reference, fully qualified: android.os.Binder,
        # android.content.pm.Signature, android.telephony.gsm.SmsManager.
        # Match on actual TYPE references only — not the raw string pool, which
        # over-fires (every referenced class name also appears as a string)
        # and skews inference away from the reference-based training features.
        return feat in self.classes

    def _match_bare(self, feat: str) -> bool:
        if feat.startswith("/"):  # /system/bin, /system/app
            return any(feat in s for s in self.strings if "/" in s)
        if feat[:1].islower():  # method name or shell command (e.g. chmod, su)
            # shell commands legitimately live in the string pool, so the
            # string fallback stays here (but not for class-name shapes).
            return feat in self.method_names or feat in self.strings
        # capitalized simple class name: ClassLoader, ProcessBuilder, IBinder —
        # match on referenced type names, not the raw string pool.
        return feat in self.class_simple

    # ---- public -------------------------------------------------------------

    def match(self, feat: str) -> bool:
        if feat.startswith("/"):
            return self._match_bare(feat)
        if _UPPER_RE.match(feat):
            # permission-shaped; a few (NFC, CAMERA) are also literal strings
            return self._match_permission(feat)
        if feat.startswith(("android.intent.", "intent.action.")):
            return self._match_intent(feat)
        if feat.startswith(("Ljava", "Ljavax", "Landroid", "Lorg", "Lcom")):
            return self._match_l_dotted(feat)
        if "." in feat:
            return self._match_short_dotted(feat)
        return self._match_bare(feat)

    def vector(self, feature_names: list[str] | None = None) -> dict[str, int]:
        names = feature_names or load_feature_names()
        return {f: int(self.match(f)) for f in names}
