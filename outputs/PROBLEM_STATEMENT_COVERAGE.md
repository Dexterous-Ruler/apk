# Problem-Statement Coverage

**"Harnessing Generative AI for Automated Reverse Engineering, Static and
Dynamic Analysis, and Risk Scoring of Fraudulent Mobile Applications (APKs)
and Malwares"**

Every clause in the title, mapped to a working, verified capability.

| Required capability | Status | How APKSHIELD delivers it |
|---|---|---|
| **Generative AI** | ✅ | Claude powers two layers: the **investigation report** (verdict, MITRE, IOCs, Hindi warning — `genai_report.py`) and the **reverse-engineering** layer that reads decompiled code (`reverse_engineer.py`). Detection stays in fast trees+rules; the LLM never sets the score. |
| **Automated Reverse Engineering** | ✅ | `deep_analysis.py` builds an Androguard cross-reference graph **in-memory** (real malware never written to disk), extracts the most suspicious methods with their **smali**, and Claude **reads the actual bytecode** and reconstructs the logic — e.g. on a real Cerberus sample it recovered the AES-encrypted SMS command channel, the remote-command table, screen-recording via `/system/bin/screenrecord`, and the C2 at `cerberusapp.com/download/ping` (with the `q.a` string-deobfuscation routine). Grounded against the supplied code. |
| **Static Analysis** | ✅ | Androguard manifest/permissions/components/cert + APKiD packer detection + custom fast DEX-table parser + suspicious-API + embedded-IOC extraction + Drebin-215 ML (`apk_static.py`, `dexparse.py`, `drebin_map.py`). |
| **Dynamic Analysis** | ✅ | Real sandbox **runtime behavior** via VirusTotal multi-sandbox detonation (hash-only, never the APK): runtime C2 domains/IPs contacted at execution, dropped payloads, and MITRE techniques observed *during detonation* (`dynamic_analysis.py`). Plus a self-hosted **Frida** instrumentation script (`tools/frida_hooks.js`) and **MobSF** REST integration for live detonation when an Android instance is connected. On the Cerberus sample the sandbox **confirmed the C2 the static RE found** — static→dynamic cross-validation. |
| **Behavioral / taint analysis** *(depth bonus)* | ✅ | Source→sink data-flow over the call graph: SMS-read → network = OTP exfiltration; identity → network = fingerprint exfil; component-entry → sink trigger chains. The runtime behavior the bytecode encodes, without executing it. |
| **Risk Scoring** | ✅ | Explainable 0–100 fusion (ML + impersonation + capability combos) + **threat-intel escalation** + **dynamic escalation** (observed C2 / dropped executable raises the score). Severity bands + per-point reason codes (`risk.py`). |
| **Fraudulent Mobile Applications (APKs)** | ✅ | India-specific bank-impersonation layer (typosquat + package/cert/icon mimicry, boundary-matched, FP-tested) — `impersonation.py`. |
| **Malwares (general)** | ✅ | Validated on real in-the-wild **Hook** and **Cerberus** banking trojans (MalwareBazaar), analyzed in-memory; ML + threat-intel + RE generalize beyond fake-bank to general Android malware. |

## Architecture (fast path + deep path)

```
            suspicious.apk
                 │
   ┌─────────────┴──────────────┐
   │  FAST PATH  (<1s typical)  │   verdict renders instantly
   │  static → ML → impersonation → risk fusion → threat-intel escalation
   │  → GenAI report (async, fills in after)
   └─────────────┬──────────────┘
                 │  (on demand: "Run deep analysis")
   ┌─────────────┴──────────────┐
   │  DEEP PATH  (~20-40s)       │
   │  call-graph behavioral taint  +  GenAI reverse-engineering of the
   │  bytecode  +  dynamic sandbox runtime behavior (+ self-hosted Frida/MobSF)
   └────────────────────────────┘
```

The split keeps the live demo's verdict instant while the heavyweight
reverse-engineering and dynamic detonation run on demand.

## Honest scoping (still true, still disclosed)
- Dynamic runtime behavior is sourced from VirusTotal's sandboxes for known
  hashes; for an unknown zero-day not yet in any sandbox, the self-hosted
  Frida/MobSF harness is the path (activates with a connected emulator). We
  state this rather than imply we detonate every sample locally.
- The GenAI RE reads smali (reliable, in-memory); jadx is bundled
  (`tools/bin/jadx`) as the optional clean-Java decompiler for on-disk samples.
- The static ML model is Drebin-era; modern obfuscated trojans are caught by
  the threat-intel + dynamic + RE layers, not the static classifier alone —
  which is exactly why the design is layered.
