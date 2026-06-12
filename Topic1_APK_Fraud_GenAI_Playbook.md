# Topic 1 — Generative-AI-Based Automated Analysis & Risk Scoring of Fraudulent APKs
## Winning Completion Playbook

> **Goal of this document:** a complete, execution-ready blueprint to win the *"GenAI-Based Automated Analysis and Risk Scoring of Fraudulent APKs"* problem statement. It is built from a **verified** research sweep of the tooling, datasets, GenAI techniques, and — crucially — the **actual public submissions to the National CyberShield Hackathon 2025 "Fake Banking APK Detector"** problem (the closest real-world precedent to this exact track).
>
> **The one-line winning thesis:** *Pure ML accuracy does NOT win this track. A **working live demo** (upload APK → static analysis → 0–100 risk score → explainable verdict) + an **India fraud narrative** + **multi-signal impersonation proof** + a **cheap GenAI explanation/triage layer** + **honest, time-aware evaluation** is the recipe that wins.*

---

## 0. TL;DR — The 9 moves that win this track

1. **Ship a working end-to-end demo, not a notebook.** Upload an APK → verdict + reasons in <30 s. Judges reward "show, don't tell." Have a **recorded fallback video**.
2. **Hour-1 baseline:** clone [`haripatel07/android-malware-detector`](https://github.com/haripatel07/android-malware-detector) (Androguard → 215 Drebin features → RandomForest, ships a trained model) to get an instant upload→verdict demo, then iterate.
3. **Build on the right foundations:** **MobSF** (21.2k★) for deep static+dynamic + REST API; **Androguard** (6.1k★) as your own feature extractor.
4. **Differentiate with MULTI-SIGNAL impersonation detection** (the fake-*bank* winner): typosquat name distance, package-keyword heuristics, **official-bank package + signing-cert allowlist**, icon perceptual hash, APK SHA-256 vs official binary. This is what separates "generic malware classifier" from "fake-BANK detector."
5. **Make GenAI the explanation/triage layer** (maps to the topic name): use a cheap LLM (e.g. GPT-4o-mini, ~$0.20/APK via **LAMD-style context slicing**) to turn the verdict + features into a plain-language, **MITRE ATT&CK-mapped** risk report (+ Hindi/Tamil/Telugu scam explanations). Keep *detection* in fast trees.
6. **Add production-credible signals pure-ML teams skip:** Google **Play Integrity API** (sideload/tamper), **VirusTotal/MalwareBazaar** threat-intel, MobSF dynamic. Reads as "deployable," not "toy."
7. **Banking-trojan red-flag permission cheat-sheet:** `BIND_ACCESSIBILITY_SERVICE` + `SYSTEM_ALERT_WINDOW` (overlay) + `RECEIVE_SMS/READ_SMS` (OTP theft) + device-admin + `RECEIVE_BOOT_COMPLETED`. Narrate these.
8. **Evaluate honestly:** precision/recall/F1/FPR + confusion matrix under a realistic ~90% benign ratio; dedup repacked APKs; **time-aware (TESSERACT/AUT) split**. Never quote accuracy alone.
9. **GenAI reliability add-on:** a **hallucination/grounding check** (LAMD's Data-Relationship-Coverage), cost/latency numbers, and a fully-local Ollama path for "can't send malware to the cloud." Don't tell the model the sample is malicious (it biases every function as suspicious).

---

## 1. Problem statement (as given)

> Fraudsters distribute malicious APKs via WhatsApp/SMS/email/phishing to steal credentials and perform unauthorized transactions. Manual analysis is slow and expert-dependent. Build a **GenAI-powered malware analysis system** that automatically analyzes suspicious APKs and identifies malicious behavior — leveraging GenAI for **reverse engineering, malware pattern recognition, automated code interpretation, and intelligent threat summarization**, alongside **static and dynamic analysis** of permissions, APIs, embedded code, runtime activities, and network communications. Output: **detect malware patterns, classify threat severity, generate risk scores, and produce detailed investigation reports with actionable recommendations.**

**No dataset is provided for this topic** — you supply APK samples (benign + malicious). See §6 for where to get them.

---

## 2. The winning recipe (from real National CyberShield 2025 submissions)

The closest precedent to this exact problem statement is the **National CyberShield Hackathon 2025 "Fake Banking APK Detector"**. Public submissions + a participant's writeup converge on a clear winning stack:

> **React Native / Next.js frontend + FastAPI/Flask backend + Androguard + scikit-learn/XGBoost + GPT-4o-mini (explanations) + VirusTotal + MobSF + Play Integrity API.**

**The cross-cutting lesson:** the win came from a **full, clickable end-to-end app** with a clean *upload → verdict → confidence → threat-factors* UI, an **India fraud narrative**, **multi-signal impersonation proof**, and explainability — **not** from a higher accuracy number.

> ⚠️ **Honest caveat for your slides:** the most-cited submission (`adityashriwas/BankShield`) was *selected at* the hackathon (not confirmed 1st place) and trained on **synthetic data** with ~85–90% claimed accuracy. Use it as an **architecture template**, not as metrics to trust. Treat all 99–100% accuracy claims skeptically (they're random-split numbers that collapse under time-aware evaluation).

---

## 3. Winning architecture (layered — ship inner layers first)

```
                       suspicious.apk (uploaded / from WhatsApp link)
                                        │
        ┌───────────────────────────────┼────────────────────────────────┐
        ▼                               ▼                                ▼
[A] STATIC ANALYSIS         [B] IMPERSONATION CHECK          [C] THREAT INTEL
  Androguard:                 (the fake-BANK differentiator)    VirusTotal hash/URL
  - permissions, intents      - typosquat name distance         MalwareBazaar family
  - components, API calls      (Levenshtein/TheFuzz)            WHOIS on exfil domains
  - signing certificate        - package-keyword heuristics     Play Integrity verdict
  - embedded URLs/IPs          - official pkg + CERT allowlist    (sideload/tamper)
  - APKiD packer/obfuscator    - icon perceptual hash
        │                       - APK SHA-256 vs official
        ▼                               │                                │
[D] ML RISK MODEL  ◄─────────────────────┴────────────────────────────────┘
  RandomForest / XGBoost on 215 Drebin-style features → P(malicious)
  → fuse with weighted impersonation score → 0–100 RISK SCORE + severity band
        │
        ▼
[E] GENAI EXPLANATION + TRIAGE LAYER   (maps to the "GenAI" in the topic title)
  LLM (GPT-4o-mini / local Ollama) with LAMD-style context slicing:
  - plain-language verdict + WHY (reason codes)
  - MITRE ATT&CK technique mapping + IOC extraction
  - multilingual scam explanation (Hindi/Tamil/Telugu)
  - hallucination/grounding check (Data-Relationship-Coverage)
        │
        ▼
[F] INVESTIGATION REPORT + ALERT
  severity, risk score, evidence, recommendations, takedown/CERT-In evidence kit
        │
        ▼   (STRETCH)
[G] DYNAMIC ANALYSIS: MobSF + Frida in a sandbox/emulator → runtime API + network capture
```

**Scope realistically:** lead with **A→B→C→D→E→F** (achievable in a weekend). Position **G (dynamic)**, GNN/CNN, and agentic-RE/decompilation as **stretch goals**. A clean, explainable, honestly-evaluated baseline beats a fragile SOTA clone.

---

## 4. Layer details

### [A] Static analysis (the de-facto baseline everyone uses)
Use **Androguard** `AnalyzeAPK()` to extract:
- **Permissions** (binary vector over ~330 standard permissions; **total permission count** and **unidentified/proprietary permission count** are consistently the *top-weighted* features — per DroidDetective).
- **Intents, components** (activities/services/receivers/providers), **restricted/suspicious API calls**, **opcodes**.
- **Signing certificate** (issuer, validity, self-signed flag) — powers the cert allowlist.
- **Embedded URLs/IPs** — feed threat-intel.
- **APKiD** packer/obfuscation fingerprint — a high-signal feature *and* a router (packed → static unreliable → trigger dynamic).

**Banking-trojan red-flag permission cheat-sheet (memorize for the demo):**
| Permission | Why it's a fake-bank signal |
|---|---|
| `BIND_ACCESSIBILITY_SERVICE` | Auto-grant permissions, read screen, auto-fill — SOVA/Anubis hallmark |
| `SYSTEM_ALERT_WINDOW` | Overlay fake login screens on real bank apps |
| `RECEIVE_SMS` / `READ_SMS` | Steal OTPs |
| `REQUEST_INSTALL_PACKAGES`, device-admin | Drop payloads, block uninstall |
| `RECEIVE_BOOT_COMPLETED` | Persistence across reboots |

### [B] Multi-signal impersonation detection — *the differentiator*
A repackaged clone of a real bank app may have "normal" permissions; you must **prove impersonation**:
1. **Typosquat name similarity** (Levenshtein / TheFuzz): "PhonPay" vs "PhonePe", "SBl" vs "SBI".
2. **Package-id keyword heuristics:** `com.sbi.*` claims but cert ≠ official SBI cert.
3. **Official-bank allowlist (highest ROI, build-it-yourself):** a small table of legit Indian bank/UPI package names + signing-cert SHA-256 fingerprints (SBI, ICICI, HDFC, PhonePe, GPay, BHIM). Trivial to assemble, powers the verdict.
4. **Icon/logo perceptual hash** (Pillow + ImageHash) vs official icons.
5. **APK SHA-256** vs known-official binaries.
→ Combine into a **weighted 0–100 risk score** (steal the model from [`Gaurang-5/fake-app-detector`](https://github.com/Gaurang-5/fake-app-detector)).

### [C] Threat-intel enrichment (production credibility)
- **VirusTotal** (hash + embedded URL/domain reputation), **MalwareBazaar/ThreatFox** (real samples + IOCs), **WHOIS** on exfil domains.
- **Google Play Integrity API**: `appLicensingVerdict` (installed from Play vs sideloaded), `appIntegrity` (tampered), `playProtectVerdict`. Indian fake-bank APKs are almost always **sideloaded via WhatsApp/SMS**, so "was this from the Play Store?" is a high-precision signal.

### [D] ML risk model
- **Drebin 215-feature** static vector → **RandomForest / XGBoost** (90–99% on standard splits; fast; native feature importances). This is the practical sweet spot — reach for GNN/CNN/BERT only as a stretch.
- Explainability: **SHAP / `feature_importances_`** → "flagged because: SEND_SMS + accessibility + overlay + self-signed cert + package mimics `com.sbi.*`."

### [E] GenAI layer (this is what makes it a *GenAI* solution)
Keep detection in fast trees; use the LLM where it shines — **interpretation, summarization, triage, reporting**:
- **LAMD context-engineering pattern** (the standout technique): collect suspicious APIs (FlowDroid/PScout/SuSi) → **backward slicing** to isolate only relevant instructions → **tier-wise summarization** (function → API-intent-in-context → APK verdict). Lets a cheap GPT-4o-mini analyze whole APKs at **~$0.20/APK**, hitting ~90% F1 (vs Drebin 81%) with far lower false-negatives.
- **Triage + MITRE ATT&CK mapping + IOC extraction + analyst report** (use [`malwoverview`](https://github.com/alexandreborges/malwoverview) `--llm`, or a CrewAI two-agent split: Triage Analyst + Threat-Intel Analyst).
- **Hallucination grounding (mandatory):** reconstruct variable/data dependencies → compute a **Data-Relationship-Coverage** metric vs a threshold; reject/redo summaries that fail. *Demo a caught hallucination* — judges love it.
- **Agentic RE (stretch):** [`GhidrAssist`](https://github.com/jtang613/GhidrAssist) / [`Gepetto`](https://github.com/JusticeRage/Gepetto) / [`LLM4Decompile`](https://github.com/albertan017/LLM4Decompile) for native `.so` analysis.
- **Prompt discipline:** *don't* tell the model "this is malware" (biases it); use neutral behavior description, then judge maliciousness separately. Resist naive RAG — a 2026 study found generic RAG over MITRE/VT docs often *lowers* explanation quality; if you RAG, use a strong embedder + tight thresholds and A/B test it.

### [G] Dynamic analysis (stretch)
**MobSF** dynamic module + **Frida** hooks in a rooted AVD/Genymotion; capture runtime API calls, network (tcpdump → pcap, ~80 CICFlowMeter flow features), logcat. Use **CuckooDroid** as a design reference. Watch for anti-emulator/anti-Frida evasion; use UI fuzzing (Monkey/DroidBot) for coverage. **Demo safety: never execute droppers on the demo machine — sandbox/VM, static IOC extraction only.**

---

## 5. Verified reference repos

> All verified live (stars/status from the research run). Clone the **template** ones first.

**Foundations / tooling**
| Repo | Stars | Use |
|---|---|---|
| [MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | 21.2k | All-in-one static+dynamic; use its **REST API** as a feature/threat-intel backend |
| [androguard/androguard](https://github.com/androguard/androguard) | 6.1k | Your programmatic static feature extractor (`AnalyzeAPK()`) |
| [rednaga/APKiD](https://github.com/rednaga/APKiD) | 2.5k | Packer/obfuscator fingerprint (`pip install apkid`) |
| [skylot/jadx](https://github.com/skylot/jadx) | — | DEX→readable Java for triage/demo |
| [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool) | — | Unpack/disassemble→smali, repackage |
| [frida/frida](https://github.com/frida/frida) | — | Runtime hooking for dynamic analysis |

**Fake-bank / hackathon templates (clone these — directly on-topic)**
| Repo | Stars | Use |
|---|---|---|
| [haripatel07/android-malware-detector](https://github.com/haripatel07/android-malware-detector) | — | **Hour-1 baseline:** Androguard 215-feat → RandomForest + shipped Drebin model |
| [adityashriwas/BankShield-Detecting-Fake-banking-APKs](https://github.com/adityashriwas/BankShield-Detecting-Fake-banking-APKs) | 3 | Direct CyberShield 2025 submission; Next.js+Flask+Androguard+ensemble, clickable demo. *Architecture template (synthetic-data metrics — don't trust numbers)* |
| [Aditya-Coder477/Full_Fake_Bank_APK_Detector](https://github.com/Aditya-Coder477/Full_Fake_Bank_APK_Detector) | — | Most feature-complete: Androguard + sklearn + multi-Indian-language + FastAPI/Streamlit |
| [Gaurang-5/fake-app-detector](https://github.com/Gaurang-5/fake-app-detector) | — | **Best multi-signal counterfeit scoring** — steal this model |
| [AnushaHardaha/APK-Detector (Cryptera)](https://github.com/AnushaHardaha/APK-Detector) | 2 | VirusTotal + MalwareBazaar threat-intel wired into a web verdict UI |
| [Aathish04/RevEng-Android-Scam-App](https://github.com/Aathish04/RevEng-Android-Scam-App) | — | Real ICICI-impersonation teardown (jadx/Genymotion/Burp) — **high-impact demo opener** |
| [user1342/DroidDetective](https://github.com/user1342/DroidDetective) | 139 | Permission-only RF + pretrained model; cite its top-feature insight |

**ML / DL approaches (stretch tracks)**
| Repo | Stars | Use |
|---|---|---|
| [s2labres/tesseract-ml-release](https://github.com/s2labres/tesseract-ml-release) | 20 | **Time-aware eval** (`time_aware_train_test_split`, AUT metric) — *credibility multiplier* |
| [vinayakakv/android-malware-detection](https://github.com/vinayakakv/android-malware-detection) | 39 | GCN on Function Call Graphs (obfuscation-resistant track; archived — adapt) |
| [Kartikaggarwal98/Android_MalwareAnalysis](https://github.com/Kartikaggarwal98/Android_MalwareAnalysis) | 22 | Bytecode→grayscale-image + CNN — *visually demoable* "malware fingerprint" |

**GenAI for malware / RE**
| Repo | Stars | Use |
|---|---|---|
| [albertan017/LLM4Decompile](https://github.com/albertan017/LLM4Decompile) | 6.7k | LLM decompilation/refinement of native libs (local, pip-installable) |
| [alexandreborges/malwoverview](https://github.com/alexandreborges/malwoverview) | 3.9k | Threat-intel across VT/HA/Triage/MalwareBazaar/ThreatFox **with `--llm` enrichment** (risk, family, ATT&CK, IOCs) — drop-in GenAI triage |
| [jtang613/GhidrAssist](https://github.com/jtang613/GhidrAssist) | 665 | Agentic RE (Ghidra + MCP tool-calling + Graph-RAG) |
| [JusticeRage/Gepetto](https://github.com/JusticeRage/Gepetto) | 3.4k | IDA Pro LLM plugin (explain functions, auto-rename) |
| [llnl/OGhidra](https://github.com/llnl/OGhidra) | — | Ghidra + **Ollama (fully local)** — answer to "can't send malware to cloud" |
| [tmylla/Awesome-LLM4Cybersecurity](https://github.com/tmylla/Awesome-LLM4Cybersecurity) | 1.5k | 612+ papers — jump-off point for more GenAI-for-malware ideas |

---

## 6. Datasets & live samples

| Dataset | What | Note |
|---|---|---|
| **Drebin (215-feature CSV)** | ~15,036 apps (5,560 malware + 9,476 benign), 8-category static scheme | Fastest ML baseline. Use a [Kaggle mirror](https://www.kaggle.com/datasets/shashwatwork/android-malware-dataset-for-machine-learning) (official TU-BS page needs access request) |
| **CICMalDroid 2020** | ~17,341 APKs, 5 classes incl. **Banking** & **SMS** malware; ready static/dynamic CSVs | The **Banking class maps directly** to this theme. [UNB CIC](https://www.unb.ca/cic/datasets/maldroid-2020.html) / [Kaggle](https://www.kaggle.com/datasets/rianadr/android-malware-dataset-cicmaldroid-2020) |
| **AndroZoo** | ~24M APKs, VirusTotal-scanned, **timestamped** | Essential for the **time-aware/TESSERACT** concept-drift eval; free researcher API key. [androzoo.uni.lu](https://androzoo.uni.lu/) |
| **CCCS-CIC-AndMal-2020** | ~400K apps, 14 categories, 191 families | Large multi-class family benchmark (harder) |
| **MalwareBazaar / ThreatFox** | Live real APK samples + IOCs (SOVA/Anubis banking trojans) | [bazaar.abuse.ch](https://bazaar.abuse.ch) — demo on a *real* fake-bank sample |
| **Official-bank allowlist** | *Build it yourself* | Curated legit Indian bank/UPI package names + cert SHA-256 — powers impersonation verdict |

---

## 7. Evaluation (honest = credibility)
- Report **precision / recall / F1 / FPR + confusion matrix** under a **realistic ~90% benign** ratio — *never accuracy alone* (balanced toy splits inflate to 99%).
- **Dedup repacked near-duplicate APKs** across the split (else you over-report).
- **Time-aware split** (TESSERACT / AUT metric): train on past, test on future — exposes concept drift. *Stating you avoided spatial + temporal + leakage bias beats a higher leaderboard number with expert judges.*
- For GenAI: use **re-executability / behavior-match** for decompilation quality (not BLEU); report **false-negative rate**; have **cost/latency numbers** ready (~$0.20/APK GPT-4o-mini; local Ollama path).

---

## 8. Judging criteria & how to score on each

| Criterion | What judges look for | Your move |
|---|---|---|
| **Working demo > metrics** | Live upload→verdict→reasons in <30 s | Polished UI + recorded fallback video |
| **Domain "so-what"** | Real Indian fraud tie + deployment path | Fake SBI/ICICI/HDFC/UPI via WhatsApp; CERT-In/police reporting + takedown evidence kit |
| **Explainability** | WHY flagged, not just a score | SHAP/feature-importance + LLM reason codes |
| **Honest evaluation** | Precision/recall/FPR, realistic ratio, time-aware split | The §7 discipline + confusion matrix |
| **Robustness awareness** | Obfuscation/packing, adversarial evasion | APKiD + dynamic fallback; mention graph/hybrid features |
| **Production signals** | Play Integrity, cert allowlist, MobSF/VT | Wire at least one |
| **GenAI rigor** | Grounding/hallucination check, cost transparency, human-in-the-loop | Demo a caught hallucination; "force-multiplier, not autonomy" |

**Pitfalls that kill teams:** accuracy theater (99% on stale Drebin); calling rule heuristics "AI/DNA fingerprinting" without substance (security judges probe); doing only malware classification when the problem is **impersonation**; telling the LLM "this is malware"; executing live droppers on the demo machine; naive RAG.

---

## 9. Demo & pitch strategy (the narrative that wins)
1. **Open with a real teardown** (Aathish04-style): a WhatsApp-distributed fake-ICICI APK exfiltrating to `/add.php` on free hosting. Makes the threat **visceral**.
2. **Cite credibility:** CERT-In / Cyber Swachhta Kendra **SOVA** advisory (Android banking trojan targeting 200+ apps incl. Indian banks via smishing, abusing accessibility).
3. **Live demo:** upload the sample → static analysis → impersonation check → risk score 0–100 → **GenAI plain-language report** with MITRE ATT&CK mapping + Hindi explanation.
4. **Show explainability + production signals:** "flagged because sideloaded (Play Integrity) + accessibility+overlay+SMS + self-signed cert + `com.sbi.*` mimicry + VT 12/60 detections."
5. **Impact layer:** auto-generated **CERT-In/police takedown evidence kit** + user-facing "this is NOT the official bank app → here's the real Play Store link."
6. **Roadmap:** MobSF dynamic, GNN on call graphs, on-device pre-install scanning.

---

## 10. Tech stack (copy-paste)
- **Static/RE:** Androguard, apktool, jadx, APKiD, FlowDroid (taint), Frida (dynamic)
- **ML:** scikit-learn (RandomForest), XGBoost/LightGBM, SHAP, pandas/joblib
- **Impersonation:** TheFuzz (Levenshtein), Pillow + ImageHash (icon hash)
- **Threat-intel:** VirusTotal API, MalwareBazaar/ThreatFox, Play Integrity API, WHOIS
- **GenAI:** GPT-4o-mini (cheap, context-efficient) or Claude (best tool-use) via LiteLLM gateway; **Ollama** (Devstral/Qwen-coder/DeepSeek) for fully-local; CrewAI/LangGraph for multi-agent triage; MITRE ATT&CK for mapping
- **App:** FastAPI/Flask backend (`/analyze` endpoint) + React Native (Expo) or Next.js frontend; Streamlit for a fast analyst dashboard; SQLite/PostgreSQL for scan logs; Docker for reproducible demo
- **Smishing module (bonus):** TF-IDF + RandomForest, or IndicBERT for Indian-language/code-mixed SMS lure classification

---

## 11. Hour-by-hour plan (~2-day hackathon)
| Phase | Deliverable |
|---|---|
| **H0–2** | Clone `haripatel07/android-malware-detector`; get upload-APK → verdict working locally |
| **H2–5** | Wrap in FastAPI + minimal web UI; integrate Androguard custom feature extractor; APKiD |
| **H5–9** | **Impersonation layer** (typosquat + cert allowlist + icon hash) — your differentiator |
| **H9–13** | **GenAI report layer** (LLM verdict→reason codes→MITRE ATT&CK + multilingual) + grounding check |
| **H13–17** | Threat-intel (VT/MalwareBazaar) + Play Integrity; honest eval (time-aware split, confusion matrix) |
| **H17–22** | MobSF dynamic (stretch); polish UI; takedown evidence kit; real-sample demo |
| **H22–24** | Pitch deck, recorded demo video, rehearse the §9 narrative |

---

## 12. Key references (verified)
- DroidDissector — dual static+dynamic blueprint (arXiv 2308.04170): https://arxiv.org/html/2308.04170
- LAMD — *Context-driven Android Malware Detection with LLMs* (DLSP 2025): https://arxiv.org/html/2502.13055 · PDF: https://s2lab.cs.ucl.ac.uk/downloads/DLSP2025_LLM_enhanced_malware_detection.pdf
- TESSERACT — *Eliminating Experimental Bias in Malware Classification* (USENIX Sec 2019): https://www.usenix.org/system/files/sec19fall_pendlebury_prepub.pdf
- Cisco Talos — *Using LLMs as a reverse engineering sidekick*: https://blog.talosintelligence.com/using-llm-as-a-reverse-engineering-sidekick/
- MalLoc — fine-grained payload localization via LLMs: https://www.themoonlight.io/en/review/malloc-toward-fine-grained-android-malicious-payload-localization-via-llms
- *Evaluating RAG for Explainable Malware Analysis* (RAG can degrade quality): https://arxiv.org/html/2605.03140
- CERT-In / Cyber Swachhta Kendra **SOVA** advisory: https://www.csk.gov.in/alerts/SOVA.html
- National CyberShield Hackathon 2025 (CII): https://ciisummit.com/wp-content/uploads/2025/08/National-CyberShield-Hackathon-2025.pdf
- Play Integrity API (Android Developers): https://developer.android.com/google/play/integrity/overview

---
*Generated from a multi-agent verified research sweep (tooling, datasets, GenAI techniques, and real National CyberShield 2025 fake-banking-APK submissions). All repo links were fetched/verified during research.*
