# APKSHIELD — Solution Approach

**Problem Statement:** Harnessing Generative AI for Automated Reverse Engineering, Static and Dynamic Analysis, and Risk Scoring of Fraudulent Mobile Applications (APKs) and Malwares

**Code (GitHub):** https://github.com/Dexterous-Ruler/apk
**One-click live dashboard (Google Colab):** https://colab.research.google.com/github/Dexterous-Ruler/apk/blob/main/APKShield_Colab.ipynb

> This document is the content source for a 6–8 slide deck. Each numbered section below = one slide.

---

## Slide 1 — Title & Thesis

- **Project:** APKSHIELD — GenAI-powered forensics & risk scoring for fraudulent banking APKs.
- **The problem in one line:** Fraudsters distribute fake banking apps over WhatsApp/SMS to steal OTPs and drain accounts; manual analysis is slow and expert-dependent.
- **Our thesis:** A judge uploads a suspicious APK and gets, in seconds, an explainable **0–100 risk score** and a **GenAI-written investigation report** — produced by a single pipeline that performs static analysis, ML scoring, bank-impersonation detection, real sandbox dynamic analysis, and **LLM-driven reverse engineering of the actual bytecode**.
- **Status:** Fully working prototype — live, testable backend + dashboard (links above).

---

## Slide 2 — The Problem & Why It Is Hard

- **The threat (India-specific):** Banking-trojan families — **SOVA, Hook, Cerberus, Anubis, Octo** — masquerade as bank/UPI apps and abuse **Accessibility services + screen overlays + SMS interception** to capture credentials and OTPs, then exfiltrate to command-and-control servers.
- **Delivery:** sideloaded via WhatsApp/SMS phishing ("Update your SBI KYC"), never the Play Store.
- **Why manual analysis fails to scale:** reverse-engineering one sample takes a skilled analyst hours; banks face a continuous stream.
- **Why pure static ML fails:** modern trojans **obfuscate and load their real payload at runtime**, so it is invisible to static features (concept drift). Any single detection signal is easy to evade.
- **The gap we close:** an automated, fast, **explainable and honest** system that spans **static + dynamic + reverse engineering + risk scoring**, with Generative AI doing the interpretive heavy lifting.

---

## Slide 3 — Solution Approach: Layered, Two-Speed Pipeline

- **Design principle:** no single layer is trusted alone; capabilities are fused into one explainable score, so a bypassed signal never collapses the verdict.

- **FAST PATH (instant verdict, <1s):**
  `APK → Static analysis (Androguard + APKiD + custom DEX parser) → ML risk model (LightGBM on Drebin-215) → Bank-impersonation check (typosquat + package/cert/icon) → Risk fusion (0–100 + reason codes) → Threat-intel escalation (VirusTotal + MalwareBazaar) → GenAI investigation report (async)`

- **DEEP PATH (on demand):**
  `Call-graph behavioral taint analysis (source → sink, e.g. SMS-read → network = OTP exfil)  +  GenAI Reverse Engineering (Claude reads the decompiled bytecode)  +  Dynamic analysis (VirusTotal multi-sandbox detonation + self-hosted Frida/MobSF harness)`

- **Full coverage of the problem statement:**
  | Required capability | Delivered by |
  |---|---|
  | Reverse engineering | In-memory decompilation + Claude reading the bytecode |
  | Static analysis | Androguard/APKiD/DEX parser + Drebin-215 ML |
  | Dynamic analysis | VirusTotal sandbox detonation + Frida/MobSF harness |
  | Risk scoring | Explainable 0–100 fusion + threat-intel/dynamic escalation |
  | Generative AI | Reverse engineering + investigation report layers |
  | Fraudulent APKs & malware | Bank-impersonation layer + general malware ML/threat-intel |

---

## Slide 4 — How Generative AI Is Harnessed (the core)

- **GenAI Reverse Engineering:** suspicious methods are decompiled in memory and the LLM **reads the actual bytecode and reconstructs the malicious logic.** On a real *Cerberus* sample it recovered, from the code: an **AES-encrypted command channel over SMS** (that aborts the broadcast to stay hidden), the **remote-command table** (LOCK / FIND / CAPTUREVIDEO), **screen recording**, and the **C2 endpoint `cerberusapp.com`** — including the string-deobfuscation routine.
- **GenAI Investigation Report:** plain-language verdict, **MITRE ATT&CK** mapping, IOC extraction, recommended actions, and a **multilingual (Hindi) customer warning**.
- **Trust & reliability engineering (what makes the GenAI dependable):**
  - Detection stays in fast trees + rules — **the LLM never sets the risk score** (no hallucinated verdicts).
  - **Neutral-evidence prompting** (the model is never told "this is malware") → an independent assessment that cross-checks our score.
  - **Grounding / anti-hallucination check:** every IOC and claim must trace to extracted evidence; invented indicators are caught and stripped.
  - **Prompt-injection defense:** attacker-controlled strings inside the APK are treated as data, never as instructions.
  - **Deterministic fallback:** a template report keeps the system working with no API key or network.
- **Killer validation — static → dynamic cross-check:** the reverse engineering found the C2 *in the code*; the dynamic sandbox **independently confirmed** the sample contacted that exact C2 at runtime.

---

## Slide 5 — Datasets Used (detailed)

| Dataset | What it is | Scale | Source | Role in the system |
|---|---|---|---|---|
| **Drebin-215** | Labeled Android static-feature dataset (permissions, API calls, intents as 215 binary features) | 15,036 apps — 5,560 malware / 9,476 benign | Public Drebin mirror (Kaggle/GitHub) | **Trains the ML risk classifier.** We found **51.7% duplicate feature vectors** and use group-aware cross-validation so the metric is leak-free and honest |
| **MalwareBazaar (abuse.ch)** | Real in-the-wild Android banking trojans (Hook, Cerberus, Anubis, Octo families) | 10 genuine samples downloaded for validation | abuse.ch API (password-protected zips) | **Real-world validation + reverse-engineering + behavioral analysis.** Analyzed **in memory only — never written to disk or executed** |
| **VirusTotal** | 70+ AV-engine reputation **and** multi-sandbox detonation behavior (runtime C2, dropped files, runtime MITRE) | Hash-only lookups | VirusTotal API | **Threat-intel score escalation + dynamic runtime analysis.** Only the SHA-256 is sent — never the APK |
| **Official Indian Bank/UPI App Allowlist** | Curated package IDs + signing-cert / icon references for SBI, ICICI, HDFC, Axis, Kotak, PNB, PhonePe, GPay, BHIM, Paytm, etc. | Self-built reference table | Curated | **Powers bank-impersonation detection** (typosquat, package/cert/icon mimicry) |
| **Controlled test fixtures** | Crafted **harmless** fake-bank APKs (typosquat names, banking-trojan permission sets, self-signed certs) + real benign apps (F-Droid) | Bundled in the repo | Built / collected | **Safe, repeatable testing and demos** — zero risk |
| **Roadmap datasets** | CICMalDroid 2020 (banking & SMS malware classes); AndroZoo (timestamped) | — | UNB CIC / AndroZoo | Family-level expansion + **time-aware (TESSERACT) drift evaluation** |

- **Data safety & ethics:** real malware is kept **AES-encrypted at rest**, decrypted only in memory for static analysis, and **never installed or executed**; threat-intel services receive only hashes, never the binary.

---

## Slide 6 — Evaluation & Honest Methodology (Results)

- **ML model — LightGBM on Drebin-215, dedup-safe (StratifiedGroupKFold):**
  - **PR-AUC 0.9967 · ROC-AUC 0.9978**
  - **Recall ≈ 96.8%** at a **0.88% false-positive rate**
  - **Precision ≈ 92%** when re-weighted to a realistic **90%-benign** stream (we never quote inflated balanced-split accuracy)
  - **51.7% duplicate vectors disclosed** and handled with group-aware CV → a leak-free, honest number.
- **Real-world validation:** 10 genuine in-the-wild banking trojans (Hook + Cerberus) all scored **CRITICAL**; VirusTotal flagged them on **18–34 of 76** engines.
- **The honest-evaluation centrepiece:** static ML alone scores these modern trojans **near zero** (their payload loads at runtime — textbook concept drift). The **layered system (threat-intel + dynamic + reverse engineering) catches them anyway.** We surface this limitation instead of hiding it — which is exactly why the design is layered, not a single classifier.
- **Explainable by construction:** every point of the 0–100 score traces to a named reason code, and the independent LLM verdict cross-checks the rule-based score.

---

## Slide 7 — Tech Stack, Live Demo & How to Test

- **Stack:** Python · Flask backend · **Androguard + APKiD** (static analysis / RE) · **LightGBM / scikit-learn** (ML) · **Claude / Anthropic API** (GenAI report + reverse engineering) · **VirusTotal + MalwareBazaar** (threat-intel + dynamic) · **Frida + MobSF** (self-hosted live detonation) · custom browser dashboard.
- **It is a working prototype, not a mockup:** upload an APK → instant verdict + evidence tabs → on-demand deep reverse-engineering & dynamic analysis.
- **Test it yourself (zero setup):**
  - **GitHub (full code + docs):** https://github.com/Dexterous-Ruler/apk
  - **Live dashboard on Google Colab (Run all → click the URL):** https://colab.research.google.com/github/Dexterous-Ruler/apk/blob/main/APKShield_Colab.ipynb
  - Runs **offline in template mode**, or at **full power** with free API keys (Anthropic, VirusTotal, MalwareBazaar).
- **Differentiators:** GenAI that *reverse-engineers real code* (not just summarizes a manifest) · static→dynamic cross-validation · India-specific impersonation layer · grounded/anti-hallucinated AI · honest, leak-free evaluation.
- **Roadmap:** on-device pre-install scanning · live self-hosted dynamic sandbox at scale · Google Play Integrity signals · time-aware drift evaluation.

---

## Slide 8 — Live Product (Screenshots)

*(reserved — paste dashboard mockup / screenshots here)*

---

**make whole ppt visually appealing and leave 1 page for mockup ss WHICH I WILL PASTE**
