# APKSHIELD — Demo Runbook (Topic 1)

The 3-minute live demo + pitch script + Q&A. Topic 1: *GenAI-based automated
analysis and risk scoring of fraudulent APKs.*

## 0. Before the pitch (one-time)
```powershell
cd C:\Users\tanis\hackathon\apk
pip install -r requirements.txt          # already installed in the build env

# Keys live in apk\.env (already set this build): ANTHROPIC_API_KEY (live Claude
# report), VT_API_KEY + MWB_API_KEY (threat intel + real-sample download).
# server.py auto-loads .env — nothing to export.

python server.py                         # -> http://127.0.0.1:8800

# (optional) refresh the real in-the-wild samples — analyzed in-memory, never run:
python analysis\fetch_real_samples.py --limit 4
```
Open **http://127.0.0.1:8800** in a browser. The status pills (top-right) show
what's live: ML model, GenAI engine (Claude vs template), threat-intel.

> The server does **not** survive a reboot — restart `python server.py` at the venue.

## 1. The hook (15s)
> "Fraudsters send fake banking APKs over WhatsApp — 'Update your SBI KYC' —
> that steal OTPs and drain accounts. Analyzing one by hand takes a skilled
> reverse engineer hours. APKSHIELD does it in **under a second**, end to end,
> and writes the investigation report itself."

## 2. Live demo (90s)
1. **Drop the fake SBI APK** (click the `fake-bank · fake sbi yono rewards`
   chip, or drag `data/samples/crafted/fake_sbi_yono_rewards.apk`).
2. The gauge swings to **91 / 100 CRITICAL**. Point at the three layer bars:
   > "It's not one model — three independent layers agree: the **ML classifier**
   > (Drebin-215) says 0.99 malware; the **impersonation layer** proves it's
   > faking SBI; and the **capability combo** is the exact accessibility +
   > screen-overlay + SMS pattern of the SOVA banking trojan."
3. **Impersonation tab:** "It calls itself *SBl YONO Rewards* — note the
   capital-i-as-l typosquat — claims the `com.sbi.*` package, but is signed
   with a throwaway debug certificate. No bank ships an app signed like this."
4. **AI Report tab:** "Claude turns the raw evidence into an analyst report —
   plain-language verdict, **MITRE ATT&CK** mapping, the **exfil URL and IP**
   it found in the code, recommended actions, and a **Hindi warning** for the
   customer. Crucially —" point at the green banner — "every indicator is
   **grounded**: if the model invents a URL that isn't in the file, we catch
   and strip it. No hallucinated intelligence reaches the analyst."
5. **Contrast:** drop `clean_notes_app` (or F-Droid) → **0–5 MINIMAL**.
   > "A real app sails through. Low false positives are the whole game in
   > fraud ops."
6. **The real-malware moment** (the strongest beat): click a **`REAL · HOOK`**
   chip — a genuine in-the-wild Hook banking trojan from MalwareBazaar,
   analyzed live **in-memory** (the malware is never written to disk or run).
   > "Watch the layers: our static ML model scores it almost zero — because a
   > 2024 trojan hides its payload and loads it at runtime, invisible to static
   > features. That's the honest limit of static ML. But the **threat-intel
   > layer** sees 27 AV vendors flag it and **escalates it to 85 CRITICAL** —
   > and Claude independently reads it as malicious. We never let a stale model
   > clear a file the world already knows is malware. *That's* why it's layered,
   > not one classifier."

## 2b. The deep-analysis showcase — RE + dynamic (the winning moment, 60s)
Pick a **`REAL · Cerberus`** chip (the `com.lsdroid.cerberus` sample has rich,
readable malicious code), let the verdict load, then click **"Run deep
analysis"**. After ~30s, three tabs appear:
1. **AI Reverse Engineering** — "This is Claude reading the *actual decompiled
   bytecode*. It reconstructed: an AES/CBC-encrypted **command channel over
   SMS** that aborts the broadcast to hide it, the full remote-command table
   (LOCK / FIND / CAPTUREVIDEO), **screen recording** via `/system/bin/
   screenrecord`, and the **C2 at `cerberusapp.com/download/ping`** — including
   the `q.a` string-deobfuscation routine. Every claim is grounded against the
   code it read (green banner)."
2. **Behavioral Flows** — "Static taint analysis: it traced SMS-read → network
   as an OTP-exfil path, and the trigger→action chains."
3. **Dynamic Runtime** — "And here's the proof it's not just static guessing:
   real **sandbox detonation** behavior. The malware was executed in an
   isolated sandbox and contacted `cerberusapp.com` and `cellphonetrackers.org`
   at runtime — **the exact C2 our reverse engineering found in the code.**
   Static RE finds it, dynamic detonation confirms it. We sent only the hash,
   never the malware."

> The static→dynamic cross-validation (RE finds the C2 string → sandbox
> confirms the connection) is the single most convincing beat — lead the Q&A
> back to it.

## 3. The credibility close (30s)
> "And we evaluated honestly. On the Drebin benchmark the model is 98% recall
> at a 0.5% false-positive rate — but we **don't** quote that naked accuracy.
> We prior-shift precision to a realistic 90%-benign stream (**95.6%**), we
> disclose that we couldn't do a time-aware split, and we never execute the
> malware — static analysis only, the sample never runs. That honesty is in
> `outputs/REPORT.md`."

## 4. Q&A cheat-sheet
- **"Is the malware real / safe to run here?"** The crafted demo samples are
  our *own* harmless APKs carrying the fraud *signals* (typosquat name, scary
  permissions, suspicious API references, exfil strings) but **no executable
  payload** — they can't run as malware. For real samples we analyze straight
  from a password-protected zip **in memory, statically, never executed**.
- **"Why not just an LLM end-to-end?"** Detection in trees + rules is fast,
  cheap, deterministic, and explainable; the LLM is the *interpretation* layer.
  We also never tell it "this is malware" (that biases it) — it assesses the
  neutral evidence and its verdict cross-checks our score.
- **"What about obfuscated/packed APKs?"** APKiD flags packers/protectors as a
  high-signal feature and a router — packed → static is unreliable → escalate
  to dynamic (MobSF/Frida, our roadmap).
- **"How does it scale?"** ~0.5–1s per APK, CPU-only, stateless `/api/analyze`.
  Drop it behind a queue for batch triage of reported samples.
- **"Production signals?"** Cert allowlist + Play Integrity (sideload check) +
  VirusTotal/MalwareBazaar threat intel (hash-only, already wired).

## 5. If something breaks
- **Claude/network down:** the report layer auto-falls-back to the deterministic
  template — the demo looks identical minus the LLM prose. Nothing to do.
- **Server won't start:** check port 8800 is free; `python -c "import androguard"`.
- **A sample errors:** use a different chip; `python src/pipeline.py <apk>` shows
  the stack trace.
- **Recorded fallback:** keep a screen recording of the fake-SBI run as backup.
