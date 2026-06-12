# How to run & test APKSHIELD

Two ways. **For judges who just want to click and test the live dashboard,
use Colab. For code review / serious local runs, use GitHub + local.**

---

## ⭐ Recommended for judges: Google Colab (zero setup, live dashboard)

The backend is a Python/Flask server with a browser dashboard — Colab runs both
and gives a public URL, so a judge needs **nothing installed**.

1. Open **`APKShield_Colab.ipynb`** in Google Colab
   (github.com → the notebook → "Open in Colab", or upload it to
   [colab.research.google.com](https://colab.research.google.com)).
2. (Optional) paste free API keys in the **Keys** cell — Claude
   (anthropic.com), VirusTotal, MalwareBazaar — for the full experience.
   Leave blank to run in offline/template mode (static + ML + impersonation +
   risk still work fully).
3. **Runtime → Run all.** The last cell prints a live URL — click it.
4. In the dashboard: click a sample chip, or a **`REAL · Cerberus`** chip →
   **"Run deep analysis"** for the reverse-engineering + dynamic showcase.

Colab gives every judge their own live instance from one shared notebook link —
the best "test it perfectly without installing anything" path.

> **Why Colab over a hosted always-on URL?** A permanent deployment (Render/HF
> Spaces) would need your API keys baked into a public server (cost + key
> exposure) and heavyweight deps. Colab is free, needs no secrets in the repo,
> and each judge runs their own isolated instance. GitHub is the code; Colab is
> the live test.

---

## Local (full control, code review)

```bash
git clone https://github.com/Dexterous-Ruler/apk.git
cd apk
pip install -r requirements.txt

cp .env.example .env          # then fill in keys (all optional)
python server.py              # -> http://127.0.0.1:8800
```

Windows (PowerShell):
```powershell
git clone https://github.com/Dexterous-Ruler/apk.git ; cd apk
pip install -r requirements.txt
Copy-Item .env.example .env   # edit in your keys
python server.py
```

CLI (no server): `python src/pipeline.py data/samples/crafted/fake_sbi_yono_rewards.apk`

---

## What works with / without keys

| Feature | No keys | With keys |
|---|---|---|
| Static analysis, ML score, impersonation, risk fusion, behavioral taint, reverse-engineering (structural) | ✅ full | ✅ full |
| GenAI investigation report + AI reverse-engineering narrative | template fallback | ✅ Claude (`ANTHROPIC_API_KEY`) |
| Threat-intel reputation + score escalation | off | ✅ (`VT_API_KEY`, `MWB_API_KEY`) |
| Dynamic sandbox runtime behavior | off | ✅ (`VT_API_KEY`) |
| Real malware samples (Hook/Cerberus) | not in repo | `python analysis/fetch_real_samples.py` (`MWB_API_KEY`) |

Free keys: [anthropic.com](https://www.anthropic.com) · [virustotal.com](https://www.virustotal.com) · [auth.abuse.ch](https://auth.abuse.ch) (MalwareBazaar).

---

## Notes
- **Real malware is never committed** to the repo (GitHub policy + safety) and
  is never written to disk or executed — samples stay AES-encrypted and are
  decrypted only in memory for static analysis. Re-fetch with the script above.
- **Scan history persists by default** (saved under `outputs/scans/`). Use the
  **Clear** button in the dashboard's history panel to delete all records.
- The self-hosted Frida/MobSF *live* detonation path (`tools/frida_hooks.js`)
  needs a connected Android emulator; the VirusTotal multi-sandbox path gives
  real runtime behavior without one.
