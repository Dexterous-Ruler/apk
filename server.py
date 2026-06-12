"""APK Fraud Analyzer — Flask backend (Topic 1).

Completely independent of the mule/ project: its own port (8800), its own
pipeline, its own dashboard. Upload an APK -> static + ML + impersonation +
risk fusion -> GenAI investigation report -> threat-intel enrichment -> JSON.

Run:  python server.py        ->  http://127.0.0.1:8800
"""
from __future__ import annotations

import base64
import io
import json
import os
import sys
import tempfile
import time
import uuid
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "src"))


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (stdlib only) so API keys aren't hardcoded in
    source. Existing environment variables always win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


_load_dotenv(HERE / ".env")

from flask import Flask, jsonify, request, send_from_directory  # noqa: E402

import pipeline  # noqa: E402
import genai_report  # noqa: E402
import threat_intel  # noqa: E402
import deep_analysis  # noqa: E402
import reverse_engineer  # noqa: E402
import dynamic_analysis  # noqa: E402

# Maps a scan's analysis_id -> how to re-fetch its APK bytes for deep analysis.
# Uploads keep bytes in memory (capped); sample/real are re-derived on demand.
SESSION_SOURCES: dict = {}
UPLOAD_BYTES: dict = {}

WEB = HERE / "web"
OUT = HERE / "outputs"
SCANS = OUT / "scans"
SAMPLES = HERE / "data" / "samples"
REAL_ENC = SAMPLES / "real_encrypted"
ZIP_PWD = b"infected"
MAX_UPLOAD_MB = 200

app = Flask(__name__, static_folder=str(WEB), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


# ---------------------------------------------------------------------------
def _icon_data_url(apk_path: str) -> str | None:
    """Extract the app icon as a base64 data URL for the UI (the pipeline
    drops raw icon bytes from its JSON to keep it serializable)."""
    try:
        from androguard.core.apk import APK
        from apk_static import _extract_icon
        icon = _extract_icon(APK(apk_path))
        if not icon:
            return None
        fmt = "png" if icon[:8] == b"\x89PNG\r\n\x1a\n" else "webp"
        return f"data:image/{fmt};base64,{base64.b64encode(icon).decode()}"
    except Exception:
        return None


def _finish_analysis(result: dict, prefer_llm: str, icon_path: str | None,
                     t0: float) -> dict:
    import risk as _risk
    # threat intel first, so it can escalate the score before the report is
    # written (a static model trained on old malware can't clear a file that
    # many AV engines flag).
    sha = result["static"]["file"]["sha256"]
    result["threat_intel"] = threat_intel.enrich(sha)
    result["risk"] = _risk.apply_threat_intel(result["risk"], result["threat_intel"])
    # The GenAI report is generated ASYNCHRONOUSLY (via /api/report/<id>) so the
    # deterministic verdict renders instantly and LLM latency never blocks it.
    result["genai"] = {"pending": True, "engine": "pending", "report": {},
                       "grounding": {"grounded": True, "issues": []}}
    result["_prefer_llm"] = prefer_llm
    result["icon"] = _icon_data_url(icon_path) if icon_path else None
    result["analysis_id"] = uuid.uuid4().hex[:12]
    result["analyzed_epoch"] = int(time.time())
    result["wall_seconds"] = round(time.time() - t0, 2)
    return result


def _run_full_analysis(apk_path: str, prefer_llm: str = "auto") -> dict:
    t0 = time.time()
    result = pipeline.analyze(apk_path)
    return _finish_analysis(result, prefer_llm, apk_path, t0)


def _decrypt_real(sha_or_prefix: str) -> tuple[str, bytes] | None:
    """Decrypt a downloaded real sample IN MEMORY from its encrypted zip.
    The decrypted APK is never written to disk."""
    import pyzipper
    match = None
    if REAL_ENC.exists():
        for z in REAL_ENC.glob("*.zip"):
            if z.stem == sha_or_prefix or z.stem.startswith(sha_or_prefix):
                match = z
                break
    if not match:
        return None
    with pyzipper.AESZipFile(io.BytesIO(match.read_bytes())) as zf:
        zf.setpassword(ZIP_PWD)
        for name in zf.namelist():
            data = zf.read(name)
            if data[:2] == b"PK" or name.lower().endswith(".apk"):
                return match.stem, data
        name = zf.namelist()[0]
        return match.stem, zf.read(name)


def _persist(result: dict) -> None:
    SCANS.mkdir(parents=True, exist_ok=True)
    record = {
        "analysis_id": result["analysis_id"],
        "analyzed_epoch": result["analyzed_epoch"],
        "file": result["static"]["file"]["name"],
        "package": result["static"]["manifest"]["package"],
        "app_name": result["static"]["manifest"]["app_name"],
        "score": result["risk"]["score"],
        "severity": result["risk"]["severity"],
        "claimed_bank": result["impersonation"].get("claimed_bank"),
    }
    (SCANS / f"{result['analysis_id']}.json").write_text(
        json.dumps(result, indent=2, default=str))
    # append to index
    idx = SCANS / "_index.json"
    history = []
    if idx.exists():
        try:
            history = json.loads(idx.read_text())
        except Exception:
            history = []
    history.insert(0, record)
    idx.write_text(json.dumps(history[:200], indent=2))


# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(str(WEB), "index.html")


@app.route("/api/config")
def config():
    bundle = pipeline.load_bundle()
    return jsonify({
        "service": "apk-fraud-analyzer",
        "version": "1.0",
        "port": 8800,
        "model_loaded": bundle is not None,
        "ml_model": bundle["model_name"] if bundle else None,
        "llm": {
            "available": bool(os.environ.get("ANTHROPIC_API_KEY")
                              or os.environ.get("ANTHROPIC_AUTH_TOKEN")),
            "model": genai_report.MODEL,
        },
        "threat_intel": threat_intel.enabled(),
        "dynamic": dynamic_analysis.status(),
        "samples": _list_samples(),
    })


@app.route("/api/model")
def model_info():
    path = OUT / "apk_model_metrics.json"
    if not path.exists():
        return jsonify({"error": "model not trained"}), 404
    metrics = json.loads(path.read_text())
    fi = OUT / "apk_feature_importance.csv"
    top = []
    if fi.exists():
        import csv
        rows = list(csv.DictReader(fi.open()))
        top = [{"feature": r["feature"],
                "importance": round(float(r["importance"]), 5)}
               for r in rows[:20]]
    return jsonify({"metrics": metrics, "top_features": top})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "apk" not in request.files:
        return jsonify({"error": "no 'apk' file in form-data"}), 400
    f = request.files["apk"]
    if not f.filename:
        return jsonify({"error": "empty filename"}), 400
    prefer = request.form.get("llm", "auto")
    suffix = ".apk"
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    try:
        f.save(tmp.name)
        tmp.close()
        result = _run_full_analysis(tmp.name, prefer_llm=prefer)
        # use the uploaded filename, not the temp name
        result["static"]["file"]["name"] = f.filename
        _register_source(result["analysis_id"], "upload",
                         Path(tmp.name).read_bytes())
        _persist(result)
        return jsonify(result)
    except Exception as exc:
        import traceback
        return jsonify({"error": f"{type(exc).__name__}: {exc}",
                        "trace": traceback.format_exc()}), 500
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def _safe_token(s: str) -> bool:
    """Route params index local files by stem — reject anything with a path
    separator or traversal so they can never escape the samples dirs."""
    return bool(s) and "/" not in s and "\\" not in s and ".." not in s


@app.route("/api/analyze-sample/<name>", methods=["POST"])
def analyze_sample(name: str):
    """One-click demo: analyze a bundled sample by file stem."""
    if not _safe_token(name):
        return jsonify({"error": "invalid sample name"}), 400
    match = None
    for p in SAMPLES.rglob("*.apk"):
        if p.stem == name or p.name == name:
            match = p
            break
    if not match:
        return jsonify({"error": f"sample '{name}' not found"}), 404
    prefer = request.form.get("llm", "auto") if request.form else "auto"
    try:
        result = _run_full_analysis(str(match), prefer_llm=prefer)
        result["static"]["file"]["name"] = match.name
        _register_source(result["analysis_id"], "sample", match.name)
        _persist(result)
        return jsonify(result)
    except Exception as exc:
        import traceback
        return jsonify({"error": f"{type(exc).__name__}: {exc}",
                        "trace": traceback.format_exc()}), 500


@app.route("/api/analyze-real/<sha>", methods=["POST"])
def analyze_real(sha: str):
    """Analyze a downloaded real malware sample IN MEMORY (decrypted from its
    encrypted zip; the malware bytes never touch disk and are never executed).
    """
    if not _safe_token(sha):
        return jsonify({"error": "invalid sample id"}), 400
    t0 = time.time()
    try:
        dec = _decrypt_real(sha)
        if not dec:
            return jsonify({"error": f"real sample '{sha}' not found"}), 404
        full_sha, apk_bytes = dec
        prefer = request.form.get("llm", "auto") if request.form else "auto"
        result = pipeline.analyze(data=apk_bytes, filename=f"{full_sha[:16]}.apk")
        result = _finish_analysis(result, prefer, icon_path=None, t0=t0)
        result["static"]["file"]["name"] = f"{full_sha[:12]}… (real sample)"
        _register_source(result["analysis_id"], "real", full_sha)
        _persist(result)
        return jsonify(result)
    except Exception as exc:
        import traceback
        return jsonify({"error": f"{type(exc).__name__}: {exc}",
                        "trace": traceback.format_exc()}), 500


def _register_source(aid: str, kind: str, ref) -> None:
    SESSION_SOURCES[aid] = (kind, ref if kind != "upload" else aid)
    if kind == "upload":
        UPLOAD_BYTES[aid] = ref
        # keep only the last few uploads in memory
        for old in list(UPLOAD_BYTES)[:-5]:
            UPLOAD_BYTES.pop(old, None)


def _bytes_for(aid: str) -> tuple[bytes | None, str | None]:
    """(apk_bytes, error) for a prior scan id, for deep analysis."""
    src = SESSION_SOURCES.get(aid)
    if not src:
        return None, "unknown analysis id (re-run the scan, then deep-analyze)"
    kind, ref = src
    if kind == "upload":
        b = UPLOAD_BYTES.get(aid)
        return (b, None) if b else (None, "uploaded bytes expired from memory")
    if kind == "sample":
        for p in SAMPLES.rglob("*.apk"):
            if p.name == ref:
                return p.read_bytes(), None
        return None, "sample file no longer present"
    if kind == "real":
        dec = _decrypt_real(ref)
        return (dec[1], None) if dec else (None, "real sample not found")
    return None, "unsupported source"


@app.route("/api/report/<aid>", methods=["POST"])
def report(aid: str):
    """Generate the GenAI investigation report for a completed scan (async,
    off the fast verdict path). Loads the persisted evidence, runs the LLM,
    updates the stored scan, and returns the report."""
    if not _safe_token(aid):
        return jsonify({"error": "invalid id"}), 400
    p = SCANS / f"{aid}.json"
    if not p.exists():
        return jsonify({"error": "scan not found"}), 404
    try:
        result = json.loads(p.read_text())
        genai = genai_report.generate_report(
            result, prefer=result.get("_prefer_llm", "auto"))
        result["genai"] = genai
        p.write_text(json.dumps(result, indent=2, default=str))
        return jsonify(genai)
    except Exception as exc:
        import traceback
        return jsonify({"error": f"{type(exc).__name__}: {exc}",
                        "trace": traceback.format_exc()}), 500


@app.route("/api/deep/<aid>", methods=["POST"])
def deep(aid: str):
    """Deep analysis (on demand, ~20-60s): behavioral data-flow + GenAI reverse
    engineering of the actual bytecode + dynamic sandbox runtime behavior."""
    if not _safe_token(aid):
        return jsonify({"error": "invalid id"}), 400
    raw, err = _bytes_for(aid)
    if raw is None:
        return jsonify({"error": err}), 404
    prefer = (request.form.get("llm", "auto") if request.form else "auto")
    try:
        import hashlib
        sha = hashlib.sha256(raw).hexdigest()
        deep_res = deep_analysis.analyze_deep(data=raw).to_dict()
        re_res = reverse_engineer.reverse_engineer(deep_res, prefer=prefer)
        dyn_res = dynamic_analysis.dynamic_findings(sha)
        return jsonify({
            "analysis_id": aid,
            "behavioral": {
                "n_methods": deep_res["n_methods"],
                "seconds": deep_res["seconds"],
                "category_summary": deep_res["category_summary"],
                "behavior_flows": deep_res["behavior_flows"],
                "suspicious_call_sites": deep_res["suspicious_call_sites"],
                "note": deep_res["note"],
            },
            "reverse_engineering": re_res,
            # include the code targets so the UI can show decompiled snippets
            "re_targets": deep_res["re_targets"],
            "dynamic": dyn_res,
        })
    except Exception as exc:
        import traceback
        return jsonify({"error": f"{type(exc).__name__}: {exc}",
                        "trace": traceback.format_exc()}), 500


@app.route("/api/scans")
def scans():
    idx = SCANS / "_index.json"
    if not idx.exists():
        return jsonify([])
    return jsonify(json.loads(idx.read_text()))


@app.route("/api/scan/<analysis_id>")
def scan(analysis_id: str):
    p = SCANS / f"{analysis_id}.json"
    if not p.exists():
        return jsonify({"error": "not found"}), 404
    return jsonify(json.loads(p.read_text()))


@app.route("/api/scans", methods=["DELETE"])
def clear_scans():
    """Delete all saved scan records (history). Scans persist by default; this
    is the explicit 'clear all' action."""
    n = 0
    if SCANS.exists():
        for f in SCANS.glob("*.json"):
            try:
                f.unlink()
                n += 1
            except OSError:
                pass
    SESSION_SOURCES.clear()
    UPLOAD_BYTES.clear()
    return jsonify({"cleared": max(0, n - 1)})  # minus the _index.json itself


def _list_samples() -> list[dict]:
    out = []
    if SAMPLES.exists():
        for p in sorted(SAMPLES.rglob("*.apk")):
            if "real_encrypted" in p.parts:
                continue
            out.append({"name": p.stem,
                        "file": p.name,
                        "group": p.parent.name,
                        "size_kb": round(p.stat().st_size / 1024, 1)})
    # real downloaded samples (analyzed in-memory from encrypted zips)
    sig_map = {}
    res_json = OUT / "real_sample_results.json"
    if res_json.exists():
        try:
            for r in json.loads(res_json.read_text()):
                sig_map[r["sha256"]] = r.get("mb_signature") or r.get("family")
        except Exception:
            pass
    if REAL_ENC.exists():
        for z in sorted(REAL_ENC.glob("*.zip")):
            out.append({"name": z.stem[:12],
                        "file": z.name,
                        "group": "real",
                        "sha": z.stem,
                        "family": sig_map.get(z.stem, "malware"),
                        "size_kb": round(z.stat().st_size / 1024, 1)})
    return out


if __name__ == "__main__":
    # Host/port are configurable so the same server runs locally (127.0.0.1)
    # or on Colab/cloud (0.0.0.0) behind a tunnel/port-proxy.
    host = os.environ.get("APK_HOST", "127.0.0.1")
    port = int(os.environ.get("APK_PORT", "8800"))
    print(f"APK Fraud Analyzer  ->  http://{host}:{port}")
    bundle = pipeline.load_bundle()
    print(f"  ML model: {bundle['model_name'] if bundle else 'NOT TRAINED'}")
    print(f"  LLM: {'Claude (' + genai_report.MODEL + ')' if os.environ.get('ANTHROPIC_API_KEY') else 'template fallback (no ANTHROPIC_API_KEY)'}")
    print(f"  Threat intel: {threat_intel.enabled()}")
    print(f"  Dynamic sandbox: {dynamic_analysis.status()}")
    print(f"  Samples: {len(_list_samples())} bundled")
    app.run(host=host, port=port, debug=False, threaded=True)
