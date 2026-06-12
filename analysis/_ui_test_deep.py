"""Drive the full deep-analysis flow (RE + behavioral + dynamic) in the UI."""
from pathlib import Path
from playwright.sync_api import sync_playwright

SHOTS = Path(__file__).parent / "_shots_apk"
SHOTS.mkdir(exist_ok=True)
ENC = Path(__file__).resolve().parents[1] / "data" / "samples" / "real_encrypted"
URL = "http://127.0.0.1:8800"
# the hero Cerberus sample (rich static malicious code)
HERO = next(z.stem for z in ENC.glob("21b9ee90d26b*.zip"))

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1340, "height": 1200})
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))

    page.goto(URL)
    page.wait_for_load_state("networkidle")
    print("pills:", page.inner_text("#statusPills").replace("\n", " | "))

    # analyze the hero Cerberus sample directly via the real endpoint, then
    # the dashboard will have its analysis_id; easiest: click its REAL chip
    chip = page.query_selector(f'[data-real^="{HERO[:12]}"]')
    if chip:
        chip.click()
    else:
        # fall back: trigger via JS fetch + render
        page.evaluate(f"""async () => {{
            const r = await fetch('/api/analyze-real/{HERO}', {{method:'POST', body:new FormData()}});
            window.__d = await r.json(); render(window.__d); LAST = window.__d;
        }}""")
    page.wait_for_selector("#results:not(.hidden)", timeout=60000)
    page.wait_for_timeout(1500)
    print("verdict:", page.inner_text("#gScore"), page.inner_text("#sevBadge"))

    # run deep analysis
    page.click("#runDeep")
    print("deep running...")
    page.wait_for_selector("#deepTabs:not(.hidden)", timeout=120000)
    page.wait_for_timeout(800)
    print("deep status:", page.inner_text("#deepStatus"))
    dtabs = [t.inner_text().replace("\n", "") for t in page.query_selector_all("#deepTabs .tab")]
    print("deep tabs:", dtabs)

    for key in ["re", "behav", "dyn", "code"]:
        page.click(f'.tab[data-dtab="{key}"]')
        page.wait_for_timeout(400)
        page.screenshot(path=str(SHOTS / f"deep_{key}.png"), full_page=True)
    # grounding state on RE tab
    page.click('.tab[data-dtab="re"]')
    page.wait_for_timeout(300)
    g = page.query_selector(".panel[data-dpanel='re'] .ground")
    print("RE grounding banner:", (g.inner_text()[:80] if g else "none"))
    print("CONSOLE ERRORS:", errors if errors else "none")
    browser.close()
