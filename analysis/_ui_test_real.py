"""Drive the dashboard against a REAL Hook sample (in-memory) + a crafted one."""
from pathlib import Path
from playwright.sync_api import sync_playwright

SHOTS = Path(__file__).parent / "_shots_apk"
SHOTS.mkdir(exist_ok=True)
URL = "http://127.0.0.1:8800"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1320, "height": 1100})
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))

    page.goto(URL)
    page.wait_for_load_state("networkidle")
    chips = page.query_selector_all("#samples .chip-btn")
    print("sample chips:", [c.inner_text().replace("\n", " ") for c in chips])

    # click the first REAL sample chip
    real = page.query_selector("#samples .chip-btn[data-real]")
    print("real chip:", real.inner_text().replace("\n", " ") if real else None)
    real.click()
    page.wait_for_selector("#results:not(.hidden)", timeout=40000)
    page.wait_for_timeout(1600)
    print("REAL score:", page.inner_text("#gScore"), page.inner_text("#sevBadge"))
    print("layers:", page.inner_text("#vLayers").replace("\n", " "))
    print("esc-note present:", bool(page.query_selector(".esc-note")))
    if page.query_selector(".esc-note"):
        print("  ->", page.inner_text(".esc-note")[:120])
    page.screenshot(path=str(SHOTS / "real_verdict.png"))

    # threat intel tab
    page.click('.tab[data-tab="ti"]')
    page.wait_for_timeout(400)
    page.screenshot(path=str(SHOTS / "real_threatintel.png"), full_page=True)

    print("CONSOLE ERRORS:", errors if errors else "none")
    browser.close()
