"""Drive the APKSHIELD dashboard headlessly and screenshot every tab."""
from pathlib import Path
from playwright.sync_api import sync_playwright

SHOTS = Path(__file__).parent / "_shots_apk"
SHOTS.mkdir(exist_ok=True)
URL = "http://127.0.0.1:8800"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1320, "height": 1000})
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))

    page.goto(URL)
    page.wait_for_load_state("networkidle")
    page.screenshot(path=str(SHOTS / "0_landing.png"))
    print("pills:", page.inner_text("#statusPills").replace("\n", " | "))
    print("samples:", len(page.query_selector_all("#samples .chip-btn")))

    # click the fake SBI sample
    page.click('[data-sample="fake_sbi_yono_rewards"]')
    page.wait_for_selector("#results:not(.hidden)", timeout=30000)
    page.wait_for_timeout(1400)  # gauge animation
    page.screenshot(path=str(SHOTS / "1_verdict.png"))
    print("score:", page.inner_text("#gScore"), page.inner_text("#sevBadge"))
    print("layers:", page.inner_text("#vLayers").replace("\n", " "))

    tabs = page.query_selector_all("#tabs .tab")
    print("tabs:", [t.inner_text().replace("\n", "") for t in tabs])
    for i, key in enumerate(["verdict", "perms", "imp", "code", "ai", "ti"]):
        page.click(f'.tab[data-tab="{key}"]')
        page.wait_for_timeout(350)
        page.screenshot(path=str(SHOTS / f"2_{i}_{key}.png"), full_page=True)

    # history present?
    print("history items:", len(page.query_selector_all("#hist .hist-item")))

    # benign sample for contrast
    page.click('[data-sample="clean_notes_app"]')
    page.wait_for_selector("#results:not(.hidden)", timeout=30000)
    page.wait_for_timeout(1200)
    page.screenshot(path=str(SHOTS / "3_benign.png"))
    print("benign score:", page.inner_text("#gScore"), page.inner_text("#sevBadge"))

    print("CONSOLE ERRORS:", errors if errors else "none")
    browser.close()
