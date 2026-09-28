"""Optional Playwright screenshot capture."""

from __future__ import annotations

from pathlib import Path


class ScreenshotCapture:
    def __init__(self, timeout_ms: int = 10000):
        self.timeout_ms = max(1000, int(timeout_ms))

    def capture(self, target: str, output_path: str | Path) -> dict[str, str | int | None]:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {"target": target, "path": str(path), "error": "Install playwright and run 'playwright install chromium'"}

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(f"https://{target}", wait_until="domcontentloaded", timeout=self.timeout_ms)
                page.screenshot(path=str(path), full_page=True)
                browser.close()
            return {"target": target, "path": str(path), "error": None}
        except Exception as exc:
            return {"target": target, "path": str(path), "error": str(exc)}
