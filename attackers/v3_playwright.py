"""
What is this file:
    Third-version browser-automated attacker script using Playwright to drive a real browser
    against the target application.

What it tries to mimic:
    A real headless or full browser session executing requests with authentic browser networking,
    headers, and navigation behavior.

What I saw in the jsonl in details:
    - Request cadence / response_ms: [e.g., timing patterns, asset/page loads, or automation bursts]
    - Endpoints & parameters: [e.g., /search and /listings/{id} requests generated through the browser context]
    - Headers & metadata: [e.g., browser user-agent, accept-language, referer, has_cookie, sec_fetch_dest, sec_fetch_mode, header_order]
    - Example jsonl entry:
      {"ts": "[...]", "ip": "[...]", "method": "GET", "path": "/listings/[...]", "query": "[...]", "status": 200, "response_ms": [...], "http_version": "[...]", "user_agent": "Mozilla/5.0 [...]", "accept_language": "[...]", "referer": "[...]", "has_cookie": [...], "sec_fetch_dest": "empty", "sec_fetch_mode": "cors", "header_order": ["..."]}

What I learnt about the attack:
    - [e.g., browser automation produces much closer HTTP/Sec-Fetch headers than raw HTTP clients, shifting detection toward behavioral/session patterns]
    - [e.g., what subtle differences remained between v3_playwright.py and human_sim.py in your logs]
"""
import random
import time
from playwright.sync_api import sync_playwright

BASE = "http://localhost:8000"

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        for listing_id in range(1, 61):
            page.goto(f"{BASE}/view/{listing_id}")
            page.mouse.wheel(0, random.randint(200, 800))
            time.sleep(random.uniform(1.0, 4.0))
        browser.close()

if __name__ == "__main__":
    main()