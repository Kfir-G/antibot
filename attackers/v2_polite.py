"""
What is this file:
    Second-version "polite" scraper/bot script designed to throttle requests and appear less
    aggressive than `v1_httpx.py`.

What it tries to mimic:
    A slower, rate-throttled client that spaces out requests and/or sets more plausible request
    attributes to avoid simple rate/burst detection.

What I saw in the jsonl in details:
    - Request cadence / response_ms: [e.g., longer/randomized sleep intervals between requests compared to v1]
    - Endpoints & parameters: [e.g., targeted /search or /listings/{id} calls spread over time]
    - Headers & metadata: [e.g., custom/browser-like user-agent, whether sec-fetch-* or referer were still missing or static]
    - Example jsonl entry:
      {"ts": "[...]", "ip": "[...]", "method": "GET", "path": "/search", "query": "city=[...]", "status": 200, "response_ms": [...], "http_version": "[...]", "user_agent": "[...]", "accept_language": "[...]", "referer": [...], "has_cookie": [...], "sec_fetch_dest": [...], "sec_fetch_mode": [...], "header_order": ["..."]}

What I learnt about the attack:
    - [e.g., slowing down defeats naive request-per-second thresholds, but behavioral/structural signals can still expose automation]
    - [e.g., compare how v2_polite.py still differs from human_sim.py in navigation patterns or headers]
"""
import random
import time
import httpx

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:158.0) Gecko/20100101 Firefox/158.0",
    "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
    "Referer": "http://localhost:8000/search?city=Madrid",
}

with httpx.Client(base_url="http://localhost:8000", headers=HEADERS) as c:
    for listing_id in range(1, 601):
        c.get(f"/listings/{listing_id}")
        time.sleep(random.uniform(0.05, 0.25))
