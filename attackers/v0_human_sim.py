"""
Legit no attack
What is this file:
    Simulates normal, legitimate human user traffic against the listings API to establish a
    baseline alongside automated/abusive traffic.

What it tries to mimic:
    A real user browsing property listings (e.g., searching by city, viewing individual
    listings, realistic pacing/delays between actions, and standard browser headers/behavior).

What I saw in the jsonl in details:
    - Request cadence / response_ms: [e.g., irregular intervals between requests; typical response_ms]
    - Endpoints & parameters: [e.g., /search with city/limit, followed by /listings/{id} for viewed items]
    - Headers & metadata: [e.g., consistent user-agent, accept-language, referer, has_cookie, sec_fetch_*]
    - Example jsonl entry:
      {"ts": "[...]", "ip": "[...]", "method": "GET", "path": "/listings/[...]", "query": "[...]", "status": 200, "response_ms": [...], "http_version": "[...]", "user_agent": "[...]", "accept_language": "[...]", "referer": "[...]", "has_cookie": [...], "sec_fetch_dest": "[...]", "sec_fetch_mode": "[...]", "header_order": ["..."]}

What I learnt about the attack:
    - [e.g., how legitimate traffic differs from bots in timing distributions, navigation flow, and header consistency]
    - [e.g., where overlap exists that could cause false positives if a detector is too aggressive]
"""
import random
import time
import httpx

HEADERS = {
    # Consistent user-agent
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:158.0) Gecko/20100101 Firefox/158.0",
    
    # Preferred client languages
    "Accept-Language": "es-ES,es;q=0.9",
}

with httpx.Client(base_url="http://localhost:8000", headers=HEADERS) as c:
    c.get("/search?city=Madrid")
    for _ in range(40):
        c.get(f"/listings/{random.randint(1, 3000)}")
        time.sleep(random.uniform(0.2, 1.5))