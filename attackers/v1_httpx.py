"""
What is this file:
    First-version baseline bot/scraper script using `httpx` to send automated HTTP requests
    against the application endpoints.

What it tries to mimic:
    [e.g., basic automated scraping / enumeration of /search and /listings/{id} without sophisticated
    evasion or full browser rendering]

What I saw in the jsonl in details:
    - Request cadence / response_ms: [e.g., tight/uniform delays or rapid bursts; status codes like 200/404]
    - Endpoints & parameters: [e.g., sequential or broad enumeration of /listings/{listing_id} or /search]
    - Headers & metadata: [e.g., httpx default or minimal user-agent, missing/anomalous referer or sec_fetch_* headers, header_order]
    - Example jsonl entry:
      {"ts": "[...]", "ip": "[...]", "method": "GET", "path": "/listings/[...]", "query": "[...]", "status": [...], "response_ms": [...], "http_version": "[...]", "user_agent": "python-httpx/[...]", "accept_language": null, "referer": null, "has_cookie": false, "sec_fetch_dest": null, "sec_fetch_mode": null, "header_order": ["host", "accept", "accept-encoding", "user-agent"]}

What I learnt about the attack:
    - [e.g., naive HTTP clients leave clear fingerprints in User-Agent, missing browser headers, header_order, and request rate]
    - [e.g., high 404 rates or predictable ID scans stand out immediately in requests.jsonl]
"""
import httpx

BASE_URL = "http://localhost:8000"

def main():
    with httpx.Client(base_url=BASE_URL) as client:
        for listing_id in range(1, 301):
            r = client.get(f"/listings/{listing_id}")
            print(listing_id, r.status_code)

if __name__ == "__main__":
    main()
