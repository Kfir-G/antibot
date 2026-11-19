"""
This file contains middleware for logging HTTP requests.
the input requests are processed to extract relevant information for analysis.
the output is a log entry written to a file.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from starlette.middleware.base import BaseHTTPMiddleware

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "requests.jsonl"


class RequestLogMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging HTTP requests.
    """

    async def dispatch(self, request, call_next):
        """
        Log the request and response.
        """
        start = time.perf_counter()  # Start timing the request
        response = await call_next(request)  # Call the next middleware or endpoint
        elapsed_ms = round((time.perf_counter() - start) * 1000, 1)  # Measure elapsed time

        # headers
        raw = request.scope["headers"]  # Raw headers from the request
        header_order = [k.decode() for k, _ in raw]  # Order of headers
        h = request.headers  # Headers

        # extract relevant information - entry
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),  # UTC timestamp of the request in ISO 8601 format
            "ip": request.client.host if request.client else None,  # Client IP address, or None if unavailable
            "method": request.method,  # HTTP request method (e.g., GET, POST)
            "path": request.url.path,  # Request URL path without query string
            "query": request.url.query,  # Raw query string parameters
            "status": response.status_code,  # HTTP response status code
            "response_ms": elapsed_ms,  # Total request processing time in milliseconds
            "http_version": request.scope.get("http_version"),  # HTTP protocol version (e.g., "1.1", "2")
            "user_agent": h.get("user-agent"),  # Client User-Agent header value
            "accept_language": h.get("accept-language"),  # Preferred client languages header value
            "referer": h.get("referer"),  # Referring URL header value
            "has_cookie": "cookie" in h,  # Whether any Cookie header was present on the request
            "sec_fetch_dest": h.get("sec-fetch-dest"),  # Fetch metadata destination header (useful for browser/bot analysis)
            "sec_fetch_mode": h.get("sec-fetch-mode"),  # Fetch metadata request mode header (e.g., cors, navigate)
            "header_order": header_order,  # Ordered list of raw header names (useful for fingerprinting clients/bots)
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        return response