"""
Detection rules for the request log.

Each function takes data extracted from the log (timestamps, rows, gaps) and
returns a number or a verdict. It does not read files or print anything.
analysis/analyze.py loads the log, calls these functions, and prints the report.
"""
from datetime import datetime
from statistics import mean, pstdev

# Burst rule settings
WINDOW_SECONDS = 10            # length of the sliding window, in seconds
MAX_REQUESTS_IN_WINDOW = 100   # more than this many requests in one window is suspicious
MIN_REQUESTS = 10              # clients with fewer requests than this are never judged


def is_navigation(r: dict) -> bool:
    """
    Tell whether a log row is a page navigation (the user asked for a page)
    as opposed to an asset the browser loaded by itself (CSS, JS, images).

    Why it matters: a browser loads several assets per page, so counting them
    would inflate the request rate and distort the timing between pages.

    Rows from clients that do not send the sec-fetch-dest header (curl, httpx)
    have no value for it and are treated as navigations.
    """
    return r.get("sec_fetch_dest") in (None, "document")


def max_requests_in_window(timestamps: list[datetime], window_seconds: float = WINDOW_SECONDS) -> int:
    """
    Return the highest number of requests a client sent inside any single
    window of `window_seconds`.

    Uses a sliding window with two pointers: `end` moves forward one request
    at a time, and `start` moves forward until the window is short enough.
    The largest window size seen along the way is the answer.
    """
    ts = sorted(timestamps)
    best = 0
    start = 0
    for end in range(len(ts)):
        # Shrink the window from the left until it fits in window_seconds
        while (ts[end] - ts[start]).total_seconds() > window_seconds:
            start += 1
        best = max(best, end - start + 1)
    return best


def is_suspicious(timestamps: list[datetime]) -> bool:
    """
    Rule 1: burst detection.

    A client is suspicious if it sent more than MAX_REQUESTS_IN_WINDOW requests
    inside one WINDOW_SECONDS window. A human can open several tabs quickly but
    cannot sustain that rate, while a simple scraper easily does.

    Clients with fewer than MIN_REQUESTS requests are never flagged, because a
    handful of requests is not enough evidence to judge anyone.

    Known limit: a scraper that stays under the threshold (for example by
    sleeping between requests) passes this rule.
    """
    if len(timestamps) < MIN_REQUESTS:
        return False
    return max_requests_in_window(timestamps) > MAX_REQUESTS_IN_WINDOW


def gap_cv(gaps: list[float]) -> float:
    """
    Coefficient of variation of the gaps between requests: standard deviation
    divided by the mean.

    Low value  -> the gaps are almost constant, which looks mechanical.
    High value -> a mix of short and long pauses, which looks human.

    Returns 0 when there are too few gaps (5 or fewer) to say anything, or when
    the mean is 0. This is a feature for now, not a rule: it is not used in the
    verdict until we choose a threshold from real data.
    """
    return pstdev(gaps) / mean(gaps) if len(gaps) > 5 and mean(gaps) > 0 else 0


def no_referer_ratio(navs: list[dict]) -> float:
    """
    Share (0 to 1) of page navigations that arrived with no Referer header.

    A person usually reaches a listing from another page (search results, a
    link), so most of their navigations carry a Referer. A scraper that requests
    URLs directly sends none. Direct visits and privacy tools also remove the
    header, so this is a weak signal that should be combined with others.

    Expects only navigation rows (see is_navigation). Returns 0 for an empty list.
    """
    return sum(1 for r in navs if not r["referer"]) / len(navs) if navs else 0
