"""
This file analyzes the request logs and detects suspicious behavior.
The input logs are processed to extract relevant features for analysis.
The output is a report summarizing the findings.

HOW TO READ THE REPORT
======================
Each row is one client, defined as the pair (IP, User-Agent). Every column
is a feature: a number that describes how that client behaves. No single
column proves anything. Read a row in this order:

  1. Is there enough data?      (n, navs)
  2. Which columns are expensive for an attacker to fake?  (seq%, burst)
  3. Do the columns contradict each other?
  4. How does the row compare with a real browser baseline?
  5. Who legitimate could this rule block by mistake?

COLUMNS
-------
client   The User-Agent, cut to 26 characters. The group key is (ip, UA), so
         two clients sharing both are merged into one row, and one attacker
         that changes its UA appears as several rows. Weak point of grouping.

n        All requests from this client, assets included.
         Small n means weak evidence. detector.MIN_REQUESTS (10) is the floor
         under which nobody is judged. A row with n=1 tells you nothing.

navs     Requests where the user asked for a page (see is_navigation).
assets   Requests the browser made by itself (CSS, JS, images).
         A real browser on our /view pages shows assets about 2x navs.
         httpx and curl show assets=0, but that is NOT evidence on its own:
         is_navigation treats rows with no sec_fetch_dest as navigations, so
         those clients always land in "navs". Also, assets stays 0 for
         everyone if sec_fetch_dest is not being logged (check logging_mw.py
         and restart the server).

gap_ms   Median time between consecutive navigations, in milliseconds.
         Machine: a few ms to a few hundred ms.  Human: seconds.
         The median is used because a single long pause (reading a page)
         would distort an average.

cv       Coefficient of variation of the gaps: spread divided by the mean.
         Low  -> gaps are nearly constant, looks mechanical.
         High -> mix of short and long pauses, looks human.
         Caution 1: if the gaps are tiny (v1: 1 ms), ordinary timing noise
         is large compared with the mean, so cv comes out HIGH even for a
         machine. A high cv does not prove a human.
         Caution 2: a script that draws pauses from random.uniform() produces
         a predictable cv (about 0.38 to 0.44) whatever it imitates.
         Do not choose a threshold until you have measured a real browser.

seq%     Share of consecutive page steps where the ID goes up by exactly 1
         (/listings/N or /view/N). 100 means the client walks the site in
         order, which is enumeration. People jump around.
         Caution: it shows 0 both for "random order" and for "no IDs at all",
         so check navs first. Legitimate sequential readers exist (someone
         pressing "next listing", search-engine crawlers), so a rule needs a
         minimum number of steps.

lang%    Share of ALL requests carrying an Accept-Language header.
         Browsers always send it. Libraries do not, unless the attacker adds
         it. One line of code defeats it, so it is a weak signal. Some
         legitimate API clients also send none.

noref%   Share of navigations with no Referer header.
         A person usually arrives from another page, so most navigations carry
         one. Direct visits, bookmarks and privacy tools remove it, so
         100 is not proof. Also cheap to fake. The table does not show whether
         the referer is CONSISTENT (the same value repeated, pointing at a
         page the client never visited); that is the better signal.

fav      Number of /favicon.ico requests. Browsers fetch it on their own,
         normally once per site and then cache it (in this lab it returns
         404, so it can repeat). A client that claims to be a browser and
         loads hundreds of pages without it is probably not one.
         Headless Chromium also does not request it.

burst    The most navigations the client made inside any single window of
         WINDOW_SECONDS (10 s). Compared with MAX_REQUESTS_IN_WINDOW (100).
         It is a threshold, not a fact: v2 reached 70 and passed; a threshold
         of 50 would have caught it, at the price of more false positives.

verdict  Currently set ONLY by the burst rule. "ok" means "no rule we have
         written flagged it", NOT "human". Rows can contradict the browser
         they claim to be (header order, missing sec-fetch headers) and still
         say "ok", because no rule reads those yet.

NOT IN THE TABLE YET (visible in the raw log)
---------------------------------------------
  header_order       Browsers send headers in a fixed order; libraries differ.
  sec_fetch_*        Present on every browser request, absent in httpx/curl.
  User-Agent text    HeadlessChrome and python-httpx name themselves.
  Referer values     Whether they are consistent with where the client went.

REFERENCE VALUES FROM OUR LAB RUNS
----------------------------------
  client        navs   gap_ms    cv    seq%  lang%  noref%  fav  burst
  real Firefox    17     3852   0.22       6    100     100   17      4
  human_sim       41     946   0.43       0    100     100     0    14
  v1 (httpx)     300       1   1.13     100      0     100     0   300
  v2 (polite)    600     156   0.38     100    100       0     0    70
  v3 (browser)    60    2596   0.37     100      0     100     0     6

Patterns worth noticing:
  - v1 is caught by almost every column. It is the easy attacker.
  - v2 fixed lang% and noref% with one header each, but left seq% at 100.
  - human_sim has human-looking behavior (seq% 0, slow gaps), but noref%
    100 because it is httpx and never sends a referer.
  - The expensive columns to fake are seq% and the header/sec-fetch
    contradictions, not lang% or noref%.
"""
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import median

from app.detector import (
    gap_cv,
    is_navigation,
    is_suspicious,
    max_requests_in_window,
    no_referer_ratio,
)

LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "requests.jsonl"

rows = [json.loads(l) for l in LOG_FILE.read_text().splitlines() if l.strip()]

# Group by client (IP + User-Agent)
groups = defaultdict(list)
for r in rows:
    groups[(r["ip"], r["user_agent"])].append(r)

# Analyze each group and extract features
print(f"{'client':<28}{'n':>5}{'navs':>6}{'assets':>8}{'gap_ms':>9}{'cv':>6}"
      f"{'seq%':>6}{'lang%':>7}{'noref%':>8}{'fav':>5}{'burst':>7}  verdict")

for (ip, ua), reqs in groups.items():
    # Split page navigations from assets the browser loads by itself
    navs = [r for r in reqs if is_navigation(r)]
    assets = len(reqs) - len(navs)

    # Extract timestamps (navigations only)
    ts = sorted(datetime.fromisoformat(r["ts"]) for r in navs)

    # Calculate gaps between navigations
    gaps = [(b - a).total_seconds() * 1000 for a, b in zip(ts, ts[1:])]

    # Extract listing IDs (/listings/N for the API, /view/N for the HTML page)
    ids = [int(m.group(1)) for r in navs
           if (m := re.match(r"/(?:listings|view)/(\d+)$", r["path"]))]
    steps = list(zip(ids, ids[1:]))

    # Calculate sequential request ratio
    seq = sum(1 for a, b in steps if b == a + 1) / len(steps) if steps else 0

    # Calculate language header ratio (all requests)
    lang = sum(1 for r in reqs if r["accept_language"]) / len(reqs)

    # Calculate share of navigations with no referer
    noref = no_referer_ratio(navs)

    # Count favicon requests
    fav = sum(1 for r in reqs if r["path"] == "/favicon.ico")

    # Calculate burst (most navigations inside one window)
    burst = max_requests_in_window(ts)

    # Determine verdict
    verdict = "BOT?" if is_suspicious(ts) else "ok"

    # Print the analysis results
    print(f"{(ua or '-')[:26]:<28}{len(reqs):>5}{len(navs):>6}{assets:>8}"
          f"{median(gaps) if gaps else 0:>9.0f}{gap_cv(gaps):>6.2f}"
          f"{seq*100:>6.0f}{lang*100:>7.0f}{noref*100:>8.0f}{fav:>5}{burst:>7}  {verdict}")