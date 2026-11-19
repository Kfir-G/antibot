"""
This file contains the main application logic.
the input requests are processed to extract relevant information for analysis.
the output is a JSON response with the search results or a specific listing.

correlate with v3
"""
import random
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from .logging_mw import RequestLogMiddleware

app = FastAPI()
app.add_middleware(RequestLogMiddleware)

random.seed(1)
LISTINGS = {
    i: {"id": i, "city": random.choice(["Madrid", "Lugo", "Sevilla", "Valencia"]),
        "price": random.randint(400, 2500), "rooms": random.randint(1, 5)}
    for i in range(1, 3001)
}

@app.get("/search")
def search(city: str | None = None, limit: int = 20):
    items = [l for l in LISTINGS.values() if not city or l["city"] == city]
    return items[:limit]

@app.get("/listings/{listing_id}")
def listing(listing_id: int):
    if listing_id not in LISTINGS:
        raise HTTPException(404)
    return LISTINGS[listing_id]

# -- view listing page --

@app.get("/view/{listing_id}", response_class=HTMLResponse)
def view(listing_id: int):
    l = LISTINGS.get(listing_id)
    if not l:
        raise HTTPException(404)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Listing {l['id']}</title>
<link rel="stylesheet" href="/static/style.css"></head>
<body><h1>{l['city']} · {l['rooms']} rooms</h1><p>{l['price']} EUR/month</p>
<script src="/static/app.js"></script></body></html>"""

@app.get("/static/style.css")
def css():
    return Response("body{font-family:sans-serif}", media_type="text/css")

@app.get("/static/app.js")
def js():

    return Response("console.log('ok')", media_type="application/javascript")
