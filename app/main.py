"""
This file contains the main application logic.
the input requests are processed to extract relevant information for analysis.
the output is a JSON response with the search results or a specific listing.
"""
import random
from fastapi import FastAPI, HTTPException
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
    """
    Search for listings by city and limit the number of results.
    """
    items = [l for l in LISTINGS.values() if not city or l["city"] == city]
    return items[:limit]

@app.get("/listings/{listing_id}")
def listing(listing_id: int):
    """
    Get a specific listing by its ID.
    """
    if listing_id not in LISTINGS:
        raise HTTPException(404)
    return LISTINGS[listing_id]
