"""
Item Service - VULNERABLE version.

WARNING: This service contains INTENTIONAL security vulnerabilities for
demonstration purposes as part of the self-healing API proof of concept.

Vulnerabilities present:
  1. BOLA                (OWASP API1:2023)  – GET /items/{id} has no ownership check
  2. SQL Injection       (OWASP API10:2023) – POST /items/search uses f-string in SQL
  3. Missing Auth        (OWASP API2:2023)  – POST /items requires no authentication
  4. Missing Rate Limit  (OWASP API4:2023)  – /items/search has no rate limiting
  5. Excessive Data Exp. (OWASP API3:2023)  – GET /items/{id} returns the secret field

DO NOT deploy this service in a real environment.
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .database import get_db, init_db

app = FastAPI(
    title="Item Service (Vulnerable)",
    description="Intentionally vulnerable item service for self-healing API demo.",
)


class CreateItemRequest(BaseModel):
    owner_id: int
    name: str
    price: float


class SearchRequest(BaseModel):
    query: str


@app.on_event("startup")
def startup():
    init_db()


# ---------------------------------------------------------------------------
# VULNERABILITY 1 – BOLA
# Any user can retrieve any item regardless of ownership.
# ---------------------------------------------------------------------------
@app.get("/items/{item_id}")
def get_item(item_id: int):
    """Retrieve an item. VULNERABLE: No ownership check (BOLA)."""
    db = get_db()
    # VULN: no check that the caller owns item_id
    row = db.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(status_code=404, detail="Item not found")
    # VULN: explicitly returns secret field regardless of caller identity
    return {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "name": row["name"],
        "price": row["price"],
        "secret": row["secret"],
    }


# ---------------------------------------------------------------------------
# VULNERABILITY 2 – SQL Injection + VULNERABILITY 4 – Missing Rate Limiting
# The search query is interpolated directly into the SQL string.
# There is also no rate-limiting, so the endpoint can be abused endlessly.
# ---------------------------------------------------------------------------
@app.post("/items/search")
def search_items(req: SearchRequest):
    """Search items. VULNERABLE: SQL Injection and missing rate limiting."""
    db = get_db()
    # VULN: f-string SQL injection – e.g. query="' OR '1'='1"
    sql = f"SELECT * FROM items WHERE name LIKE '%{req.query}%'"
    rows = db.execute(sql).fetchall()
    db.close()
    # VULN: no rate limiting on this endpoint
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# VULNERABILITY 3 – Missing Authentication
# Any anonymous caller can create items.
# ---------------------------------------------------------------------------
@app.post("/items", status_code=201)
def create_item(req: CreateItemRequest):
    """Create an item. VULNERABLE: No authentication required."""
    db = get_db()
    # VULN: no authentication – anyone can create items for any owner_id
    cursor = db.execute(
        "INSERT INTO items (owner_id, name, price) VALUES (?, ?, ?)",
        (req.owner_id, req.name, req.price),
    )
    db.commit()
    item_id = cursor.lastrowid
    db.close()
    return {"id": item_id, "owner_id": req.owner_id, "name": req.name, "price": req.price}


@app.get("/items")
def list_items():
    """List all items. No auth, returns all items including secrets."""
    db = get_db()
    rows = db.execute("SELECT * FROM items").fetchall()
    db.close()
    return [dict(r) for r in rows]
