"""
User Service - VULNERABLE version.

WARNING: This service contains INTENTIONAL security vulnerabilities for
demonstration purposes as part of the self-healing API proof of concept.

Vulnerabilities present:
  1. SQL Injection       (OWASP API10:2023) – login endpoint uses f-string in SQL query
  2. Broken Auth         (OWASP API2:2023)  – /users and /users/{id} require no auth
  3. Excessive Data Exp. (OWASP API3:2023)  – GET /users/{id} returns the password field
  4. BOLA                (OWASP API1:2023)  – DELETE /users/{id} performs no ownership check

DO NOT deploy this service in a real environment.
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .database import get_db, init_db

app = FastAPI(
    title="User Service (Vulnerable)",
    description="Intentionally vulnerable user service for self-healing API demo.",
)


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str


@app.on_event("startup")
def startup():
    init_db()


# ---------------------------------------------------------------------------
# VULNERABILITY 1 – SQL Injection
# The login query is built with an f-string so an attacker can bypass auth
# with a payload like: username="' OR '1'='1" password="anything"
# ---------------------------------------------------------------------------
@app.post("/login")
def login(req: LoginRequest):
    """Authenticate a user. VULNERABLE: SQL Injection."""
    db = get_db()
    # VULN: raw SQL with f-string – susceptible to SQL injection
    query = (
        f"SELECT * FROM users WHERE username = '{req.username}'"
        f" AND password = '{req.password}'"
    )
    row = db.execute(query).fetchone()
    db.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": "Login successful", "user_id": row["id"]}


# ---------------------------------------------------------------------------
# VULNERABILITY 2 – Missing Authentication (list all users)
# Any anonymous caller can enumerate every account.
# ---------------------------------------------------------------------------
@app.get("/users")
def list_users():
    """List all users. VULNERABLE: No authentication required."""
    db = get_db()
    # VULN: no auth check before returning sensitive user data
    rows = db.execute("SELECT * FROM users").fetchall()
    db.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# VULNERABILITY 3 – Excessive Data Exposure
# The password hash is included in the response body.
# ---------------------------------------------------------------------------
@app.get("/users/{user_id}")
def get_user(user_id: int):
    """Get a single user. VULNERABLE: Returns password field."""
    db = get_db()
    # VULN: no auth, and password is included in the serialised row
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    # VULN: explicitly returns the password hash – should be excluded from the response
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "password": row["password"],
        "role": row["role"],
    }


# ---------------------------------------------------------------------------
# VULNERABILITY 4 – BOLA (Broken Object Level Authorization)
# Any caller can delete ANY user by supplying their id – no ownership check.
# ---------------------------------------------------------------------------
@app.delete("/users/{user_id}")
def delete_user(user_id: int):
    """Delete a user. VULNERABLE: No ownership / authorisation check."""
    db = get_db()
    # VULN: no check that the caller owns (or has rights over) this user record
    result = db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": f"User {user_id} deleted"}
