"""
User Service - Shared database setup.

Uses SQLite via raw sqlite3 for simplicity in the demo.
"""
import sqlite3
import os

DB_PATH = os.environ.get("USER_DB_PATH", "user_service.db")


def get_db():
    """Return a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables and seed demo data."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL UNIQUE,
            email    TEXT    NOT NULL,
            password TEXT    NOT NULL,
            role     TEXT    NOT NULL DEFAULT 'user'
        );
        INSERT OR IGNORE INTO users (username, email, password, role)
        VALUES
            ('alice', 'alice@example.com', 'hashed_pw_alice', 'admin'),
            ('bob',   'bob@example.com',   'hashed_pw_bob',   'user'),
            ('carol', 'carol@example.com', 'hashed_pw_carol', 'user');
        """
    )
    conn.commit()
    conn.close()
