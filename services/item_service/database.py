"""
Item Service - Shared database setup.

Uses SQLite via raw sqlite3 for simplicity in the demo.
"""
import sqlite3
import os

DB_PATH = os.environ.get("ITEM_DB_PATH", "item_service.db")


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
        CREATE TABLE IF NOT EXISTS items (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            name     TEXT    NOT NULL,
            price    REAL    NOT NULL DEFAULT 0.0,
            secret   TEXT
        );
        INSERT OR IGNORE INTO items (id, owner_id, name, price, secret)
        VALUES
            (1, 1, 'Alice Item',  9.99,  'secret_key_for_item_1'),
            (2, 2, 'Bob Item',   19.99,  'secret_key_for_item_2'),
            (3, 3, 'Carol Item',  4.99,  'secret_key_for_item_3');
        """
    )
    conn.commit()
    conn.close()
