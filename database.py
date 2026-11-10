
import os
import sqlite3
from flask import current_app


def get_db_connection():
    db_path = os.path.join(current_app.instance_path, "artist_corner.db")

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    return connection


def init_db():
    os.makedirs(current_app.instance_path, exist_ok=True)

    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()
