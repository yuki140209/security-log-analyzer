import sqlite3
import json
import os

DB_FILE = "lotusguard.db"


def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            filename TEXT,
            total_ips INTEGER,
            high_severity_count INTEGER,
            timestamp TEXT,
            results_json TEXT,
            ai_summary TEXT,
            FOREIGN KEY (user_email) REFERENCES users(email)
        )
    """)

    conn.commit()
    conn.close()


def create_user(email, password_hash):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, password_hash))
    conn.commit()
    conn.close()


def get_user(email):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    return row


def update_user_password(email, new_password_hash):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_hash = ? WHERE email = ?", (new_password_hash, email))
    conn.commit()
    conn.close()


def add_history_entry(user_email, filename, total_ips, high_severity_count, timestamp, results, ai_summary):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO history (user_email, filename, total_ips, high_severity_count, timestamp, results_json, ai_summary)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_email, filename, total_ips, high_severity_count, timestamp, json.dumps(results), ai_summary))
    conn.commit()
    conn.close()


def get_recent_history(user_email, limit=5):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM history WHERE user_email = ? ORDER BY id DESC LIMIT ?
    """, (user_email, limit))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_history_entry_by_position(user_email, index):
    """index 0 = most recent."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM history WHERE user_email = ? ORDER BY id DESC
    """, (user_email,))
    rows = cursor.fetchall()
    conn.close()
    if index < 0 or index >= len(rows):
        return None
    return rows[index]


def delete_history_entry_by_position(user_email, index):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id FROM history WHERE user_email = ? ORDER BY id DESC
    """, (user_email,))
    rows = cursor.fetchall()
    conn.close()

    if index < 0 or index >= len(rows):
        return False

    entry_id = rows[index]["id"]
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM history WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
    return True