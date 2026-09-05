import json
import os
from database import init_db, create_user, add_history_entry, get_user

USERS_FILE = "users.json"

init_db()

if os.path.exists(USERS_FILE):
    with open(USERS_FILE, "r") as f:
        old_users = json.load(f)

    for email, data in old_users.items():
        if get_user(email) is None:
            create_user(email, data["password"])
            print("Migrated user: " + email)

            for entry in data.get("history", []):
                add_history_entry(
                    user_email=email,
                    filename=entry.get("filename", "unknown"),
                    total_ips=entry.get("total_ips", 0),
                    high_severity_count=entry.get("high_severity_count", 0),
                    timestamp=entry.get("timestamp", ""),
                    results=entry.get("results", []),
                    ai_summary=entry.get("ai_summary", "")
                )
            print("  Migrated " + str(len(data.get("history", []))) + " history entries.")
        else:
            print("Skipped (already exists): " + email)

    print("Migration complete!")
else:
    print("No users.json found — starting with a fresh database.")
    init_db()