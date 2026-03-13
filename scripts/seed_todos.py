#!/usr/bin/env python3
"""Seed todos by calling the running API.

Usage:
    python scripts/seed_todos.py [BASE_URL]

Default BASE_URL: http://localhost:8080
"""

import json
import sys
from pathlib import Path

import httpx

SEED_FILE = Path(__file__).parent.parent / "localdev" / "data" / "seed_data.json"
DEFAULT_BASE_URL = "http://localhost:8080"


def main() -> None:
    base_url = (
        sys.argv[1].rstrip("/") if len(sys.argv) > 1 else DEFAULT_BASE_URL
    ) + "/api/v1/todos/"
    todos = json.loads(SEED_FILE.read_text())

    with httpx.Client(base_url=base_url) as client:
        count = client.get("", params={"limit": 1}).json()["pagination"]["total_items"]
        if count > 0:
            print(f"Database already has {count} todos. Skipping seed.")
            return

        for i, todo in enumerate(todos, 1):
            client.post("", json=todo)
            print(f"[{i}/{len(todos)}] Created: {todo['title']}")

    print(f"\nDone. Seeded {len(todos)} todos.")


if __name__ == "__main__":
    main()
