#!/usr/bin/env python3
"""Publish a text file to Telegram using repository secrets."""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path


def main() -> None:
    """Send the requested message, or skip when secrets are unavailable."""
    if len(sys.argv) != 2:
        raise SystemExit("usage: publish_telegram.py <message-file>")

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        print("Telegram secrets are not configured; skipping notification.")
        return

    message = Path(sys.argv[1]).read_text().strip()
    payload = urllib.parse.urlencode(
        {
            "chat_id": chat_id,
            "text": message,
            "disable_web_page_preview": "true",
        }
    ).encode()
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)
    if not result.get("ok"):
        raise RuntimeError(f"Telegram rejected the message: {result}")
    print("Telegram notification sent.")


if __name__ == "__main__":
    main()
