"""One-off Discord C5 test. Webhook from env only — never hardcode or commit it."""

import os
import sys

import requests

url = os.environ.get("DISCORD_WEBHOOK_URL")
if not url:
    print("Set DISCORD_WEBHOOK_URL first.", file=sys.stderr)
    sys.exit(1)

msg = {
    "username": "Watchtower",
    "embeds": [
        {
            "title": "New device on your network",
            "description": "**Unknown device** (vendor: Hikvision) joined at 192.168.1.42",
            "color": 15105570,
            "fields": [
                {
                    "name": "Why it matters",
                    "value": "Cameras often ship with Telnet open.",
                    "inline": False,
                },
                {
                    "name": "What to do",
                    "value": "Check if you recognise it. If not, block it on your router.",
                    "inline": False,
                },
            ],
            "footer": {"text": "Scan finished 21:05 · 1 new, 0 gone, 2 changed"},
        }
    ],
}

r = requests.post(url, json=msg, timeout=10)
print(r.status_code)  # 204 means it worked
if r.status_code not in (200, 204):
    print(r.text, file=sys.stderr)
    sys.exit(1)
