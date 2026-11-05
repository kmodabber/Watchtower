# Contract C5 — Discord alert message (draft for doc 05)

## When we send

Send **one** Discord message after a scan finishes if that scan found anything new:

- new device
- device gone
- newly opened port / new service
- new high-severity risk finding

Send **nothing** when the scan found no changes and no new serious risks.
**One message per scan**, even if many things changed (no spam).

## Message shape

Plain language for a non-expert. Always include a short **what to do**.

Suggested fields (embed or plain text — product can use either; Stage 1 test used an embed):

| Field | Purpose | Example |
| --- | --- | --- |
| Title | What happened | New device on your network |
| Description | Who / where | Unknown device (vendor: Hikvision) joined at 192.168.1.42 |
| Why it matters | One sentence risk | Cameras often ship with Telnet open. |
| What to do | Non-expert fix | Check if you recognise it. If not, block it on your router. |
| Footer | Scan summary | Scan finished 21:05 · 1 new, 0 gone, 2 changed |
| Link | Dashboard | Details: http://\<pi-name\>.local:8000/changes |

PRD example (plain text, multiple changes in one message):

```
Watchtower: 2 changes on 192.168.8.0/24
NEW DEVICE Phone (private address), 192.168.8.57
NEW SERVICE Camera (Hikvision), port 23 Telnet: high risk
Details: http://<pi-name>.local:8000/changes
```

## Limits

- Discord hard cap: **2,000 characters** per message. If truncated, end with `…and N more`.
- Webhook URL stays in local config / env only — **never in the repo**.
- Username for the bot: `Watchtower`.

## Stage 1 proof

Test script: `spike/discord_test.py` (reads `DISCORD_WEBHOOK_URL` from the environment).
HTTP **204** = success. Paste a screenshot of the alerts channel next to this section in doc 05.
