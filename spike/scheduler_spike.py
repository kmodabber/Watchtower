"""Throwaway scheduler spike for Stage 1. Fake scans only."""
import sqlite3
import time
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler

db = sqlite3.connect("spike.db", check_same_thread=False)
db.execute(
    """CREATE TABLE IF NOT EXISTS scan_requests (
    id INTEGER PRIMARY KEY, kind TEXT, status TEXT DEFAULT 'pending')"""
)
db.commit()


def run_scan(kind):
    print(f"{datetime.now():%H:%M:%S} pretend {kind} scan")


def check_requests():
    row = db.execute(
        "SELECT id, kind FROM scan_requests "
        "WHERE status='pending' ORDER BY id LIMIT 1"
    ).fetchone()
    if row:
        db.execute(
            "UPDATE scan_requests SET status='running' WHERE id=?", (row[0],)
        )
        db.commit()
        run_scan(row[1] + " (requested)")
        db.execute(
            "UPDATE scan_requests SET status='done' WHERE id=?", (row[0],)
        )
        db.commit()


sched = BackgroundScheduler()
# seconds for testing; the real values are minutes=5 and minutes=15
sched.add_job(
    run_scan,
    "interval",
    seconds=5,
    args=["quick"],
    max_instances=1,
    coalesce=True,
)
sched.add_job(
    run_scan,
    "interval",
    seconds=15,
    args=["full"],
    max_instances=1,
    coalesce=True,
)
sched.add_job(check_requests, "interval", seconds=2, max_instances=1)
sched.start()
print("Running. Ctrl+C to stop.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    sched.shutdown()
