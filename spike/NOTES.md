# Scheduler spike notes (WT-FR-21)

## Did it work?

Yes. With intervals of 5 s (quick) and 15 s (full), and a 2 s poll for `scan_requests`:

```
Running. Ctrl+C to stop.
17:07:38 pretend quick scan
17:07:39 pretend full (requested) scan
17:07:43 pretend quick scan
```

After inserting a pending `full` row into `spike.db`, the request job picked it up within about 2 seconds and printed `pretend full (requested) scan`.

## `max_instances=1` and `coalesce=True`

- **`max_instances=1`**: APScheduler will not start a second copy of the same job while one is still running. That stops the same timer from overlapping itself (e.g. a slow "full" scan still going when the next interval fires).
- **`coalesce=True`**: if the scheduler missed several firings (process busy or asleep), it merges them into one run instead of catching up with a burst of back-to-back jobs.

Together they keep one job type from stacking up. They do **not** stop a *quick* job and a *full* job from running at the same time, because those are different jobs.

## Stage 2 problem: quick + full at once

Idea: use a **single worker queue** (or one shared lock) so every scan—timer or Scan now—goes through one worker. Only one scan runs at a time; the next waits. A thread-pool size of 1 on the scheduler (as in the PRD for T-21) is the same idea.

## If the app restarts while a request is `running`

That row stays `running` forever and is never picked up again (the poller only looks for `pending`). On startup we should reset stuck `running` rows back to `pending` (or mark them `failed`) so Scan now is not lost.

## Hand-in

- Branch with `spike/scheduler_spike.py` and this file (not on `main`).
- Add `spike.db` to `.gitignore`.
- PR for Adam to review.
