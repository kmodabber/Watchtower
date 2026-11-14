<h1 align="center">Watchtower</h1>

## What is it? 

Home network scanner that finds devices, flags risky settings in plain language with fixes, and alerts you when something changes. Built with Python, Nmap and Scapy, with a web dashboard. Runs on a Raspberry Pi.

## Development

Python 3.12 (same as the scanner dev container in `lab/Dockerfile.scanner`).

```sh
uv sync                   # or: pip install -e . "ruff==0.8.6" "pytest==8.3.4" httpx
uv run ruff check .       # lint
uv run ruff format .      # format (CI runs ruff format --check)
uv run pytest             # unit tests
```

CI (`.github/workflows/ci.yml`) runs the same three checks on every pull request.
Changes to `main` go through a pull request with one review.

## Database and API

The database is SQLite at `var/watchtower.db` (git-ignored). The schema (contract C2) is
defined in `watchtower/store/models.py` and built by Alembic migrations.

```sh
uv run watchtower db seed   # create the database and fill it from the lab fixtures
uv run watchtower web       # API on http://127.0.0.1:8000, try it at /docs
uv run watchtower db upgrade   # apply new migrations to an existing database
```

To re-seed, delete `var/watchtower.db` first. Changing a model? Generate a migration and
commit it with the change (CI fails if models and migrations disagree):

```sh
uv run alembic revision --autogenerate -m "what changed"
uv run alembic upgrade head
```

## Scan the test lab

The lab is a set of fake devices on an isolated Docker network (`lab/inventory.yaml`
lists what should be found). Scans only ever run against the lab; never point the
scanner at a real network without the real-network checklist (doc 09).

```sh
cd lab
docker compose up -d --build                                    # start the lab devices
docker compose --profile dev run --rm scanner python -m lab.discover_c1
docker compose down                                             # stop the lab
```

`lab.discover_c1` runs a quick Nmap scan from the scanner dev container and prints the
result as C1 JSON (one entry per device, plus the Docker gateway at `172.28.0.1`).
