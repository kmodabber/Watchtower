<h1 align="center">Watchtower</h1>

## What is it? 

Home network scanner that finds devices, flags risky settings in plain language with fixes, and alerts you when something changes. Built with Python, Nmap and Scapy, with a web dashboard. Runs on a Raspberry Pi.

## Development

Python 3.12 (same as the scanner dev container in `lab/Dockerfile.scanner`).

```sh
uv sync                   # or: pip install "ruff==0.8.6" "pytest==8.3.4" "pyyaml==6.0.2"
ruff check .              # lint
ruff format .             # format (CI runs ruff format --check)
pytest                    # unit tests
```

CI (`.github/workflows/ci.yml`) runs the same three checks on every pull request.
Changes to `main` go through a pull request with one review.

