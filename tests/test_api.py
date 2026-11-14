"""WT-73 (WT-FR-22): contract C4 endpoint shapes, on a database seeded from the lab fixtures."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from watchtower.api.app import create_app
from watchtower.cli import main
from watchtower.store.seed import SeedError, seed

CAMERA_MAC = "c0:56:e3:12:34:56"


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    db = tmp_path_factory.mktemp("api") / "watchtower.db"
    assert seed(db) == 5  # five lab devices in the saved fixtures
    with TestClient(create_app(db)) as c:
        yield c


def _camera(client: TestClient) -> dict:
    return next(d for d in client.get("/api/devices").json() if d["mac"] == CAMERA_MAC)


def test_health(client: TestClient) -> None:
    body = client.get("/api/health").json()
    assert body["database_ok"] is True
    assert body["last_scan_at"] == "2026-11-06T08:09:46Z"


def test_devices_worst_first_with_highest_severity(client: TestClient) -> None:
    devices = client.get("/api/devices").json()
    assert len(devices) == 5
    assert devices[0]["highest_severity"] == "high"
    camera = _camera(client)
    assert camera["type"] == "camera"
    assert camera["highest_severity"] == "high"  # Telnet
    assert camera["open_findings"] == 2
    assert camera["name"]  # never empty


def test_device_detail(client: TestClient) -> None:
    camera = client.get(f"/api/devices/{_camera(client)['id']}").json()
    assert [p["port"] for p in camera["ports"]] == [23, 80, 554]
    assert [f["rule_id"] for f in camera["findings"]] == ["RF-TELNET", "RF-HTTP-ADMIN"]
    assert {c["kind"] for c in camera["changes"]} == {"new_device", "new_finding"}
    assert isinstance(camera["type_reasons"], list)


def test_device_not_found(client: TestClient) -> None:
    assert client.get("/api/devices/9999").status_code == 404


def test_findings_worst_first_and_filters(client: TestClient) -> None:
    findings = client.get("/api/findings").json()
    order = ["high", "medium", "low", "info"]
    assert [order.index(f["severity"]) for f in findings] == sorted(
        order.index(f["severity"]) for f in findings
    )
    high = client.get("/api/findings", params={"severity": "high"}).json()
    assert high and all(f["severity"] == "high" for f in high)
    assert client.get("/api/findings", params={"open": "false"}).json() == []
    assert client.get("/api/findings", params={"severity": "urgent"}).status_code == 422


def test_changes_newest_first_and_since(client: TestClient) -> None:
    changes = client.get("/api/changes").json()
    assert changes[0]["at"] >= changes[-1]["at"]
    after_quick = client.get("/api/changes", params={"since": "2026-11-06T08:00:00Z"}).json()
    assert after_quick and all(c["kind"] == "new_finding" for c in after_quick)
    assert client.get("/api/changes", params={"since": "yesterday"}).status_code == 422


def test_scans(client: TestClient) -> None:
    scans = client.get("/api/scans").json()
    assert [s["profile"] for s in scans] == ["full", "quick"]  # newest first
    assert client.get(f"/api/scans/{scans[0]['id']}").json()["status"] == "done"
    assert client.get("/api/scans/9999").status_code == 404


def test_scan_now_queues_a_request_and_accepts_no_target(client: TestClient) -> None:
    r = client.post("/api/scans", json={"profile": "quick"})
    assert r.status_code == 202
    assert r.json()["profile"] == "quick" and r.json()["picked_up_at"] is None
    assert client.post("/api/scans").json()["profile"] == "full"  # no body: full scan
    assert client.post("/api/scans", json={"target": "8.8.8.8"}).status_code == 422


def test_consent(client: TestClient) -> None:
    assert client.post("/api/consent", json={}).status_code == 422
    assert client.post("/api/consent", json={"i_own_this_network": False}).status_code == 422
    body = client.post("/api/consent", json={"i_own_this_network": True}).json()
    assert body["ownership_confirmed"] is True
    assert client.get("/api/health").json()["ownership_confirmed"] is True


def test_scores_network_row_first(client: TestClient) -> None:
    scores = client.get("/api/scores").json()
    assert scores[0]["device_id"] is None
    assert all(0 <= s["score"] <= 100 for s in scores)


def test_docs_page_lists_endpoints(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert {"/api/health", "/api/devices", "/api/findings", "/api/scores"} <= paths.keys()


def test_seed_refuses_a_database_with_scans(tmp_path: Path) -> None:
    seed(tmp_path / "w.db")
    with pytest.raises(SeedError):
        seed(tmp_path / "w.db")


def test_cli_db_upgrade_and_seed(tmp_path: Path) -> None:
    db = str(tmp_path / "cli.db")
    assert main(["db", "upgrade", "--db", db]) == 0
    assert main(["db", "seed", "--db", db]) == 0
    assert main(["db", "seed", "--db", db]) == 1
