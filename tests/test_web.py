"""Web tests. They need PostgreSQL (docker compose up -d); skipped otherwise."""
import io
import re

import pytest
from werkzeug.security import generate_password_hash

import db

try:
    db.init_db()
except db.psycopg2.OperationalError:
    pytest.skip("PostgreSQL is not reachable", allow_module_level=True)

import app as assas  # noqa: E402

PASSWORD = "correct-horse-1"


@pytest.fixture
def client(monkeypatch):
    assas.app.config["TESTING"] = True
    assas._failed_logins.clear()
    db.create_user("pytest_user", generate_password_hash(PASSWORD))
    # Keep the tests independent from OpenSearch
    monkeypatch.setattr(assas.search_store, "index_logs", lambda *a, **k: 0)
    return assas.app.test_client()


def token(client, path="/login"):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).text).group(1)


def login(client, password=PASSWORD, next_url=None):
    url = "/login" + (f"?next={next_url}" if next_url else "")
    return client.post(url, data={"username": "pytest_user", "password": password,
                                  "csrf_token": token(client)})


def test_post_without_csrf_token_is_rejected(client):
    r = client.post("/login", data={"username": "pytest_user", "password": PASSWORD})
    assert r.status_code == 400


@pytest.mark.parametrize("target", ["https://evil.example/", "//evil.example/", "/\\evil.example"])
def test_no_open_redirect(client, target):
    r = login(client, next_url=target)
    assert r.status_code == 302 and r.headers["Location"] == "/"


def test_local_next_is_kept(client):
    assert login(client, next_url="/history").headers["Location"] == "/history"


def test_logout_requires_post(client):
    login(client)
    assert client.get("/logout").status_code == 405


def test_login_rate_limit(client):
    for _ in range(assas.LOGIN_MAX_FAILURES):
        assert login(client, password="wrong").status_code == 401
    assert login(client).status_code == 429


def test_analyze_and_download_per_analysis(client):
    login(client)
    with open("sample_logs/auth_test.log", "rb") as f:
        data = f.read()
    r = client.post("/analyze", data={"logfile": (io.BytesIO(data), "auth.log"),
                                      "csrf_token": token(client, "/")},
                    content_type="multipart/form-data")
    assert r.status_code == 200 and "CRITICAL" in r.text
    analysis_id = re.search(r"/download/(\d+)", r.text).group(1)
    report = client.get(f"/download/{analysis_id}")
    assert report.status_code == 200 and b"Possible compromised account" in report.data
    assert client.get("/download/999999999").status_code == 404


def test_security_headers(client):
    r = client.get("/login")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
