from reports import build_report_csv
from search_store import build_query


def test_report_neutralizes_formulas():
    csv = build_report_csv([{"timestamp": "t", "user": '=HYPERLINK("http://x")', "ip": "+1",
                             "event": "@SUM(1)", "severity": "LOW", "reason": "-2"}]).decode("utf-8-sig")
    row = csv.splitlines()[1]
    assert "'=HYPERLINK" in row and "'+1" in row and "'@SUM" in row and "'-2" in row


def test_report_accepts_database_rows():
    csv = build_report_csv([{"event_time": "2026-01-01", "username": "bob", "ip": "1.1.1.1",
                             "event": "login", "severity": "HIGH", "reason": "x"}]).decode("utf-8-sig")
    assert "2026-01-01,bob,1.1.1.1" in csv


def test_search_wildcards_are_escaped():
    query = build_query(user="a*b")
    assert query["bool"]["filter"][0]["wildcard"]["user"]["value"] == "*a\\*b*"
