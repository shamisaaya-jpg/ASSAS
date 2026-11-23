import json

import pandas as pd
import pytest

from conftest import SAMPLES
from detection import detect_threats
from charts import build_chart_data
from parsers import parse_auth_log, parse_log_file
from windows_parser import parse_timestamps


def severities(threats):
    return threats["severity"].value_counts().to_dict()


def test_linux_demo_detects_compromise():
    logs = parse_log_file(str(SAMPLES / "demo_attack.log"))
    threats = detect_threats(logs)
    crit = threats[threats["severity"] == "CRITICAL"]
    assert list(crit["ip"]) == ["192.168.56.10"]
    assert severities(threats)["HIGH"] == 2


def test_windows_demo_detects_backdoor():
    threats = detect_threats(parse_log_file(str(SAMPLES / "windows_security.csv")))
    reasons = " ".join(threats["reason"])
    assert "Possible backdoor" in reasons
    assert "Administrators group" in reasons


def test_iso_dates_are_not_day_month_swapped():
    parsed = parse_timestamps(pd.Series(["2026-01-05 10:00:00", "05/01/2026 10:00:00"]))
    assert list(parsed.dt.month) == [1, 1]
    assert list(parsed.dt.day) == [5, 5]


def test_windows_csv_with_early_month_day(tmp_path):
    path = tmp_path / "win.csv"
    path.write_text("TimeCreated,EventID,User,IP,Computer,Message\n"
                    "2026-03-04 09:00:00,4625,bob,10.0.0.9,PC,failed\n")
    assert parse_log_file(str(path))["timestamp"].iloc[0] == "2026-03-04 09:00:00"


def test_ipv6_source_address():
    df = parse_auth_log("Nov 21 22:10:01 h sshd[1]: Failed password for root "
                        "from 2001:db8::5 port 22 ssh2", year=2026)
    assert df["ip"].iloc[0] == "2001:db8::5"


def test_json_lines_and_wrapped_json(tmp_path):
    event = {"timestamp": "2026-01-01 10:00:00", "user": "a", "ip": "1.1.1.1",
             "event": "login", "status": "failed"}
    lines = tmp_path / "a.json"
    lines.write_text("\n".join(json.dumps(event) for _ in range(3)))
    assert len(parse_log_file(str(lines))) == 3

    wrapped = tmp_path / "b.json"
    wrapped.write_text(json.dumps({"events": [event, event]}))
    assert len(parse_log_file(str(wrapped))) == 2


def test_invalid_json_is_a_value_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(ValueError):
        parse_log_file(str(bad))


def test_lockouts_are_not_brute_force():
    df = pd.DataFrame([{"timestamp": f"2026-01-01 10:00:0{i}", "user": "x", "ip": "9.9.9.9",
                        "event": "account_locked", "status": "failed"} for i in range(6)])
    threats = detect_threats(df)
    assert "HIGH" not in set(threats["severity"])
    assert threats["reason"].str.contains("locked out").all()


def test_attacker_first_last_use_time_not_file_order():
    df = pd.DataFrame([
        {"timestamp": "2026-01-01 12:00:00", "user": "r", "ip": "6.6.6.6", "event": "login", "status": "failed"},
        {"timestamp": "2026-01-01 08:00:00", "user": "r", "ip": "6.6.6.6", "event": "login", "status": "failed"},
    ])
    attacker = build_chart_data(df, detect_threats(df))["attacker"]
    assert (attacker["first"], attacker["last"]) == ("2026-01-01 08:00:00", "2026-01-01 12:00:00")
