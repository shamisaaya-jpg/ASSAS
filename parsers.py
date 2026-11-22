import re
from io import StringIO

import pandas as pd

from windows_parser import is_windows_csv, parse_windows_events


# ---------- Linux auth.log ----------

AUTH_PATTERNS = [
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"),
     "login", "failed", "warning"),
    (re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+)"),
     "login", "success", "info"),
    (re.compile(r"pam_unix\(sudo:auth\): authentication failure.*?(?:ruser|user)=(?P<user>\S+)"),
     "sudo", "failed", "warning"),
]

TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T[\d:]+|\w{3}\s+\d+\s[\d:]+)")

COLUMNS = ["timestamp", "user", "ip", "event", "status", "level", "message"]


def parse_auth_log(text, year=2026):
    """Read a Linux auth.log / journalctl export and return a DataFrame."""
    rows = []
    for line in text.splitlines():
        for regex, event, status, level in AUTH_PATTERNS:
            match = regex.search(line)
            if match:
                ts = TIMESTAMP.match(line)
                rows.append({
                    "timestamp": ts.group(1) if ts else "",
                    "user": match.groupdict().get("user") or "",
                    "ip": match.groupdict().get("ip") or "",
                    "event": event,
                    "status": status,
                    "level": level,
                    "message": line.strip(),
                })
                break

    df = pd.DataFrame(rows, columns=COLUMNS)
    if df.empty:
        raise ValueError("No authentication events found in this log file.")

    no_year = ~df["timestamp"].str.match(r"^\d{4}")
    df.loc[no_year, "timestamp"] = f"{year} " + df.loc[no_year, "timestamp"]
    df["timestamp"] = (
        pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
        .dt.strftime("%Y-%m-%d %H:%M:%S")
    )
    return df


# ---------- CSV / JSON / LOG ----------

def _read_csv(file_path):
    """Read a CSV. Windows Event Viewer exports have one more column than the header
    (the description), so we give that extra column the name "Message"."""
    import csv
    with open(file_path, encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, [])
        first = next(reader, [])
    if len(first) == len(header) + 1:
        return pd.read_csv(file_path, encoding="utf-8-sig", header=0,
                           names=header + ["Message"], index_col=False)
    return pd.read_csv(file_path, encoding="utf-8-sig")


def parse_log_file(file_path):
    """Read a CSV, JSON or Linux auth log file and return a DataFrame."""
    path = file_path.lower()

    if path.endswith(".csv"):
        df = _read_csv(file_path)
        if is_windows_csv(df):
            df = parse_windows_events(df)
    elif path.endswith(".json"):
        df = pd.read_json(file_path)
    elif path.endswith((".log", ".txt")):
        with open(file_path, encoding="utf-8", errors="replace") as f:
            df = parse_auth_log(f.read())
    else:
        raise ValueError("Unsupported file format. Use CSV, JSON, LOG or TXT.")

    if df.empty:
        raise ValueError("The log file is empty.")

    df.columns = [str(column).strip().lower() for column in df.columns]
    return df


def parse_log_text(text):
    """Parse log data provided as CSV text."""
    df = pd.read_csv(StringIO(text))
    if df.empty:
        raise ValueError("No log entries were found.")
    df.columns = [str(column).strip().lower() for column in df.columns]
    return df