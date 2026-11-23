"""Read Windows Security events (exported to CSV) and convert them to the ASSAS format."""
import re

import pandas as pd

COLUMNS = ["timestamp", "user", "ip", "event", "status", "level", "message", "os"]

# Windows Event ID -> (ASSAS event, status, level)
EVENT_MAP = {
    4624: ("login", "success", "info"),
    4625: ("login", "failed", "warning"),
    4634: ("logoff", "success", "info"),
    4720: ("account_created", "success", "warning"),
    4722: ("account_enabled", "success", "info"),
    4726: ("account_deleted", "success", "warning"),
    4728: ("group_add", "success", "warning"),
    4732: ("group_add", "success", "warning"),
    4740: ("account_locked", "failed", "warning"),
}

ACCOUNT = re.compile(r"Account Name:\s*([^\s]+)", re.IGNORECASE)
ADDRESS = re.compile(r"(?:Source Network Address|Adresse r[ée]seau source):\s*([^\s]+)", re.IGNORECASE)
GROUP = re.compile(r"Group Name:\s*([^\r\n]+)", re.IGNORECASE)


ISO_DATE = re.compile(r"^\s*\d{4}-\d{2}-\d{2}")


def _naive(series):
    return series.dt.tz_localize(None)


def parse_timestamps(values):
    """Parse Windows timestamps.

    The PowerShell export writes ISO dates (2026-01-05 10:00:00) while a French
    Event Viewer export writes day first (05/01/2026 10:00:00). dayfirst=True
    must only be used for the second kind: applied to ISO strings it swaps day
    and month (2026-01-05 would become 1 May).
    """
    text = values.astype(str)
    iso = text.str.match(ISO_DATE)
    parsed = pd.Series(pd.NaT, index=values.index, dtype="datetime64[ns]")
    if iso.any():
        parsed[iso] = _naive(pd.to_datetime(text[iso], errors="coerce", format="mixed", utc=True))
    if (~iso).any():
        parsed[~iso] = _naive(pd.to_datetime(text[~iso], errors="coerce", dayfirst=True,
                                             format="mixed", utc=True))
    return parsed


def _col(df, *names):
    """Find a column whatever its exact spelling (EventID, Event ID, Id...)."""
    wanted = {n.replace(" ", "").lower() for n in names}
    for col in df.columns:
        if str(col).replace(" ", "").lower() in wanted:
            return col
    return None


def is_windows_csv(df):
    return _col(df, "EventID", "Event ID", "Id") is not None and \
        _col(df, "TimeCreated", "Date and Time", "Date et heure") is not None


def _clean(value):
    value = "" if pd.isna(value) else str(value).strip()
    return "" if value in {"-", "::1", "127.0.0.1", "nan"} else value


def parse_windows_events(df):
    """Convert a Windows Security CSV into the common ASSAS columns."""
    id_col = _col(df, "EventID", "Event ID", "Id")
    time_col = _col(df, "TimeCreated", "Date and Time", "Date et heure")
    user_col = _col(df, "User", "TargetUserName", "AccountName")
    ip_col = _col(df, "IP", "IpAddress", "SourceAddress")
    msg_col = _col(df, "Message", "Description")
    if msg_col is None:
        # Event Viewer "Save as CSV" puts the description in the last, unnamed column
        msg_col = df.columns[-1]

    rows = []
    for _, r in df.iterrows():
        try:
            event_id = int(r[id_col])
        except (TypeError, ValueError):
            continue
        if event_id not in EVENT_MAP:
            continue
        event, status, level = EVENT_MAP[event_id]
        message = "" if pd.isna(r[msg_col]) else str(r[msg_col])

        user = _clean(r[user_col]) if user_col else ""
        if not user:
            names = [n for n in ACCOUNT.findall(message) if n not in {"-", "SYSTEM"}]
            user = names[-1] if names else ""
        ip = _clean(r[ip_col]) if ip_col else ""
        if not ip:
            found = ADDRESS.search(message)
            ip = _clean(found.group(1)) if found else ""

        # Ignore machine accounts (DESKTOP-01$) and local system logons
        if user.endswith("$"):
            continue

        if event == "group_add":
            group = GROUP.search(message)
            if group:
                message = f"{message} [group: {group.group(1).strip()}]" if "[group:" not in message else message

        rows.append({
            "timestamp": r[time_col],
            "user": user,
            "ip": ip,
            "event": event,
            "status": status,
            "level": level,
            "message": message or f"Windows event {event_id}",
            "os": "windows",
        })

    result = pd.DataFrame(rows, columns=COLUMNS)
    if result.empty:
        raise ValueError("No supported Windows security events (4624, 4625, 4720, 4732...) found.")

    result["timestamp"] = parse_timestamps(result["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
    return result
