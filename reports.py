import csv
import io

REPORT_COLUMNS = ["timestamp", "user", "ip", "event", "severity", "reason"]

# Cells starting with these characters are run as formulas by Excel / LibreOffice.
# Log content is attacker-controlled (a username like =HYPERLINK(...)), so neutralize them.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def generate_summary(threats):
    """Generate a summary of detected threats."""
    if threats is None or threats.empty:
        return {
            "total_threats": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

    severity = threats["severity"].fillna("").str.upper()

    return {
        "total_threats": len(threats),
        "critical": int((severity == "CRITICAL").sum()),
        "high": int((severity == "HIGH").sum()),
        "medium": int((severity == "MEDIUM").sum()),
        "low": int((severity == "LOW").sum()),
    }


def safe_cell(value):
    """Prevent CSV / formula injection when the report is opened in a spreadsheet."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def build_report_csv(alerts):
    """Build the CSV report (bytes, UTF-8 with BOM for Excel) from alert rows.

    `alerts` is an iterable of dicts using either the detection column names
    (timestamp, user...) or the database ones (event_time, username...).
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(REPORT_COLUMNS)
    for alert in alerts:
        writer.writerow([safe_cell(v) for v in (
            alert.get("timestamp", alert.get("event_time")),
            alert.get("user", alert.get("username")),
            alert.get("ip"),
            alert.get("event"),
            alert.get("severity"),
            alert.get("reason"),
        )])
    return buffer.getvalue().encode("utf-8-sig")
