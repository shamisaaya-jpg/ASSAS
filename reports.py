from pathlib import Path
import pandas as pd


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


def export_report(threats, output_path="reports/threat_report.csv"):
    """Export detected threats to a CSV report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if threats is None:
        threats = pd.DataFrame(
            columns=[
                "timestamp", "user", "ip",
                "event", "severity", "reason"
            ]
        )

    threats.to_csv(path, index=False, encoding="utf-8-sig")
    return str(path)
