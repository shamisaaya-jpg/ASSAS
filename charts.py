import pandas as pd


def _top(series, n=5):
    """Return the n most frequent values as {"labels": [...], "values": [...]}."""
    series = series[series.astype(str).str.strip() != ""]
    counts = series.value_counts().head(n)
    return {
        "labels": [str(label) for label in counts.index],
        "values": [int(value) for value in counts.values],
    }


def _fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def build_chart_data(logs, threats):
    """Prepare all the numbers the dashboard charts need."""
    data = logs.copy()
    for col in ["timestamp", "user", "ip", "event", "status"]:
        if col not in data.columns:
            data[col] = ""
    data = data.fillna("")

    status = data["status"].astype(str).str.lower()
    is_failed = status.str.contains(r"fail|denied", regex=True)
    is_success = status.str.contains(r"success|accepted", regex=True)

    # ---------- Timeline: failed vs successful logins ----------
    timestamps = pd.to_datetime(data["timestamp"], errors="coerce")
    valid = timestamps.notna()
    timeline = {"labels": [], "failed": [], "success": []}

    if valid.any():
        span = (timestamps[valid].max() - timestamps[valid].min()).total_seconds()
        if span <= 3600:
            freq, fmt = "1min", "%H:%M"
        elif span <= 2 * 86400:
            freq, fmt = "1h", "%Hh"
        else:
            freq, fmt = "1D", "%d/%m"

        frame = pd.DataFrame({
            "ts": timestamps[valid],
            "failed": is_failed[valid].astype(int),
            "success": is_success[valid].astype(int),
        }).set_index("ts")
        grouped = frame.resample(freq).sum()

        timeline = {
            "labels": [ts.strftime(fmt) for ts in grouped.index],
            "failed": [int(v) for v in grouped["failed"]],
            "success": [int(v) for v in grouped["success"]],
        }

    # ---------- Top attackers and targeted users ----------
    failed_rows = data[is_failed]
    top_ips = _top(failed_rows["ip"])
    top_users = _top(failed_rows["user"])

    # ---------- Severity of detected findings ----------
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    if threats is not None and not threats.empty:
        severity = threats["severity"].fillna("").astype(str).str.upper()
        severity_values = [int((severity == level).sum()) for level in severity_order]
    else:
        severity_values = [0, 0, 0, 0]

    # ---------- Spotlight: main attacker ----------
    attacker = None
    if top_ips["labels"]:
        ip = top_ips["labels"][0]
        rows = data[data["ip"].astype(str) == ip]
        times = timestamps[rows.index]
        attacker = {
            "ip": ip,
            "failed": int(is_failed[rows.index].sum()),
            "success": int(is_success[rows.index].sum()),
            "users": sorted({str(u) for u in rows["user"] if str(u).strip()}),
            "first": _fmt(times.min()) if times.notna().any() else str(rows["timestamp"].iloc[0]),
            "last": _fmt(times.max()) if times.notna().any() else str(rows["timestamp"].iloc[-1]),
        }

    total = len(data)
    failed_total = int(is_failed.sum())
    return {
        "timeline": timeline,
        "top_ips": top_ips,
        "top_users": top_users,
        "severity": {"labels": severity_order, "values": severity_values},
        "totals": {
            "events": total,
            "failed": failed_total,
            "success": int(is_success.sum()),
            "fail_rate": round(100 * failed_total / total) if total else 0,
        },
        "attacker": attacker,
    }
