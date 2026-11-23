import pandas as pd

COLUMNS = ["timestamp", "user", "ip", "event", "severity", "reason"]
ACCOUNT_EVENTS = {"account_created", "account_enabled", "account_deleted",
                  "account_locked", "group_add", "logoff"}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _max_window(times, window):
    """Find the busiest time window: returns (count, start, end)."""
    best = (0, None, None)
    j = 0
    for i in range(len(times)):
        while times[i] - times[j] > window:
            j += 1
        count = i - j + 1
        if count > best[0]:
            best = (count, times[j], times[i])
    return best


def _fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(ts) else ""


def detect_threats(df, failed_threshold=5, window_minutes=5,
                   spray_threshold=3, sudo_threshold=3):
    """
    Apply ASSAS detection rules and return one finding per suspicious activity.

    Rules:
      1. Brute force        HIGH      >= failed_threshold failed logins from one IP in window_minutes
      2. Compromise         CRITICAL  successful login from a brute-forcing IP, after the failures
      3. Password spraying  MEDIUM    one IP tried >= spray_threshold different accounts
      4. Sudo abuse         MEDIUM    >= sudo_threshold failed sudo for one user in window_minutes
      5. Isolated failures  LOW       failed attempts below the thresholds
      6. Log level          CRITICAL / MEDIUM for critical, fatal or error events
      7. Account changes    CRITICAL / HIGH / MEDIUM for account creation (after a
                            compromise = backdoor), admin group adds, lockouts, deletions
    """
    if df is None or df.empty:
        return pd.DataFrame(columns=COLUMNS)

    data = df.copy()
    for col in ["timestamp", "user", "ip", "event", "status", "level", "message"]:
        if col not in data.columns:
            data[col] = ""
        data[col] = data[col].fillna("").astype(str).str.strip()

    data["ts"] = pd.to_datetime(data["timestamp"], errors="coerce")
    data = data.sort_values("ts", na_position="last")
    window = pd.Timedelta(minutes=window_minutes)
    findings = []

    def add(timestamp, user, ip, event, severity, reason):
        findings.append({"timestamp": timestamp, "user": user, "ip": ip,
                         "event": event, "severity": severity, "reason": reason})

    failed = (
        data["event"].str.contains(r"failed login|login failed|authentication failed",
                                   case=False, regex=True)
        | data["status"].str.contains(r"failed|failure|denied", case=False, regex=True)
    )
    success = (
        data["event"].str.contains(r"login|authentication", case=False, regex=True)
        & data["status"].str.contains(r"success|successful|accepted", case=False, regex=True)
    )
    is_sudo = data["event"].str.contains("sudo", case=False)
    # Account management events can carry status "failed" too (e.g. a lockout)
    # but they are not login attempts: they must not feed the brute-force rules.
    is_account_event = data["event"].isin(ACCOUNT_EVENTS)

    login_failures = data[failed & ~is_sudo & ~is_account_event & (data["ip"] != "")]
    flagged_ips = set()
    compromise_times = []

    # ---------- Rule 1: brute force (sliding time window) ----------
    for ip, rows in login_failures.groupby("ip"):
        times = list(rows["ts"].dropna())
        if times:
            count, first, last = _max_window(times, window)
            period = f"in {window_minutes} min ({_fmt(first)[11:]} -> {_fmt(last)[11:]})"
        else:
            count, first, last = len(rows), None, None
            period = "in this file"

        if count >= failed_threshold:
            flagged_ips.add(ip)
            users = ", ".join(sorted(set(rows["user"]) - {""}))
            add(_fmt(first) or rows["timestamp"].iloc[0], users, ip, "login", "HIGH",
                f"Brute force: {count} failed logins {period}. Targeted users: {users}")

            # ---------- Rule 2: success after the brute force ----------
            ok = data[success & (data["ip"] == ip)]
            if first is not None:
                ok = ok[ok["ts"] >= first]
            for _, row in ok.iterrows():
                compromise_times.append(row["ts"])
                add(row["timestamp"], row["user"], ip, row["event"], "CRITICAL",
                    f"Possible compromised account: '{row['user']}' logged in "
                    f"from {ip} after {count} failed attempts")

        # ---------- Rule 3: password spraying ----------
        distinct_users = sorted(set(rows["user"]) - {""})
        if len(distinct_users) >= spray_threshold:
            flagged_ips.add(ip)
            add(rows["timestamp"].iloc[0], ", ".join(distinct_users), ip, "login", "MEDIUM",
                f"Password spraying / user enumeration: {len(distinct_users)} "
                f"different accounts tried from {ip}")

    # ---------- Rule 4: repeated sudo failures ----------
    sudo_failures = data[failed & is_sudo]
    flagged_sudo_users = set()
    for user, rows in sudo_failures.groupby("user"):
        times = list(rows["ts"].dropna())
        count = _max_window(times, window)[0] if times else len(rows)
        if count >= sudo_threshold:
            flagged_sudo_users.add(user)
            add(rows["timestamp"].iloc[0], user, "", "sudo", "MEDIUM",
                f"Privilege escalation attempt: {count} failed sudo for '{user}' "
                f"in {window_minutes} min")

    # ---------- Rule 5: isolated failures (below thresholds) ----------
    for ip, rows in login_failures.groupby("ip"):
        if ip not in flagged_ips:
            users = ", ".join(sorted(set(rows["user"]) - {""}))
            add(rows["timestamp"].iloc[-1], users, ip, "login", "LOW",
                f"{len(rows)} failed login(s) from {ip} (below brute-force threshold)")
    for user, rows in sudo_failures.groupby("user"):
        if user not in flagged_sudo_users:
            add(rows["timestamp"].iloc[-1], user, "", "sudo", "LOW",
                f"{len(rows)} failed sudo attempt(s) for '{user}'")

    # ---------- Rule 7: account changes (Windows 4720 / 4732) ----------
    first_compromise = min(compromise_times) if compromise_times else None
    for _, row in data[data["event"] == "account_created"].iterrows():
        after_attack = first_compromise is not None and pd.notna(row["ts"]) and row["ts"] >= first_compromise
        add(row["timestamp"], row["user"], row["ip"], "account_created",
            "CRITICAL" if after_attack else "MEDIUM",
            f"Possible backdoor: account '{row['user']}' created after a compromise"
            if after_attack else f"New user account created: '{row['user']}'")
    for _, row in data[data["event"] == "group_add"].iterrows():
        privileged = "admin" in row["message"].lower()
        add(row["timestamp"], row["user"], row["ip"], "group_add",
            "HIGH" if privileged else "MEDIUM",
            f"'{row['user']}' added to the Administrators group (privilege escalation)"
            if privileged else f"'{row['user']}' added to a security group")

    for _, row in data[data["event"] == "account_locked"].iterrows():
        add(row["timestamp"], row["user"], row["ip"], "account_locked", "MEDIUM",
            f"Account '{row['user']}' locked out after repeated failed logons")
    for _, row in data[data["event"] == "account_deleted"].iterrows():
        add(row["timestamp"], row["user"], row["ip"], "account_deleted", "MEDIUM",
            f"User account deleted: '{row['user']}'")

    # ---------- Rule 6: log level ----------
    for _, row in data[data["level"].str.contains(r"critical|fatal", case=False, regex=True)].iterrows():
        add(row["timestamp"], row["user"], row["ip"], row["event"], "CRITICAL",
            "Critical or fatal log event" + (f": {row['message']}" if row["message"] else ""))
    for _, row in data[data["level"].str.fullmatch(r"error", case=False)].iterrows():
        add(row["timestamp"], row["user"], row["ip"], row["event"], "MEDIUM",
            "Error-level log event" + (f": {row['message']}" if row["message"] else ""))

    result = pd.DataFrame(findings, columns=COLUMNS)
    if not result.empty:
        result["_order"] = result["severity"].map(SEVERITY_ORDER)
        result = result.sort_values(["_order", "timestamp"]).drop(columns="_order")
        result = result.reset_index(drop=True)
    return result