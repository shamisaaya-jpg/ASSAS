"""Generate a demo Windows Security CSV (same columns as export_windows_logs.ps1)."""
import csv
import random
from datetime import datetime, timedelta

random.seed(11)
rows = []
start = datetime(2026, 11, 21, 8, 0, 0)


def add(ts, event_id, user, ip, message):
    rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), event_id, user, ip, "WIN-PC01", message])


# Normal office logons
staff = [("aya", "192.168.56.1"), ("omar", "192.168.56.21"), ("sara", "192.168.56.22")]
for hour in range(8, 19):
    for _ in range(random.randint(1, 3)):
        user, ip = random.choice(staff)
        ts = start.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
        if random.random() < 0.2:
            add(ts, 4625, user, ip, "An account failed to log on. Failure Reason: Unknown user name or bad password.")
        add(ts + timedelta(seconds=8), 4624, user, ip, "An account was successfully logged on. Logon Type: 3")

# RDP / SMB brute force from Kali at 20h
ts = start.replace(hour=20, minute=5)
for _ in range(40):
    user = random.choice(["Administrator", "Administrator", "admin", "guest"])
    add(ts, 4625, user, "192.168.56.10", "An account failed to log on. Failure Reason: Unknown user name or bad password.")
    ts += timedelta(seconds=random.randint(1, 5))

# The attacker gets in...
ts += timedelta(seconds=4)
add(ts, 4624, "Administrator", "192.168.56.10", "An account was successfully logged on. Logon Type: 10")

# ...creates a backdoor account and makes it administrator
ts += timedelta(minutes=1)
add(ts, 4720, "backdoor", "", "A user account was created. New Account: Account Name: backdoor")
ts += timedelta(seconds=20)
add(ts, 4732, "backdoor", "", "A member was added to a security-enabled local group. Group Name: Administrators")

rows.sort()
with open("sample_logs/windows_security.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["TimeCreated", "EventID", "User", "IP", "Computer", "Message"])
    writer.writerows(rows)
print(f"{len(rows)} events written to sample_logs/windows_security.csv")
