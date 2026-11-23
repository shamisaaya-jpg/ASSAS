# ASSAS — Authentication & Security Log Analyzer

ASSAS is a small Flask SOC tool. Upload a Linux `auth.log`, a Windows Security
CSV or a JSON/CSV event export. It detects attacks, saves the alerts in
PostgreSQL, and indexes every raw event in OpenSearch so you can search it.

## Detection rules

| # | Rule | Severity |
|---|------|----------|
| 1 | Brute force: 5 or more failed logins from one IP within 5 minutes | HIGH |
| 2 | Successful login from a brute-forcing IP after the failures (possible compromise) | CRITICAL |
| 3 | Password spraying: one IP tries 3 or more different accounts | MEDIUM |
| 4 | 3 or more failed `sudo` attempts for one user within 5 minutes | MEDIUM |
| 5 | Isolated failures below those thresholds | LOW |
| 6 | Log level `critical`/`fatal` (CRITICAL) or `error` (MEDIUM) | CRITICAL / MEDIUM |
| 7 | Account created (CRITICAL if it happens after a compromise), user added to Administrators (HIGH) or another group, account locked out or deleted | CRITICAL / HIGH / MEDIUM |

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then set SECRET_KEY and the passwords
docker compose up -d          # PostgreSQL + OpenSearch, bound to 127.0.0.1 only
python create_admin.py        # create your login
python app.py                 # http://127.0.0.1:5001
```

Try it with the files in `sample_logs/`. To regenerate them, run
`make_demo_log.py` or `make_demo_windows.py`.

To export real Windows events, run `export_windows_logs.ps1` in an
Administrator PowerShell. It writes `windows_security.csv` to your Desktop.

## Security notes

- Set `SECRET_KEY` in `.env`. Without it ASSAS uses a random key, so everyone is logged out when the app restarts.
- Leave `FLASK_DEBUG=0` on any machine other people can reach. The Werkzeug debugger lets anyone run code on the server.
- If you serve ASSAS over HTTPS, set `SESSION_COOKIE_SECURE=1`.
- OpenSearch runs with its security plugin disabled, so its port is bound to `127.0.0.1`. Keep it that way.
- `POSTGRES_PASSWORD` only takes effect when the database volume is first created. To change the password on an existing volume, run `ALTER USER assas PASSWORD '...'` and update `DATABASE_URL` to match.
- All logged-in analysts share the history and the reports. ASSAS is a single-team tool.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The web tests need PostgreSQL. If it is not running, they are skipped.
