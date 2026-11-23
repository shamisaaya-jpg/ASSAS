import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from dotenv import load_dotenv
from flask import (Flask, Response, abort, redirect, render_template, request,
                   session, url_for)
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import db
import search_store
from charts import build_chart_data
from detection import detect_threats
from parsers import parse_log_file
from reports import build_report_csv, generate_summary

load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

_secret = os.getenv("SECRET_KEY")
if not _secret:
    # Never fall back to a known value: a guessable key lets anyone forge sessions.
    _secret = secrets.token_hex(32)
    app.logger.warning("SECRET_KEY is not set: using a random key, sessions end on restart. "
                       "Set SECRET_KEY in .env (see .env.example).")
app.config.update(
    SECRET_KEY=_secret,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
    REMEMBER_COOKIE_HTTPONLY=True,
)

UPLOAD_DIR = Path("uploads")
ALLOWED_EXTENSIONS = {".csv", ".json", ".log", ".txt"}

UPLOAD_DIR.mkdir(exist_ok=True)


# ---------- CSRF protection ----------

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        sent = request.form.get("csrf_token", "")
        expected = session.get("_csrf", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, description="Invalid or missing CSRF token. Reload the page and try again.")


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


# ---------- Login ----------

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access ASSAS."

# Simple in-memory brute-force protection for the ASSAS login itself.
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60
_failed_logins = defaultdict(deque)
# Compared against when the username does not exist, so timing does not reveal valid users.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


def _too_many_failures(ip):
    attempts = _failed_logins[ip]
    while attempts and time.monotonic() - attempts[0] > LOGIN_WINDOW_SECONDS:
        attempts.popleft()
    return len(attempts) >= LOGIN_MAX_FAILURES


def _safe_next(target):
    """Only allow redirects to a local path (prevents open redirects)."""
    if not target:
        return None
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//") \
            or "\\" in target:
        return None
    return target


class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]


@login_manager.user_loader
def load_user(user_id):
    try:
        row = db.get_user_by_id(int(user_id))
    except ValueError:
        return None
    return User(row) if row else None


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if _too_many_failures(ip):
            return render_template(
                "login.html", error="Too many failed attempts. Try again in a few minutes."
            ), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = db.get_user_by_username(username)
        valid = check_password_hash(row["password_hash"] if row else _DUMMY_HASH, password)

        if row and valid:
            _failed_logins.pop(ip, None)
            session.clear()  # new session on login (prevents session fixation)
            login_user(User(row))
            return redirect(_safe_next(request.args.get("next")) or url_for("home"))

        _failed_logins[ip].append(time.monotonic())
        # ASSAS logs failed logins on itself too (%r keeps newlines out of the log)
        app.logger.warning("Failed ASSAS login for %r from %s", username[:50], ip)
        return render_template("login.html", error="Invalid username or password."), 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))


# ---------- Analysis ----------

@app.route("/")
@login_required
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    uploaded = request.files.get("logfile")

    if not uploaded or not uploaded.filename:
        return render_template(
            "index.html", error="Please select a log file."
        ), 400

    filename = secure_filename(uploaded.filename) or "upload"
    extension = Path(uploaded.filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        return render_template(
            "index.html", error="Only CSV, JSON, LOG and TXT files are supported."
        ), 400

    # Use a unique temporary filename to avoid filename collisions.
    saved_path = UPLOAD_DIR / f"{uuid4().hex}{extension}"

    try:
        uploaded.save(saved_path)
        logs = parse_log_file(str(saved_path))

        threats = detect_threats(logs)
        summary = generate_summary(threats)

        # Save the analysis and its alerts in PostgreSQL
        analysis_id = db.save_analysis(filename, summary, threats, current_user.id)

        # Store every raw log event in OpenSearch (for the Search page)
        try:
            indexed = search_store.index_logs(logs, filename, analysis_id)
            notice = f"{indexed} log events stored in OpenSearch."
        except Exception:
            app.logger.exception("OpenSearch indexing failed")
            notice = "Analysis saved, but OpenSearch is not reachable: logs were not indexed."

        return render_template(
            "index.html",
            summary=summary,
            threats=threats.fillna("").to_dict(orient="records"),
            charts=build_chart_data(logs, threats),
            notice=notice,
            analysis_id=analysis_id,
        )

    except (ValueError, UnicodeError) as exc:
        return render_template(
            "index.html", error=f"Could not analyze file: {exc}"
        ), 400

    except db.psycopg2.OperationalError:
        raise

    except Exception:
        app.logger.exception("Log analysis failed")
        return render_template(
            "index.html",
            error="An unexpected error occurred while analyzing the file.",
        ), 500

    finally:
        saved_path.unlink(missing_ok=True)


@app.route("/search")
@login_required
def search():
    fields = ["user", "ip", "event", "status", "os_name", "text", "date_from", "date_to"]
    f = {name: request.args.get(name, "").strip()[:200] for name in fields}
    try:
        total, rows, facets = search_store.search_logs(**f)
        error = None
    except Exception:
        app.logger.exception("OpenSearch search failed")
        total, rows, facets = 0, [], {"events": [], "statuses": [], "systems": []}
        error = "OpenSearch is not reachable. Open Docker Desktop and run: docker compose up -d"
    return render_template("search.html", f=f, total=total, rows=rows,
                           facets=facets, error=error)


@app.route("/history")
@login_required
def history():
    severity = request.args.get("severity", "").upper()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        severity = None
    return render_template(
        "history.html",
        analyses=db.list_analyses(),
        alerts=db.list_alerts(severity=severity),
        severity=severity,
    )


@app.route("/download/<int:analysis_id>")
@login_required
def download_report(analysis_id):
    analysis = db.get_analysis(analysis_id)
    if analysis is None:
        abort(404)

    stem = Path(analysis["filename"] or "log").stem
    return Response(
        build_report_csv(db.get_alerts_for_analysis(analysis_id)),
        mimetype="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="threat_report_{analysis_id}_{secure_filename(stem)}.csv"'},
    )


@app.errorhandler(db.psycopg2.OperationalError)
def database_unavailable(_error):
    app.logger.error("PostgreSQL is not reachable")
    return render_template(
        "login.html",
        error="Database unavailable. Open Docker Desktop and run: docker compose up -d",
    ), 503


@app.errorhandler(413)
def file_too_large(_error):
    return render_template(
        "index.html",
        error="File is too large. Maximum size is 10 MB.",
    ), 413


@app.cli.command("init-db")
def init_db_command():
    """Create the PostgreSQL tables."""
    db.init_db()
    print("Database ready.")


if __name__ == "__main__":
    db.init_db()
    # Debug mode exposes an interactive debugger (remote code execution): opt-in only.
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1",
            host=os.getenv("ASSAS_HOST", "127.0.0.1"),
            port=int(os.getenv("ASSAS_PORT", "5001")))
