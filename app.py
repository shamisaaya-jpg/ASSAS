import os
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, send_file, url_for
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

import db
import search_store
from detection import detect_threats
from charts import build_chart_data
from parsers import parse_log_file
from reports import export_report, generate_summary

load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-me")

UPLOAD_DIR = Path("uploads")
REPORT_PATH = Path("reports") / "threat_report.csv"
ALLOWED_EXTENSIONS = {".csv", ".json", ".log", ".txt"}

UPLOAD_DIR.mkdir(exist_ok=True)


# ---------- Login ----------

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access ASSAS."


class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]


@login_manager.user_loader
def load_user(user_id):
    row = db.get_user_by_id(int(user_id))
    return User(row) if row else None


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = db.get_user_by_username(username)

        if row and check_password_hash(row["password_hash"], password):
            login_user(User(row))
            return redirect(request.args.get("next") or url_for("home"))

        # ASSAS logs failed logins on itself too
        app.logger.warning("Failed ASSAS login for '%s' from %s",
                           username, request.remote_addr)
        return render_template("login.html", error="Invalid username or password."), 401

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
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

    filename = secure_filename(uploaded.filename)
    extension = Path(filename).suffix.lower()

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
        export_report(threats, str(REPORT_PATH))

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
        )

    except (ValueError, UnicodeError) as exc:
        return render_template(
            "index.html", error=f"Could not analyze file: {exc}"
        ), 400

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
    fields = ["user", "ip", "event", "status", "text", "date_from", "date_to"]
    f = {name: request.args.get(name, "").strip() for name in fields}
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
    severity = request.args.get("severity") or None
    return render_template(
        "history.html",
        analyses=db.list_analyses(),
        alerts=db.list_alerts(severity=severity),
        severity=severity,
    )


@app.route("/download")
@login_required
def download_report():
    if not REPORT_PATH.exists():
        return "No report is available. Analyze a log file first.", 404

    return send_file(
        REPORT_PATH,
        as_attachment=True,
        download_name="threat_report.csv",
        mimetype="text/csv",
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


if __name__ == "__main__":
    db.init_db()
    app.run(debug=True, port=5001)
