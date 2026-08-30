"""
CodeAlpha Cyber Security Internship — Task 3: Secure Coding Review
Audit subject: a small Flask "user notes" application.

*** THIS FILE IS INTENTIONALLY INSECURE. ***
It exists ONLY as a training subject for the accompanying code review
(security_review_report.docx / .md). Do NOT deploy this app, and do not
copy these patterns into real projects. Every vulnerability found here is
listed with an explanation and fix recommendation in the review report.

App purpose: a tiny "notes" service. A user logs in, can view/search notes,
and an admin can look up any user's profile by ID.
"""

import sqlite3
from flask import Flask, request, g, redirect

app = Flask(__name__)

# ---------------------------------------------------------------------
# VULNERABILITY #1 — Hardcoded secret key committed to source control.
# A real deployment's session-signing key must come from an environment
# variable or secrets manager, never a literal in the repo.
# ---------------------------------------------------------------------
app.secret_key = "supersecret123"

DATABASE = "notes.db"

# ---------------------------------------------------------------------
# VULNERABILITY #2 — Hardcoded admin credentials.
# ---------------------------------------------------------------------
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    # -------------------------------------------------------------
    # VULNERABILITY #3 — SQL Injection.
    # User input is concatenated directly into the SQL string, so a
    # username like  admin' --  bypasses the password check entirely.
    # -------------------------------------------------------------
    query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor = get_db().execute(query)
    user = cursor.fetchone()

    if user:
        return redirect(f"/notes?user_id={user[0]}")
    return "Invalid credentials", 401


@app.route("/notes")
def notes():
    # -------------------------------------------------------------
    # VULNERABILITY #4 — Broken access control / IDOR.
    # user_id comes straight from the query string with no check that
    # the logged-in user actually owns it, so ?user_id=2 reads anyone's
    # notes.
    # -------------------------------------------------------------
    user_id = request.args.get("user_id")
    cursor = get_db().execute(f"SELECT title, body FROM notes WHERE user_id = {user_id}")
    rows = cursor.fetchall()

    # -------------------------------------------------------------
    # VULNERABILITY #5 — Stored/Reflected XSS.
    # Note titles and bodies are written into the HTML response with no
    # escaping, so a note containing <script> runs in every viewer's
    # browser.
    # -------------------------------------------------------------
    html = "<h1>Your Notes</h1>"
    for title, body in rows:
        html += f"<h3>{title}</h3><p>{body}</p>"
    return html


@app.route("/search")
def search():
    term = request.args.get("q", "")
    # Same SQL Injection pattern as VULNERABILITY #3, via the search box.
    query = f"SELECT title FROM notes WHERE title LIKE '%{term}%'"
    cursor = get_db().execute(query)
    return str(cursor.fetchall())


@app.route("/admin/user/<int:user_id>")
def admin_user(user_id):
    # -------------------------------------------------------------
    # VULNERABILITY #6 — Missing authentication/authorization.
    # There is no check that the caller is logged in, let alone an
    # admin, before returning another user's profile data.
    # -------------------------------------------------------------
    cursor = get_db().execute(f"SELECT username, email, ssn FROM users WHERE id = {user_id}")
    row = cursor.fetchone()
    return str(row)


@app.route("/debug")
def debug():
    # -------------------------------------------------------------
    # VULNERABILITY #7 — Debug mode / information disclosure.
    # app.run(debug=True) below enables the Werkzeug interactive
    # debugger in production, which allows arbitrary code execution
    # from the browser if an error is triggered.
    # -------------------------------------------------------------
    raise Exception("This route exists only to demonstrate the debug console risk.")


if __name__ == "__main__":
    # VULNERABILITY #7 (continued): debug=True + host="0.0.0.0" exposes
    # the interactive debugger to the whole network.
    app.run(host="0.0.0.0", debug=True)
