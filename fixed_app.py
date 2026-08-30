"""
CodeAlpha Cyber Security Internship — Task 3: Secure Coding Review
Remediated version of vulnerable_app.py.

Every fix below is cross-referenced to a finding in security_review_report
(see the "Finding #" comments). This is a demonstration of the FIX, still
simplified for teaching purposes — a production app would add rate
limiting, structured logging, and CSRF protection on top of this.
"""

import os
import sqlite3
import html as html_lib
from functools import wraps

from flask import Flask, request, g, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Finding #1 fix — secret key now comes from the environment, never
# committed to source control. Fails loudly instead of silently using a
# weak default.
app.secret_key = os.environ["FLASK_SECRET_KEY"]

DATABASE = "notes.db"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    # Finding #3 fix — parameterized query. The DB driver treats
    # `username` strictly as data, never as SQL syntax, so `admin' --`
    # is just a literal string to match against, not a SQL fragment.
    cursor = get_db().execute(
        "SELECT id, password_hash, is_admin FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()

    # Finding #2 fix — no hardcoded credentials; passwords are checked
    # against a salted hash stored at signup time (never checked with ==).
    if row and check_password_hash(row[1], password):
        session.clear()
        session["user_id"] = row[0]
        session["is_admin"] = bool(row[2])
        return redirect("/notes")
    return "Invalid credentials", 401


@app.route("/notes")
@login_required
def notes():
    # Finding #4 fix — the user id comes from the server-side session,
    # set at login, not from a client-controlled query parameter. A user
    # can only ever see their own notes.
    user_id = session["user_id"]
    cursor = get_db().execute(
        "SELECT title, body FROM notes WHERE user_id = ?", (user_id,)
    )
    rows = cursor.fetchall()

    # Finding #5 fix — every piece of user-supplied content is HTML-escaped
    # before being placed in the response, so a title/body containing
    # <script> renders as inert text instead of executing.
    parts = ["<h1>Your Notes</h1>"]
    for title, body in rows:
        parts.append(f"<h3>{html_lib.escape(title)}</h3><p>{html_lib.escape(body)}</p>")
    return "".join(parts)


@app.route("/search")
@login_required
def search():
    term = request.args.get("q", "")
    # Finding #3 fix (same pattern) — parameterized LIKE query.
    cursor = get_db().execute(
        "SELECT title FROM notes WHERE user_id = ? AND title LIKE ?",
        (session["user_id"], f"%{term}%"),
    )
    return str(cursor.fetchall())


@app.route("/admin/user/<int:user_id>")
@login_required
@admin_required
def admin_user(user_id):
    # Finding #6 fix — now requires an authenticated admin session.
    # Finding #3 fix (same pattern) — parameterized query.
    # Also: no longer selects a raw "ssn" column at all — sensitive
    # identifiers should not be returned by a lookup endpoint like this
    # in the first place (data minimization).
    cursor = get_db().execute(
        "SELECT username, email FROM users WHERE id = ?", (user_id,)
    )
    return str(cursor.fetchone())


if __name__ == "__main__":
    # Finding #7 fix — debug mode is driven by an explicit environment
    # flag that defaults to OFF, and the app only binds to localhost by
    # default instead of every network interface.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=os.environ.get("FLASK_HOST", "127.0.0.1"), debug=debug_mode)
