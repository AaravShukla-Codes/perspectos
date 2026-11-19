"""Perspectos - a community discussion platform.

Run:  python app.py        (then open http://127.0.0.1:5000)
Make someone an admin:  python app.py makeadmin <username>
The FIRST account that registers automatically becomes the admin.
"""
import hmac
import re
import secrets
import sqlite3
import sys
import time
import unicodedata
from collections import defaultdict, deque
from datetime import datetime
from functools import wraps

from flask import Flask, abort, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import database
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
database.init_app(app)

db = database.get_db  # shortcut: db().execute(...)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def api_error(message, status=400):
    return jsonify(error=message), status


def iso(ts):
    """'2026-11-19 10:30:00' (UTC, from SQLite) -> '2026-11-19T10:30:00Z' for JavaScript."""
    return ts.replace(" ", "T") + "Z" if ts else None


@app.template_filter("pretty_date")
def pretty_date(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").strftime("%d %b %Y")
    except (TypeError, ValueError):
        return ""


CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def get_json():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def text_field(data, key, multiline=False):
    """Read a string from the JSON body, remove control characters and trim it."""
    value = data.get(key, "")
    if not isinstance(value, str):
        return ""
    value = CONTROL_CHARS.sub("", value).replace("\r\n", "\n").replace("\r", "\n")
    if multiline:
        value = re.sub(r"\n{3,}", "\n\n", value)
    else:
        value = " ".join(value.split())
    return value.strip()


def int_arg(name, default, low, high):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_word(word):
    """One word: 1-30 characters, letters/numbers only (any language), no spaces."""
    if not 1 <= len(word) <= 30:
        return False
    # L = letters, N = numbers, M = combining marks (needed for scripts like Hindi)
    return all(unicodedata.category(ch)[0] in ("L", "N", "M") for ch in word)


# --------------------------------------------------------------------------
# Security: current user, CSRF, rate limiting, headers
# --------------------------------------------------------------------------
@app.before_request
def load_user():
    g.user = None
    if request.endpoint == "static":
        return
    user_id = session.get("user_id")
    if user_id:
        g.user = db().execute(
            "SELECT id, username, bio, is_admin, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if g.user is None:  # account no longer exists
            session.clear()


def get_csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.before_request
def check_csrf():
    """Every request that changes data must send the secret token in a header.
    A malicious website cannot read our token, so it cannot forge requests."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        expected = session.get("csrf", "")
        sent = request.headers.get("X-CSRF-Token", "")
        if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
            return api_error("Security check failed. Please refresh the page and try again.", 403)


_hits = defaultdict(deque)  # (bucket, ip) -> timestamps of recent requests


def rate_limit(bucket, limit, seconds):
    """Allow at most `limit` calls per `seconds` per IP address.
    (Kept in memory: simple, but resets on restart and is per-process.)"""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if app.config["RATELIMIT_ENABLED"]:
                now = time.monotonic()
                recent = _hits[(bucket, request.remote_addr)]
                while recent and now - recent[0] > seconds:
                    recent.popleft()
                if len(recent) >= limit:
                    response, status = api_error("Too many requests. Please slow down and try again shortly.", 429)
                    response.headers["Retry-After"] = str(int(seconds - (now - recent[0])) + 1)
                    return response, status
                recent.append(now)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            if request.path.startswith("/api/"):
                return api_error("Please log in first.", 401)
            return redirect(url_for("login_page", next=request.path))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            if request.path.startswith("/api/"):
                return api_error("Please log in first.", 401)
            return redirect(url_for("login_page", next=request.path))
        if not g.user["is_admin"]:
            return api_error("Admins only.", 403)
        return view(*args, **kwargs)
    return wrapper


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.context_processor
def inject_template_globals():
    return {"csrf_token": get_csrf_token(), "me": g.get("user"), "categories": app.config["CATEGORIES"]}


@app.errorhandler(HTTPException)
def handle_http_error(error):
    if request.path.startswith("/api/"):
        return api_error(error.description, error.code)
    return render_template("error.html", code=error.code, message=error.name), error.code


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    app.logger.exception(error)
    if request.path.startswith("/api/"):
        return api_error("Something went wrong on our side.", 500)
    return render_template("error.html", code=500, message="Something went wrong"), 500


# --------------------------------------------------------------------------
# Pages (HTML)
# --------------------------------------------------------------------------
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/login")
def login_page():
    if g.user:
        return redirect(url_for("index"))
    return render_template("login.html")


@app.get("/register")
def register_page():
    if g.user:
        return redirect(url_for("index"))
    return render_template("register.html")


@app.get("/topic/<int:topic_id>")
def topic_page(topic_id):
    row = fetch_topic(topic_id)
    if row is None:
        abort(404)
    return render_template("topic.html", topic=topic_dict(row))


@app.get("/user/<username>")
def profile_page(username):
    profile = db().execute(
        "SELECT id, username, bio, created_at FROM users WHERE username = ?", (username,)
    ).fetchone()
    if profile is None:
        abort(404)
    topics = [topic_dict(r) for r in query_topics("t.user_id = ?", (profile["id"],), "recent", 50)]
    participation = db().execute(
        """SELECT t.id, t.word, COUNT(c.id) AS my_comments, MAX(c.created_at) AS last_at
           FROM comments c JOIN topics t ON t.id = c.topic_id
           WHERE c.user_id = ?
           GROUP BY t.id ORDER BY last_at DESC, t.id DESC LIMIT 50""",
        (profile["id"],),
    ).fetchall()
    total_comments = db().execute(
        "SELECT COUNT(*) FROM comments WHERE user_id = ?", (profile["id"],)
    ).fetchone()[0]
    return render_template(
        "profile.html", profile=profile, topics=topics,
        participation=participation, total_comments=total_comments,
    )


@app.get("/admin")
@admin_required
def admin_page():
    return render_template("admin.html")


# --------------------------------------------------------------------------
# API: authentication
# --------------------------------------------------------------------------
@app.get("/api/me")
def api_me():
    user = None
    if g.user:
        user = {"id": g.user["id"], "username": g.user["username"], "is_admin": bool(g.user["is_admin"])}
    return jsonify(user=user, csrf_token=get_csrf_token())


@app.post("/api/register")
@rate_limit("register", 10, 600)
def api_register():
    data = get_json()
    username = text_field(data, "username")
    email = text_field(data, "email").lower()
    password = data.get("password")

    if not USERNAME_RE.match(username):
        return api_error("Username must be 3-20 characters: letters, numbers or underscore.")
    if len(email) > 120 or not EMAIL_RE.match(email):
        return api_error("Please enter a valid email address.")
    if not isinstance(password, str) or not 8 <= len(password) <= 128:
        return api_error("Password must be between 8 and 128 characters.")

    conn = db()
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        return api_error("That username is already taken.", 409)
    if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        return api_error("That email is already registered.", 409)

    is_admin = 1 if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0 else 0
    try:
        cursor = conn.execute(
            "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)",
            (username, email, generate_password_hash(password), is_admin),
        )
        conn.commit()
    except sqlite3.IntegrityError:  # two people registered the same name at once
        return api_error("That username or email is already in use.", 409)

    session.clear()
    session["user_id"] = cursor.lastrowid
    session.permanent = True
    get_csrf_token()
    return jsonify(ok=True, username=username), 201


@app.post("/api/login")
@rate_limit("login", 10, 60)
def api_login():
    data = get_json()
    identifier = text_field(data, "username")  # username or email
    password = data.get("password")
    user = None
    if identifier and isinstance(password, str):
        user = db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ? OR email = ?",
            (identifier, identifier.lower()),
        ).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return api_error("Wrong username or password.", 401)

    session.clear()  # start a fresh session (prevents session fixation)
    session["user_id"] = user["id"]
    session.permanent = True
    get_csrf_token()
    return jsonify(ok=True, username=user["username"])


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify(ok=True)


# --------------------------------------------------------------------------
# API: topics
# --------------------------------------------------------------------------
TOPIC_COLUMNS = """
    t.id, t.word, t.description, t.category, t.created_at, t.user_id, u.username,
    (SELECT COUNT(*) FROM comments c WHERE c.topic_id = t.id) AS comment_count,
    (SELECT COUNT(*) FROM comments c
        WHERE c.topic_id = t.id AND c.created_at >= datetime('now', '-7 days')) AS recent_count,
    (SELECT COUNT(*) FROM reactions r JOIN comments c ON c.id = r.comment_id
        WHERE c.topic_id = t.id AND r.value = 1) AS like_count
"""

# Sort choices (whitelist: user input only picks a key, never becomes SQL).
SORTS = {
    "recent": "t.created_at DESC, t.id DESC",
    "discussed": "comment_count DESC, t.created_at DESC, t.id DESC",
    "popular": "like_count DESC, comment_count DESC, t.created_at DESC, t.id DESC",
    "trending": "recent_count DESC, comment_count DESC, t.created_at DESC, t.id DESC",
}


def query_topics(where="1 = 1", params=(), sort="recent", limit=20, offset=0):
    # `where` and `sort` come from this file only; user values go in `params`.
    sql = (
        f"SELECT {TOPIC_COLUMNS} FROM topics t JOIN users u ON u.id = t.user_id "
        f"WHERE {where} ORDER BY {SORTS[sort]} LIMIT ? OFFSET ?"
    )
    return db().execute(sql, (*params, limit, offset)).fetchall()


def fetch_topic(topic_id):
    rows = query_topics("t.id = ?", (topic_id,), "recent", 1)
    return rows[0] if rows else None


def topic_dict(row):
    return {
        "id": row["id"], "word": row["word"], "description": row["description"],
        "category": row["category"], "created_at": row["created_at"],
        "author": row["username"], "author_id": row["user_id"],
        "comment_count": row["comment_count"], "like_count": row["like_count"],
    }


@app.get("/api/topics")
def api_topics():
    q = request.args.get("q", "").strip()[:50]
    category = request.args.get("category", "").strip()
    sort = request.args.get("sort", "recent")
    if sort not in SORTS:
        sort = "recent"
    limit = int_arg("limit", 20, 1, 50)
    offset = int_arg("offset", 0, 0, 100000)

    conditions, params = ["1 = 1"], []
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        conditions.append(r"(t.word LIKE ? ESCAPE '\' OR t.description LIKE ? ESCAPE '\')")
        params += [like, like]
    if category:
        conditions.append("t.category = ?")
        params.append(category)

    rows = query_topics(" AND ".join(conditions), params, sort, limit + 1, offset)
    return jsonify(topics=[topic_dict(r) for r in rows[:limit]], has_more=len(rows) > limit)


@app.post("/api/topics")
@login_required
@rate_limit("topic", 10, 600)
def api_create_topic():
    data = get_json()
    word = text_field(data, "word")
    description = text_field(data, "description")
    category = text_field(data, "category") or "General"

    if not valid_word(word):
        return api_error("A topic must be ONE word: letters or numbers only, up to 30 characters.")
    if len(description) > 200:
        return api_error("Description can be at most 200 characters.")
    if category not in app.config["CATEGORIES"]:
        return api_error("Please choose a valid category.")

    conn = db()
    existing = conn.execute("SELECT id FROM topics WHERE word_key = ?", (word.casefold(),)).fetchone()
    if existing:
        return jsonify(error="That word already has a discussion.", topic_id=existing["id"]), 409
    try:
        cursor = conn.execute(
            "INSERT INTO topics (word, word_key, description, category, user_id) VALUES (?, ?, ?, ?, ?)",
            (word, word.casefold(), description, category, g.user["id"]),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return api_error("That word already has a discussion.", 409)
    return jsonify(topic=topic_dict(fetch_topic(cursor.lastrowid))), 201


@app.get("/api/topics/<int:topic_id>")
def api_get_topic(topic_id):
    row = fetch_topic(topic_id)
    if row is None:
        return api_error("Topic not found.", 404)
    return jsonify(topic=topic_dict(row))


@app.put("/api/topics/<int:topic_id>")
@login_required
@rate_limit("topic-edit", 30, 60)
def api_edit_topic(topic_id):
    row = fetch_topic(topic_id)
    if row is None:
        return api_error("Topic not found.", 404)
    if row["user_id"] != g.user["id"]:  # ownership check
        return api_error("You can only edit your own topics.", 403)

    data = get_json()
    description = text_field(data, "description")
    category = text_field(data, "category") or row["category"]
    if len(description) > 200:
        return api_error("Description can be at most 200 characters.")
    if category not in app.config["CATEGORIES"]:
        return api_error("Please choose a valid category.")

    db().execute("UPDATE topics SET description = ?, category = ? WHERE id = ?", (description, category, topic_id))
    db().commit()
    return jsonify(topic=topic_dict(fetch_topic(topic_id)))


@app.delete("/api/topics/<int:topic_id>")
@login_required
def api_delete_topic(topic_id):
    row = fetch_topic(topic_id)
    if row is None:
        return api_error("Topic not found.", 404)
    if row["user_id"] != g.user["id"] and not g.user["is_admin"]:
        return api_error("You can only delete your own topics.", 403)
    db().execute("DELETE FROM topics WHERE id = ?", (topic_id,))  # comments, reactions, reports cascade
    db().commit()
    return jsonify(ok=True)


# --------------------------------------------------------------------------
# API: comments and replies
# --------------------------------------------------------------------------
def load_comments(where, params):
    """Comments with author, like/dislike counts and the current user's reaction."""
    me_id = g.user["id"] if g.user else 0
    # `where` is written in this file only; user values always go in `params`.
    sql = f"""
        SELECT c.id, c.topic_id, c.parent_id, c.body, c.created_at, c.edited_at, c.user_id, u.username,
               COALESCE(SUM(CASE WHEN r.value = 1  THEN 1 END), 0) AS likes,
               COALESCE(SUM(CASE WHEN r.value = -1 THEN 1 END), 0) AS dislikes,
               MAX(CASE WHEN r.user_id = ? THEN r.value END)       AS my_reaction
        FROM comments c
        JOIN users u ON u.id = c.user_id
        LEFT JOIN reactions r ON r.comment_id = c.id
        WHERE {where}
        GROUP BY c.id
        ORDER BY c.created_at ASC, c.id ASC"""
    result = []
    for row in db().execute(sql, (me_id, *params)).fetchall():
        mine = row["user_id"] == me_id
        result.append({
            "id": row["id"], "topic_id": row["topic_id"], "parent_id": row["parent_id"],
            "body": row["body"], "created_at": iso(row["created_at"]), "edited_at": iso(row["edited_at"]),
            "author": row["username"], "likes": row["likes"], "dislikes": row["dislikes"],
            "my_reaction": row["my_reaction"] or 0,
            "mine": mine,
            "can_delete": mine or bool(g.user and g.user["is_admin"]),
        })
    return result


def fetch_comment(comment_id):
    return db().execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()


def valid_comment_body(body):
    if not 1 <= len(body) <= 1000:
        return "A comment must be between 1 and 1000 characters."
    return None


@app.get("/api/topics/<int:topic_id>/comments")
def api_get_comments(topic_id):
    if fetch_topic(topic_id) is None:
        return api_error("Topic not found.", 404)
    comments = load_comments("c.topic_id = ?", (topic_id,))
    return jsonify(comments=comments, total=len(comments))


@app.post("/api/topics/<int:topic_id>/comments")
@login_required
@rate_limit("comment", 20, 60)
def api_add_comment(topic_id):
    if fetch_topic(topic_id) is None:
        return api_error("Topic not found.", 404)
    data = get_json()
    body = text_field(data, "body", multiline=True)
    problem = valid_comment_body(body)
    if problem:
        return api_error(problem)

    parent_id = data.get("parent_id")
    if parent_id is not None:
        parent = fetch_comment(parent_id) if isinstance(parent_id, int) and not isinstance(parent_id, bool) else None
        if parent is None or parent["topic_id"] != topic_id:
            return api_error("The comment you are replying to does not exist.", 404)

    cursor = db().execute(
        "INSERT INTO comments (topic_id, user_id, parent_id, body) VALUES (?, ?, ?, ?)",
        (topic_id, g.user["id"], parent_id, body),
    )
    db().commit()
    return jsonify(comment=load_comments("c.id = ?", (cursor.lastrowid,))[0]), 201


@app.put("/api/comments/<int:comment_id>")
@login_required
@rate_limit("comment-edit", 30, 60)
def api_edit_comment(comment_id):
    row = fetch_comment(comment_id)
    if row is None:
        return api_error("Comment not found.", 404)
    if row["user_id"] != g.user["id"]:
        return api_error("You can only edit your own comments.", 403)
    body = text_field(get_json(), "body", multiline=True)
    problem = valid_comment_body(body)
    if problem:
        return api_error(problem)
    db().execute("UPDATE comments SET body = ?, edited_at = datetime('now') WHERE id = ?", (body, comment_id))
    db().commit()
    return jsonify(comment=load_comments("c.id = ?", (comment_id,))[0])


@app.delete("/api/comments/<int:comment_id>")
@login_required
def api_delete_comment(comment_id):
    row = fetch_comment(comment_id)
    if row is None:
        return api_error("Comment not found.", 404)
    if row["user_id"] != g.user["id"] and not g.user["is_admin"]:
        return api_error("You can only delete your own comments.", 403)
    db().execute("DELETE FROM comments WHERE id = ?", (comment_id,))  # replies and reactions cascade
    db().commit()
    return jsonify(ok=True)


# --------------------------------------------------------------------------
# API: reactions (like / dislike)
# --------------------------------------------------------------------------
@app.post("/api/comments/<int:comment_id>/react")
@login_required
@rate_limit("react", 60, 60)
def api_react(comment_id):
    if fetch_comment(comment_id) is None:
        return api_error("Comment not found.", 404)
    value = get_json().get("value")
    if value not in (1, -1, 0) or isinstance(value, bool):
        return api_error("Reaction must be 1 (like), -1 (dislike) or 0 (remove).")

    conn = db()
    if value == 0:
        conn.execute("DELETE FROM reactions WHERE comment_id = ? AND user_id = ?", (comment_id, g.user["id"]))
    else:  # insert, or change the existing reaction
        conn.execute(
            """INSERT INTO reactions (comment_id, user_id, value) VALUES (?, ?, ?)
               ON CONFLICT (comment_id, user_id) DO UPDATE SET value = excluded.value""",
            (comment_id, g.user["id"], value),
        )
    conn.commit()
    c = load_comments("c.id = ?", (comment_id,))[0]
    return jsonify(likes=c["likes"], dislikes=c["dislikes"], my_reaction=c["my_reaction"])


# --------------------------------------------------------------------------
# API: reports and admin moderation
# --------------------------------------------------------------------------
@app.post("/api/report")
@login_required
@rate_limit("report", 10, 600)
def api_report():
    data = get_json()
    kind = data.get("type")
    target_id = data.get("id")
    reason = text_field(data, "reason", multiline=True)
    if kind not in ("topic", "comment") or not isinstance(target_id, int) or isinstance(target_id, bool):
        return api_error("Invalid report.")
    if not 3 <= len(reason) <= 300:
        return api_error("Please give a reason (3-300 characters).")

    if kind == "topic":
        target = fetch_topic(target_id)
        owner_id = target["user_id"] if target else None
        column = "topic_id"
    else:
        target = fetch_comment(target_id)
        owner_id = target["user_id"] if target else None
        column = "comment_id"
    if target is None:
        return api_error("That content no longer exists.", 404)
    if owner_id == g.user["id"]:
        return api_error("You cannot report your own content.")

    # `column` is one of two fixed words chosen above, never user input.
    already = db().execute(
        f"SELECT 1 FROM reports WHERE reporter_id = ? AND {column} = ?", (g.user["id"], target_id)
    ).fetchone()
    if already:
        return api_error("You have already reported this.", 409)
    db().execute(
        f"INSERT INTO reports (reporter_id, {column}, reason) VALUES (?, ?, ?)",
        (g.user["id"], target_id, reason),
    )
    db().commit()
    return jsonify(ok=True), 201


@app.get("/api/admin/reports")
@admin_required
def api_admin_reports():
    status = "dismissed" if request.args.get("status") == "dismissed" else "open"
    rows = db().execute(
        """SELECT r.id, r.reason, r.status, r.created_at, ru.username AS reporter,
                  r.topic_id, r.comment_id,
                  t.word AS topic_word, t.description AS topic_description, tu.username AS topic_author,
                  c.body AS comment_body, c.topic_id AS comment_topic_id, cu.username AS comment_author,
                  ct.word AS comment_topic_word
           FROM reports r
           JOIN users ru        ON ru.id = r.reporter_id
           LEFT JOIN topics t   ON t.id = r.topic_id
           LEFT JOIN users tu   ON tu.id = t.user_id
           LEFT JOIN comments c ON c.id = r.comment_id
           LEFT JOIN users cu   ON cu.id = c.user_id
           LEFT JOIN topics ct  ON ct.id = c.topic_id
           WHERE r.status = ?
           ORDER BY r.created_at DESC, r.id DESC""",
        (status,),
    ).fetchall()
    reports = []
    for r in rows:
        is_topic = r["topic_id"] is not None
        reports.append({
            "id": r["id"], "type": "topic" if is_topic else "comment",
            "target_id": r["topic_id"] if is_topic else r["comment_id"],
            "topic_id": r["topic_id"] if is_topic else r["comment_topic_id"],
            "topic_word": r["topic_word"] if is_topic else r["comment_topic_word"],
            "preview": r["topic_description"] if is_topic else r["comment_body"],
            "author": r["topic_author"] if is_topic else r["comment_author"],
            "reason": r["reason"], "reporter": r["reporter"],
            "status": r["status"], "created_at": iso(r["created_at"]),
        })
    return jsonify(reports=reports)


@app.post("/api/admin/reports/<int:report_id>/dismiss")
@admin_required
def api_admin_dismiss(report_id):
    cursor = db().execute("UPDATE reports SET status = 'dismissed' WHERE id = ?", (report_id,))
    db().commit()
    if cursor.rowcount == 0:
        return api_error("Report not found.", 404)
    return jsonify(ok=True)


@app.post("/api/admin/reports/<int:report_id>/remove")
@admin_required
def api_admin_remove(report_id):
    report = db().execute("SELECT topic_id, comment_id FROM reports WHERE id = ?", (report_id,)).fetchone()
    if report is None:
        return api_error("Report not found.", 404)
    if report["topic_id"] is not None:
        db().execute("DELETE FROM topics WHERE id = ?", (report["topic_id"],))
    else:
        db().execute("DELETE FROM comments WHERE id = ?", (report["comment_id"],))
    db().commit()  # reports about the removed content are deleted by cascade
    return jsonify(ok=True)


# --------------------------------------------------------------------------
# API: profile
# --------------------------------------------------------------------------
@app.put("/api/profile")
@login_required
@rate_limit("profile", 10, 60)
def api_edit_profile():
    data = get_json()
    username = text_field(data, "username") or g.user["username"]
    bio = text_field(data, "bio", multiline=True)
    if not USERNAME_RE.match(username):
        return api_error("Username must be 3-20 characters: letters, numbers or underscore.")
    if len(bio) > 300:
        return api_error("Bio can be at most 300 characters.")
    try:
        db().execute("UPDATE users SET username = ?, bio = ? WHERE id = ?", (username, bio, g.user["id"]))
        db().commit()
    except sqlite3.IntegrityError:
        return api_error("That username is already taken.", 409)
    return jsonify(ok=True, username=username)


# --------------------------------------------------------------------------
# Command line + start
# --------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "makeadmin":
        with app.app_context():
            cursor = db().execute("UPDATE users SET is_admin = 1 WHERE username = ?", (sys.argv[2],))
            db().commit()
            print(f"{sys.argv[2]} is now an admin." if cursor.rowcount else "No user with that username.")
    else:
        import os
        app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
