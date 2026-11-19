import sqlite3

from flask import current_app, g

# Every table is created only if it does not exist yet, so existing data is
# kept when the app restarts.
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    bio           TEXT NOT NULL DEFAULT '',
    is_admin      INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS topics (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    word        TEXT NOT NULL,
    word_key    TEXT NOT NULL UNIQUE,          -- lowercase copy, so FREEDOM = freedom
    description TEXT NOT NULL DEFAULT '',
    category    TEXT NOT NULL DEFAULT 'General',
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    topic_id   INTEGER NOT NULL REFERENCES topics(id)   ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    parent_id  INTEGER REFERENCES comments(id)          ON DELETE CASCADE,  -- NULL = top-level
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    edited_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_comments_topic  ON comments(topic_id);
CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments(parent_id);
CREATE INDEX IF NOT EXISTS idx_comments_user   ON comments(user_id);

CREATE TABLE IF NOT EXISTS reactions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    comment_id INTEGER NOT NULL REFERENCES comments(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    value      INTEGER NOT NULL CHECK (value IN (1, -1)),   -- 1 = like, -1 = dislike
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (comment_id, user_id)                            -- one reaction per user per comment
);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    topic_id    INTEGER REFERENCES topics(id)            ON DELETE CASCADE,
    comment_id  INTEGER REFERENCES comments(id)          ON DELETE CASCADE,
    reason      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'dismissed')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    -- a report is about a topic OR a comment, never both
    CHECK ((topic_id IS NULL) <> (comment_id IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_report_topic
    ON reports(reporter_id, topic_id)   WHERE topic_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_report_comment
    ON reports(reporter_id, comment_id) WHERE comment_id IS NOT NULL;
"""


def get_db():
    """One database connection per request."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")  # needed for ON DELETE CASCADE
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()  # creates the tables automatically on startup
