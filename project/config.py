import os
import secrets
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)


def _load_secret_key():
    """Use SECRET_KEY from the environment, or create one once and keep it in
    instance/secret_key.txt so logins survive an app restart."""
    from_env = os.environ.get("SECRET_KEY")
    if from_env:
        return from_env
    path = os.path.join(INSTANCE_DIR, "secret_key.txt")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


class Config:
    SECRET_KEY = _load_secret_key()
    DATABASE = os.environ.get("DATABASE_PATH", os.path.join(INSTANCE_DIR, "perspectos.db"))

    # Session cookie safety. Set SESSION_COOKIE_SECURE=1 when serving over HTTPS.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)

    MAX_CONTENT_LENGTH = 64 * 1024  # reject request bodies bigger than 64 KB
    RATELIMIT_ENABLED = os.environ.get("RATELIMIT_ENABLED", "1") != "0"

    CATEGORIES = [
        "General", "Society", "Technology", "Philosophy",
        "Life", "Money", "Education", "Culture",
    ]
