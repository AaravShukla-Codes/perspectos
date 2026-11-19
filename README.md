# Perspectos

**One Word. Unlimited Perspectives.**

Perspectos is a community discussion platform built around a single idea: someone drops one word, and everyone shares what it means to them. Instead of arguing over long threads, you see a wide range of viewpoints on the same word, such as *freedom*, *success* or *home*.

**Live demo:** https://perspectos.vercel.app

Built with Flask, SQLite and vanilla JavaScript. No heavy frameworks or external services.

## Features

- **Share a word:** create a topic with a short description and a category
- **Browse and search:** Trending, Latest and Most discussed sections, plus search and category filters
- **Discuss:** threaded comments and replies on every topic
- **React:** like or dislike comments (one reaction per user per comment)
- **User profiles:** see what each member has shared
- **Moderation:** report content, with an admin dashboard to dismiss or remove reports
- **Security basics:** hashed passwords, CSRF protection, per-IP rate limiting, secure session cookies, request size limits

Categories: General, Society, Technology, Philosophy, Life, Money, Education, Culture.

## Tech stack

| Layer     | Technology                      |
| --------- | ------------------------------- |
| Backend   | Python 3, Flask                 |
| Database  | SQLite (tables created automatically) |
| Frontend  | Jinja2 templates, HTML, CSS, vanilla JS |
| Production server | gunicorn                |

## Project structure

```
project/
├── app.py            # Routes, API, security helpers
├── config.py         # Settings and environment variables
├── database.py       # SQLite schema and connection handling
├── tests.py          # Automated tests
├── requirements.txt
├── static/           # CSS and JavaScript
├── templates/        # HTML pages
└── instance/         # Database and secret key (git-ignored)
```

## Run locally

```bash
# 1. Clone
git clone https://github.com/AaravShukla-Codes/perspectos.git
cd perspectos

# 2. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the app
python app.py
```

Open http://127.0.0.1:5000 in your browser.

**The first account you register automatically becomes the admin.** To make someone else an admin later:

```bash
python app.py makeadmin <username>
```

## Run the tests

```bash
python tests.py
```

## Configuration

Set these as environment variables (all optional for local use):

| Variable               | Purpose                                              | Default                       |
| ---------------------- | ---------------------------------------------------- | ----------------------------- |
| `SECRET_KEY`           | Signs login sessions. **Set this in production.**    | Auto-generated in `instance/` |
| `DATABASE_PATH`        | Location of the SQLite file                          | `instance/perspectos.db`      |
| `SESSION_COOKIE_SECURE`| Set to `1` when serving over HTTPS                   | off                           |
| `RATELIMIT_ENABLED`    | Set to `0` to disable rate limiting (e.g. in tests)  | on                            |
| `FLASK_DEBUG`          | Set to `1` for debug mode (local only)               | off                           |

## Deployment

The live demo runs on [Vercel](https://perspectos.vercel.app). GitHub Pages can't run Flask apps, so deploy to a host that supports Python, such as Vercel, PythonAnywhere or Render.

> **Note:** on Vercel the filesystem is temporary, so the SQLite database can reset when the server restarts. For permanent data, use PythonAnywhere or Render with a persistent disk.

Production start command:

```bash
gunicorn app:app
```

Set `SECRET_KEY` and `SESSION_COOKIE_SECURE=1` in your host's environment settings. On hosts with an ephemeral disk, point `DATABASE_PATH` at a persistent volume, otherwise the database resets on every redeploy.

## Author

Made by [Aarav Shukla](https://github.com/AaravShukla-Codes).
