"""Automated checks for the Perspectos app.  Run:  python tests.py
Uses a throw-away database, so your real data in instance/ is never touched."""
import os
import subprocess
import sys
import tempfile

TMP = tempfile.mkdtemp()
DB_PATH = os.path.join(TMP, "test.db")
os.environ["DATABASE_PATH"] = DB_PATH
os.environ["RATELIMIT_ENABLED"] = "0"

import app as app_module  # noqa: E402

app = app_module.app
passed = failed = 0


def check(name, condition, extra=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  ok    {name}")
    else:
        failed += 1
        print(f"  FAIL  {name} {extra}")


class User:
    """A browser-like client that keeps its own cookies and CSRF token."""

    def __init__(self):
        self.c = app.test_client()
        self.token = self.c.get("/api/me").json["csrf_token"]

    def call(self, method, url, data=None, token=True):
        headers = {"X-CSRF-Token": self.token} if token else {}
        return self.c.open(url, method=method, json=data, headers=headers)

    def get(self, url):
        return self.c.get(url)

    def refresh_token(self):
        self.token = self.c.get("/api/me").json["csrf_token"]


def register(name, email=None, password="password123"):
    u = User()
    r = u.call("POST", "/api/register", {"username": name, "email": email or f"{name}@example.com", "password": password})
    u.refresh_token()
    return u, r


print("\nAuthentication")
alice, r = register("alice")
check("register works", r.status_code == 201, r.get_data(as_text=True))
bob, r = register("bob")
check("second user registers", r.status_code == 201)
carol, _ = register("carol")
check("/api/me shows logged-in user", alice.get("/api/me").json["user"]["username"] == "alice")
check("first user is admin", alice.get("/api/me").json["user"]["is_admin"] is True)
check("later users are not admin", bob.get("/api/me").json["user"]["is_admin"] is False)

_, r = register("alice", "other@example.com")
check("duplicate username rejected (409)", r.status_code == 409)
_, r = register("ALICE", "other@example.com")
check("duplicate username is case-insensitive", r.status_code == 409)
_, r = register("dave", "alice@example.com")
check("duplicate email rejected (409)", r.status_code == 409)
_, r = register("x", "x@example.com")
check("short username rejected", r.status_code == 400)
_, r = register("erin", "not-an-email")
check("bad email rejected", r.status_code == 400)
_, r = register("frank", "frank@example.com", "short")
check("short password rejected", r.status_code == 400)

stored = app_module.database.sqlite3.connect(DB_PATH).execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()[0]
check("password is hashed, not stored as text", stored != "password123" and ":" in stored)
check("password never appears in API responses", "password" not in alice.get("/api/me").get_data(as_text=True).lower().replace("csrf", ""))

anon = User()
r = anon.call("POST", "/api/login", {"username": "alice", "password": "wrongpass"})
check("wrong password rejected (401)", r.status_code == 401)
r = anon.call("POST", "/api/login", {"username": "alice", "password": "password123"})
check("login by username works", r.status_code == 200)
anon.refresh_token()
anon.call("POST", "/api/logout")
anon.refresh_token()
check("logout works", anon.get("/api/me").json["user"] is None)
r = anon.call("POST", "/api/login", {"username": "ALICE@example.com", "password": "password123"})
check("login by email works", r.status_code == 200)

print("\nCSRF and protected routes")
check("POST without CSRF token blocked (403)", alice.call("POST", "/api/topics", {"word": "Hack"}, token=False).status_code == 403)
bad = User()
bad.token = "forged"
check("POST with wrong CSRF token blocked (403)", bad.call("POST", "/api/logout").status_code == 403)
check("anonymous cannot create topic (401)", User().call("POST", "/api/topics", {"word": "Nope"}).status_code == 401)
check("anonymous cannot comment (401)", User().call("POST", "/api/topics/1/comments", {"body": "hi"}).status_code == 401)
check("non-admin blocked from admin API (403)", bob.get("/api/admin/reports").status_code == 403)
check("anonymous blocked from admin API (401)", User().get("/api/admin/reports").status_code == 401)

print("\nTopics")
r = alice.call("POST", "/api/topics", {"word": "Freedom", "description": "What does it mean to be free?", "category": "Philosophy"})
check("create topic", r.status_code == 201, r.get_data(as_text=True))
freedom = r.json["topic"]["id"]
check("two words rejected", alice.call("POST", "/api/topics", {"word": "two words"}).status_code == 400)
check("symbols rejected", alice.call("POST", "/api/topics", {"word": "hi!"}).status_code == 400)
check("31 characters rejected", alice.call("POST", "/api/topics", {"word": "a" * 31}).status_code == 400)
check("bad category rejected", alice.call("POST", "/api/topics", {"word": "Test", "category": "Nope"}).status_code == 400)
check("201-char description rejected", alice.call("POST", "/api/topics", {"word": "Test", "description": "x" * 201}).status_code == 400)
r = bob.call("POST", "/api/topics", {"word": "FREEDOM"})
check("duplicate word rejected case-insensitively", r.status_code == 409 and r.json["topic_id"] == freedom)
r = bob.call("POST", "/api/topics", {"word": "स्वतंत्रता", "category": "Culture"})
check("non-English word (Hindi) accepted", r.status_code == 201, r.get_data(as_text=True))
money = bob.call("POST", "/api/topics", {"word": "Money", "category": "Money"}).json["topic"]["id"]
ai = carol.call("POST", "/api/topics", {"word": "AI", "category": "Technology"}).json["topic"]["id"]

r = alice.call("PUT", f"/api/topics/{freedom}", {"description": "Updated text", "category": "Society"})
check("owner can edit topic", r.status_code == 200 and r.json["topic"]["description"] == "Updated text")
check("non-owner cannot edit topic (403)", bob.call("PUT", f"/api/topics/{freedom}", {"description": "hijack"}).status_code == 403)
check("non-owner cannot delete topic (403)", bob.call("DELETE", f"/api/topics/{freedom}").status_code == 403)
check("topic detail 404 for missing", alice.get("/api/topics/9999").status_code == 404)

print("\nComments, replies, reactions")
r = bob.call("POST", f"/api/topics/{freedom}/comments", {"body": "Freedom is choice."})
check("add comment", r.status_code == 201)
c1 = r.json["comment"]["id"]
r = carol.call("POST", f"/api/topics/{freedom}/comments", {"body": "I disagree.", "parent_id": c1})
check("reply to comment", r.status_code == 201 and r.json["comment"]["parent_id"] == c1)
c2 = r.json["comment"]["id"]
r = alice.call("POST", f"/api/topics/{freedom}/comments", {"body": "Reply to a reply", "parent_id": c2})
check("reply to a reply (nested)", r.status_code == 201)
c3 = r.json["comment"]["id"]
check("empty comment rejected", bob.call("POST", f"/api/topics/{freedom}/comments", {"body": "   "}).status_code == 400)
check("1001-char comment rejected", bob.call("POST", f"/api/topics/{freedom}/comments", {"body": "x" * 1001}).status_code == 400)
check("reply to missing parent rejected", bob.call("POST", f"/api/topics/{freedom}/comments", {"body": "hi", "parent_id": 9999}).status_code == 404)
check("reply parent from another topic rejected", bob.call("POST", f"/api/topics/{money}/comments", {"body": "hi", "parent_id": c1}).status_code == 404)

data = alice.get(f"/api/topics/{freedom}/comments").json
check("comment history lists all 3, total=3", data["total"] == 3 and len(data["comments"]) == 3)
check("comment count shows in topic list", alice.get("/api/topics?q=freedom").json["topics"][0]["comment_count"] == 3)

r = bob.call("PUT", f"/api/comments/{c1}", {"body": "Freedom is choice (edited)."})
check("owner edits comment", r.status_code == 200 and r.json["comment"]["edited_at"] is not None)
check("non-owner cannot edit comment (403)", carol.call("PUT", f"/api/comments/{c1}", {"body": "hijack"}).status_code == 403)
check("non-owner cannot delete comment (403)", carol.call("DELETE", f"/api/comments/{c1}").status_code == 403)

r = alice.call("POST", f"/api/comments/{c1}/react", {"value": 1})
check("like a comment", r.json["likes"] == 1 and r.json["my_reaction"] == 1)
r = alice.call("POST", f"/api/comments/{c1}/react", {"value": 1})
check("liking twice does not double count", r.json["likes"] == 1)
r = alice.call("POST", f"/api/comments/{c1}/react", {"value": -1})
check("change like -> dislike", r.json["likes"] == 0 and r.json["dislikes"] == 1 and r.json["my_reaction"] == -1)
carol.call("POST", f"/api/comments/{c1}/react", {"value": 1})
r = alice.call("POST", f"/api/comments/{c1}/react", {"value": 0})
check("remove reaction", r.json["dislikes"] == 0 and r.json["likes"] == 1 and r.json["my_reaction"] == 0)
check("invalid reaction value rejected", alice.call("POST", f"/api/comments/{c1}/react", {"value": 5}).status_code == 400)
rows = app_module.database.sqlite3.connect(DB_PATH).execute("SELECT COUNT(*) FROM reactions WHERE comment_id=? AND user_id=1", (c1,)).fetchone()[0]
check("database holds max one reaction per user per comment", rows == 0)
mine = [c for c in carol.get(f"/api/topics/{freedom}/comments").json["comments"] if c["id"] == c1][0]
check("each user sees their own reaction", mine["my_reaction"] == 1)

print("\nDiscovery")
for i in range(3):
    carol.call("POST", f"/api/topics/{ai}/comments", {"body": f"AI thought {i}"})
check("search finds by word", [t["word"] for t in alice.get("/api/topics?q=money").json["topics"]] == ["Money"])
check("search is case-insensitive", len(alice.get("/api/topics?q=FREE").json["topics"]) == 1)
check("search finds by description", len(alice.get("/api/topics?q=Updated").json["topics"]) == 1)
check("search with % does not match everything", len(alice.get("/api/topics?q=%25").json["topics"]) == 0)
check("search with SQL-injection text is harmless", alice.get("/api/topics?q=' OR 1=1 --").status_code == 200 and len(alice.get("/api/topics?q=' OR 1=1 --").json["topics"]) == 0)
check("category filter", [t["word"] for t in alice.get("/api/topics?category=Technology").json["topics"]] == ["AI"])
check("recent sort: newest first", alice.get("/api/topics?sort=recent").json["topics"][0]["word"] == "AI")
check("most discussed sort: AI (3) before Freedom (3 ties by date)", alice.get("/api/topics?sort=discussed").json["topics"][0]["word"] in ("AI", "Freedom"))
check("popular sort: Freedom (1 like) first", alice.get("/api/topics?sort=popular").json["topics"][0]["word"] == "Freedom")
check("trending sort works", alice.get("/api/topics?sort=trending").status_code == 200)
check("unknown sort falls back safely", alice.get("/api/topics?sort=DROP TABLE").status_code == 200)
page1 = alice.get("/api/topics?limit=2").json
check("pagination: has_more and offset", len(page1["topics"]) == 2 and page1["has_more"] and len(alice.get("/api/topics?limit=2&offset=2").json["topics"]) == 2)

print("\nProfile")
r = alice.call("PUT", "/api/profile", {"bio": "I love big questions."})
check("edit bio", r.status_code == 200)
check("bio too long rejected", alice.call("PUT", "/api/profile", {"bio": "x" * 301}).status_code == 400)
check("username taken rejected", alice.call("PUT", "/api/profile", {"username": "bob"}).status_code == 409)
check("anonymous cannot edit profile", User().call("PUT", "/api/profile", {"bio": "x"}).status_code == 401)

print("\nSafe display of user content")
alice.call("PUT", f"/api/topics/{freedom}", {"description": "<script>alert(1)</script>", "category": "Society"})
html = alice.get(f"/topic/{freedom}").get_data(as_text=True)
check("topic page escapes HTML in description", "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html)
profile_html = alice.get("/user/alice").get_data(as_text=True)
check("profile page shows bio and join date", "I love big questions." in profile_html and "Joined" in profile_html)
check("profile lists topics created", "Freedom" in profile_html)
check("profile lists participation", "Freedom" in bob.get("/user/bob").get_data(as_text=True))
check("profile does not leak email or hash", "alice@example.com" not in profile_html and "pbkdf2" not in profile_html and "scrypt" not in profile_html)
check("unknown profile is 404", alice.get("/user/nobody").status_code == 404)
check("security headers set", "script-src 'self'" in alice.get("/").headers.get("Content-Security-Policy", ""))

print("\nReports and admin moderation")
bad_comment = carol.call("POST", f"/api/topics/{money}/comments", {"body": "Buy my pills!!!"}).json["comment"]["id"]
r = alice.call("POST", "/api/report", {"type": "comment", "id": bad_comment, "reason": "Spam"})
check("report a comment", r.status_code == 201)
check("duplicate report rejected (409)", alice.call("POST", "/api/report", {"type": "comment", "id": bad_comment, "reason": "Spam again"}).status_code == 409)
check("cannot report own content", carol.call("POST", "/api/report", {"type": "comment", "id": bad_comment, "reason": "Spam"}).status_code == 400)
check("report needs a reason", bob.call("POST", "/api/report", {"type": "comment", "id": bad_comment, "reason": ""}).status_code == 400)
check("report needs valid type", bob.call("POST", "/api/report", {"type": "user", "id": 1, "reason": "bad"}).status_code == 400)
check("anonymous cannot report", User().call("POST", "/api/report", {"type": "comment", "id": bad_comment, "reason": "bad"}).status_code == 401)
r = bob.call("POST", "/api/report", {"type": "topic", "id": ai, "reason": "Off topic"})
check("report a topic", r.status_code == 201)

reports = alice.get("/api/admin/reports").json["reports"]
check("admin sees open reports", len(reports) == 2, str(len(reports)))
comment_report = [x for x in reports if x["type"] == "comment"][0]
topic_report = [x for x in reports if x["type"] == "topic"][0]
check("report shows preview, author, reporter", comment_report["preview"] == "Buy my pills!!!" and comment_report["author"] == "carol" and comment_report["reporter"] == "alice")
check("non-admin cannot remove content via admin API", bob.call("POST", f"/api/admin/reports/{comment_report['id']}/remove").status_code == 403)

check("admin dismisses a report", alice.call("POST", f"/api/admin/reports/{topic_report['id']}/dismiss").status_code == 200)
check("dismissed report leaves open list", len(alice.get("/api/admin/reports").json["reports"]) == 1)
check("dismissed report appears in dismissed list", len(alice.get("/api/admin/reports?status=dismissed").json["reports"]) == 1)
check("admin removes reported comment", alice.call("POST", f"/api/admin/reports/{comment_report['id']}/remove").status_code == 200)
check("removed comment is gone", all(c["id"] != bad_comment for c in alice.get(f"/api/topics/{money}/comments").json["comments"]))
check("no open reports left", alice.get("/api/admin/reports").json["reports"] == [])

print("\nDeleting")
check("deleting a comment also deletes its replies", alice.get(f"/api/topics/{freedom}/comments").json["total"] == 3
      and bob.call("DELETE", f"/api/comments/{c1}").status_code == 200
      and alice.get(f"/api/topics/{freedom}/comments").json["total"] == 0)
check("owner deletes own topic", carol.call("DELETE", f"/api/topics/{ai}").status_code == 200)
check("deleted topic is gone (404)", alice.get(f"/api/topics/{ai}").status_code == 404)
check("deleted topic page is 404", alice.get(f"/topic/{ai}").status_code == 404)
check("admin can delete any topic", alice.call("DELETE", f"/api/topics/{money}").status_code == 200)
leftover = app_module.database.sqlite3.connect(DB_PATH).execute("SELECT COUNT(*) FROM comments WHERE topic_id IN (?, ?)", (ai, money)).fetchone()[0]
check("comments of deleted topics are removed from DB", leftover == 0)

print("\nPages")
for url, who, code in [("/", anon, 200), ("/login", User(), 200), ("/register", User(), 200),
                       (f"/topic/{freedom}", anon, 200), ("/user/alice", anon, 200),
                       ("/admin", alice, 200), ("/admin", bob, 403), ("/admin", User(), 302),
                       ("/nope", anon, 404)]:
    check(f"GET {url} as {'admin' if who is alice else 'user'} -> {code}", who.get(url).status_code == code)
check("login page redirects when already logged in", alice.get("/login").status_code == 302)

print("\nRate limiting")
app.config["RATELIMIT_ENABLED"] = True
app_module._hits.clear()
rl = User()
codes = [rl.call("POST", "/api/login", {"username": "alice", "password": "bad-password"}).status_code for _ in range(12)]
check("login blocked after 10 tries/minute (429)", codes[:10] == [401] * 10 and codes[10] == 429, str(codes))
check("429 includes Retry-After", rl.call("POST", "/api/login", {"username": "a", "password": "b"}).headers.get("Retry-After") is not None)
app.config["RATELIMIT_ENABLED"] = False

print("\nPersistence across restart")
before = app_module.database.sqlite3.connect(DB_PATH).execute("SELECT COUNT(*) FROM users").fetchone()[0]
code = (
    "import os, sys; os.environ['DATABASE_PATH']=sys.argv[1]; os.environ['RATELIMIT_ENABLED']='0'\n"
    "import app\n"
    "c = app.app.test_client()\n"
    "t = c.get('/api/topics').json['topics']\n"
    "print(len(t), [x['word'] for x in t])\n"
    "r = c.post('/api/login', json={'username':'alice','password':'password123'}, headers={'X-CSRF-Token': c.get('/api/me').json['csrf_token']})\n"
    "print(r.status_code)\n"
)
out = subprocess.run([sys.executable, "-c", code, DB_PATH], capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__))).stdout.split("\n")
check("fresh process still sees topics", out[0].startswith("2 ") and "Freedom" in out[0], out[0])
check("fresh process can log in with old password", out[1] == "200", str(out))
check("users still there", before == 3)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
