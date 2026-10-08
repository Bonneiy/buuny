import os, re, secrets, sqlite3
from time import time
from flask import Flask, g, request, redirect, url_for, session, flash, abort, render_template
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),
    MAX_CONTENT_LENGTH=64 * 1024)
CSRFProtect(app)  # ป้องกัน CSRF ทุกฟอร์ม POST
DB = os.environ.get("DB_PATH", "app.db")
USER_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
FAILS = {}  # rate limit การเดารหัสผ่าน

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user' CHECK(role IN('user','admin')),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
"""

def init_db():
    c = sqlite3.connect(DB); c.executescript(SCHEMA)
    au, ap = os.environ.get("ADMIN_USER"), os.environ.get("ADMIN_PASSWORD")
    if au and ap and not c.execute("SELECT 1 FROM users WHERE username=?", (au,)).fetchone():
        c.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,'admin')",
                  (au, generate_password_hash(ap)))
    c.commit(); c.close()

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

@app.before_request
def load_user():
    g.user = None
    if "uid" in session:  # role อ่านจาก DB ทุกครั้ง ไม่เชื่อ cookie
        g.user = db().execute("SELECT id,username,role FROM users WHERE id=?", (session["uid"],)).fetchone()

@app.after_request
def headers(r):
    r.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "same-origin"
    return r

def login_required(f):
    from functools import wraps
    @wraps(f)
    def w(*a, **k):
        if not g.user: return redirect(url_for("login"))
        return f(*a, **k)
    return w

def admin_required(f):
    from functools import wraps
    @wraps(f)
    @login_required
    def w(*a, **k):
        if g.user["role"] != "admin": abort(403)
        return f(*a, **k)
    return w

# ---------- สมัคร / เข้าสู่ระบบ ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p, p2 = request.form.get("password", ""), request.form.get("confirm", "")
        if not USER_RE.match(u): flash("ชื่อผู้ใช้ 3-20 ตัว ใช้ a-z 0-9 _ เท่านั้น")
        elif len(p) < 8 or len(p) > 128: flash("รหัสผ่านต้องยาว 8-128 ตัวอักษร")
        elif p != p2: flash("รหัสผ่านไม่ตรงกัน")
        else:
            try:
                db().execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
                             (u, generate_password_hash(p)))  # scrypt + salt
                db().commit(); flash("สมัครสำเร็จ กรุณาเข้าสู่ระบบ")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("ชื่อผู้ใช้นี้ถูกใช้แล้ว")
    return render_template("auth.html", reg=True)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip, now = request.remote_addr, time()
        FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < 300]
        if len(FAILS[ip]) >= 5:
            flash("ลองผิดหลายครั้ง กรุณารอ 5 นาที"); return render_template("auth.html", reg=False), 429
        row = db().execute("SELECT * FROM users WHERE username=?", (request.form.get("username", ""),)).fetchone()
        if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
            session.clear(); session["uid"] = row["id"]  # กัน session fixation
            return redirect(url_for("index"))
        FAILS[ip].append(now); flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง")
    return render_template("auth.html", reg=False)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); return redirect(url_for("index"))

# ---------- CRUD โพสต์ (มีเจ้าของ) ----------
def clean_post():
    t, b = request.form.get("title", "").strip(), request.form.get("body", "").strip()
    if not (1 <= len(t) <= 100 and 1 <= len(b) <= 2000):
        flash("หัวข้อ 1-100 ตัว และเนื้อหา 1-2000 ตัวอักษร"); return None
    return t, b

def get_post(pid):
    p = db().execute("SELECT * FROM posts WHERE id=?", (pid,)).fetchone()
    if not p: abort(404)
    return p

@app.route("/")
def index():
    posts = db().execute("SELECT p.*,u.username FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC").fetchall()
    return render_template("index.html", posts=posts)

@app.route("/post/new", methods=["POST"])
@login_required
def new_post():
    d = clean_post()
    if d:
        db().execute("INSERT INTO posts(user_id,title,body) VALUES(?,?,?)", (g.user["id"], *d)); db().commit()
    return redirect(url_for("index"))

@app.route("/post/<int:pid>/edit", methods=["GET", "POST"])
@login_required
def edit_post(pid):
    p = get_post(pid)
    if p["user_id"] != g.user["id"]: abort(403)  # แก้ได้เฉพาะเจ้าของ
    if request.method == "POST":
        d = clean_post()
        if d:
            db().execute("UPDATE posts SET title=?,body=? WHERE id=? AND user_id=?", (*d, pid, g.user["id"])); db().commit()
            return redirect(url_for("index"))
    return render_template("edit.html", p=p)

@app.route("/post/<int:pid>/delete", methods=["POST"])
@login_required
def delete_post(pid):
    p = get_post(pid)
    if p["user_id"] != g.user["id"] and g.user["role"] != "admin": abort(403)
    db().execute("DELETE FROM posts WHERE id=?", (pid,)); db().commit()
    return redirect(url_for("admin") if request.form.get("from") == "admin" else url_for("index"))

# ---------- หน้า Admin ----------
@app.route("/admin")
@admin_required
def admin():
    users = db().execute("SELECT u.*,(SELECT COUNT(*) FROM posts WHERE user_id=u.id) n FROM users u").fetchall()
    posts = db().execute("SELECT p.*,u.username FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC").fetchall()
    return render_template("admin.html", users=users, posts=posts)

@app.route("/admin/user/<int:uid>/role", methods=["POST"])
@admin_required
def set_role(uid):
    r = request.form.get("role")
    if r not in ("user", "admin") or uid == g.user["id"]: abort(400)
    db().execute("UPDATE users SET role=? WHERE id=?", (r, uid)); db().commit()
    return redirect(url_for("admin"))

@app.route("/admin/user/<int:uid>/delete", methods=["POST"])
@admin_required
def del_user(uid):
    if uid == g.user["id"]: abort(400)
    db().execute("DELETE FROM users WHERE id=?", (uid,)); db().commit()
    return redirect(url_for("admin"))

@app.errorhandler(403)
def e403(_): return "403 ไม่มีสิทธิ์เข้าถึง", 403

init_db()
if __name__ == "__main__":
    app.run(debug=False)
