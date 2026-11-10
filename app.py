import os, sqlite3, secrets, hashlib, hmac, json, mimetypes
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, request, redirect, url_for, session, flash, send_file, abort, render_template, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DATABASE_PATH", BASE / "trustvault.db"))
STORAGE = Path(os.getenv("PRIVATE_STORAGE", BASE / "private_uploads"))
STORAGE.mkdir(parents=True, exist_ok=True)
ALLOWED = {"pdf", "txt", "png", "jpg", "jpeg", "docx", "xlsx"}
MAX_BYTES = 10 * 1024 * 1024

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "CHANGE-ME-BEFORE-DEPLOYMENT"),
    MAX_CONTENT_LENGTH=MAX_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
)
AUDIT_KEY = os.getenv("AUDIT_KEY", app.config["SECRET_KEY"]).encode()

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')), active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS documents(
 id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
 title TEXT NOT NULL, category TEXT NOT NULL, original_name TEXT NOT NULL,
 stored_name TEXT NOT NULL UNIQUE, size INTEGER NOT NULL, mime TEXT NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS grants(
 id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
 created_at TEXT NOT NULL, UNIQUE(document_id,user_id));
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor_id INTEGER, action TEXT NOT NULL,
 document_id INTEGER, target_user_id INTEGER, detail TEXT NOT NULL,
 prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL);
"""
def now(): return datetime.now(timezone.utc).isoformat()
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db
@app.teardown_appcontext
def close_db(exc):
    con = g.pop("db", None)
    if con: con.close()
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.commit()
    # Seed only on an empty database. Change these passwords immediately.
    seeds = [
      ("admin", os.getenv("SEED_ADMIN_PASSWORD","Admin@12345"), "admin"),
      ("owner", os.getenv("SEED_OWNER_PASSWORD","Owner@12345"), "owner"),
      ("viewer", os.getenv("SEED_VIEWER_PASSWORD","Viewer@12345"), "viewer"),
      ("viewer2", os.getenv("SEED_VIEWER2_PASSWORD","Viewer2@12345"), "viewer"),
      ("owner2", os.getenv("SEED_OWNER2_PASSWORD","Owner2@12345"), "owner"),
    ]
    for username,pw,role in seeds:
        try:
            con.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                        (username,generate_password_hash(pw),role,now()))
        except sqlite3.IntegrityError: pass
    con.commit(); con.close()

def audit(actor, action, doc_id=None, target=None, detail=""):
    con=db()
    last=con.execute("SELECT event_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev=last["event_hash"] if last else "GENESIS"
    payload={"at":now(),"actor":actor,"action":action,"doc":doc_id,"target":target,"detail":detail,"prev":prev}
    raw=json.dumps(payload,sort_keys=True,separators=(",",":"))
    digest=hmac.new(AUDIT_KEY,raw.encode(),hashlib.sha256).hexdigest()
    con.execute("INSERT INTO audit(at,actor_id,action,document_id,target_user_id,detail,prev_hash,event_hash) VALUES(?,?,?,?,?,?,?,?)",
      (payload["at"],actor,action,doc_id,target,detail,prev,digest))
    con.commit()

def verify_audit():
    prev="GENESIS"
    for row in db().execute("SELECT * FROM audit ORDER BY id"):
        payload={"at":row["at"],"actor":row["actor_id"],"action":row["action"],"doc":row["document_id"],
                 "target":row["target_user_id"],"detail":row["detail"],"prev":prev}
        raw=json.dumps(payload,sort_keys=True,separators=(",",":"))
        expected=hmac.new(AUDIT_KEY,raw.encode(),hashlib.sha256).hexdigest()
        if row["prev_hash"] != prev or not hmac.compare_digest(expected,row["event_hash"]): return False
        prev=row["event_hash"]
    return True

def login_required(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        if not session.get("uid"): return redirect(url_for("login"))
        user=db().execute("SELECT * FROM users WHERE id=? AND active=1",(session["uid"],)).fetchone()
        if not user: session.clear(); return redirect(url_for("login"))
        g.user=user
        return fn(*a,**kw)
    return wrapped
def roles(*allowed):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapped(*a,**kw):
            if g.user["role"] not in allowed: abort(403)
            return fn(*a,**kw)
        return wrapped
    return deco
def csrf():
    token=session.get("_csrf")
    supplied=request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
    if not token or not supplied or not hmac.compare_digest(token,supplied): abort(400,"CSRF validation failed")
@app.before_request
def csrf_protect():
    if request.method in ("POST","PUT","PATCH","DELETE") and request.endpoint not in (None,):
        if session.get("uid"): csrf()
@app.context_processor
def inject():
    if session.get("uid") and "_csrf" not in session: session["_csrf"]=secrets.token_urlsafe(32)
    return {"csrf_token":session.get("_csrf"),"current_user":g.get("user")}

def access(doc_id, need="read"):
    """Server-side object authorization. Admin role intentionally does not bypass document ACL."""
    user=g.user
    doc=db().execute("SELECT * FROM documents WHERE id=?",(doc_id,)).fetchone()
    if not doc: abort(404)
    if doc["owner_id"] == user["id"]: return doc
    grant=db().execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",
                       (doc_id,user["id"])).fetchone()
    if not grant or (need=="edit" and grant["permission"]!="edit"): abort(403)
    return doc

@app.route("/")
def index(): return redirect(url_for("dashboard") if session.get("uid") else url_for("login"))
@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=db().execute("SELECT * FROM users WHERE username=?",(request.form.get("username","").strip(),)).fetchone()
        if u and u["active"] and check_password_hash(u["password_hash"],request.form.get("password","")):
            session.clear(); session["uid"]=u["id"]; session["_csrf"]=secrets.token_urlsafe(32)
            audit(u["id"],"login",detail="successful login")
            return redirect(url_for("dashboard"))
        audit(None,"login_failed",detail="username="+request.form.get("username","")[:80])
        flash("Invalid username or password.")
    return render_template("login.html")
@app.post("/logout")
@login_required
def logout():
    audit(g.user["id"],"logout"); session.clear(); return redirect(url_for("login"))
@app.route("/dashboard")
@login_required
def dashboard():
    u=g.user
    if u["role"]=="admin":
        docs=db().execute("SELECT d.*,u.username owner FROM documents d JOIN users u ON u.id=d.owner_id ORDER BY d.id DESC").fetchall()
    elif u["role"]=="owner":
        docs=db().execute("SELECT * FROM documents WHERE owner_id=? ORDER BY id DESC",(u["id"],)).fetchall()
    else:
        docs=db().execute("""SELECT d.*,u.username owner,g.permission FROM documents d
          JOIN grants g ON g.document_id=d.id JOIN users u ON u.id=d.owner_id
          WHERE g.user_id=? ORDER BY d.id DESC""",(u["id"],)).fetchall()
    return render_template("dashboard.html",docs=docs)
@app.route("/upload",methods=["GET","POST"])
@roles("owner")
def upload():
    if request.method=="POST":
        f=request.files.get("file"); title=request.form.get("title","").strip(); category=request.form.get("category","General").strip()
        if not f or not f.filename or not title: flash("Choose a file and enter a title."); return redirect(url_for("upload"))
        original=secure_filename(f.filename)
        ext=original.rsplit(".",1)[-1].lower() if "." in original else ""
        if ext not in ALLOWED: abort(400,"File type not allowed.")
        data=f.read(MAX_BYTES+1)
        if not data or len(data)>MAX_BYTES: abort(400,"Empty file or file exceeds 10 MB.")
        stored=secrets.token_hex(24)+"."+ext
        # File is stored outside static/ and has no public URL.
        (STORAGE/stored).write_bytes(data)
        cur=db().execute("""INSERT INTO documents(owner_id,title,category,original_name,stored_name,size,mime,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?)""",(g.user["id"],title[:120],category[:60],original,stored,len(data),
          mimetypes.guess_type(original)[0] or "application/octet-stream",now(),now()))
        doc_id=cur.lastrowid; audit(g.user["id"],"upload",doc_id,detail=f"name={original};size={len(data)}")
        flash("Document uploaded."); return redirect(url_for("dashboard"))
    return render_template("upload.html")
@app.get("/document/<int:doc_id>")
@login_required
def detail(doc_id):
    d=access(doc_id); owner=db().execute("SELECT username FROM users WHERE id=?",(d["owner_id"],)).fetchone()
    grants=db().execute("SELECT g.*,u.username FROM grants g JOIN users u ON u.id=g.user_id WHERE document_id=?",(doc_id,)).fetchall()
    mygrant=db().execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",(doc_id,g.user["id"])).fetchone()
    can_edit=(d["owner_id"]==g.user["id"] or (mygrant and mygrant["permission"]=="edit"))
    return render_template("detail.html",doc=d,owner=owner["username"],grants=grants,can_edit=can_edit)
@app.get("/download/<int:doc_id>")
@login_required
def download(doc_id):
    d=access(doc_id,"read")
    path=STORAGE/d["stored_name"]
    if not path.is_file(): abort(404)
    audit(g.user["id"],"download",doc_id,detail="download granted")
    return send_file(path,as_attachment=True,download_name=d["original_name"],mimetype="application/octet-stream")
@app.post("/document/<int:doc_id>/edit")
@login_required
def edit_doc(doc_id):
    d=access(doc_id,"edit")
    title=request.form.get("title","").strip()
    if not title: abort(400,"Title required.")
    db().execute("UPDATE documents SET title=?,category=?,updated_at=? WHERE id=?",
      (title[:120],request.form.get("category","General")[:60],now(),doc_id))
    audit(g.user["id"],"metadata_edit",doc_id,detail="title/category updated")
    flash("Document details updated."); return redirect(url_for("detail",doc_id=doc_id))
@app.post("/document/<int:doc_id>/delete")
@login_required
def delete_doc(doc_id):
    d=access(doc_id,"edit")
    # Owner-only destructive operation.
    if d["owner_id"]!=g.user["id"]: abort(403)
    db().execute("DELETE FROM documents WHERE id=?",(doc_id,))
    audit(g.user["id"],"delete",doc_id,detail="document record deleted")
    try: (STORAGE/d["stored_name"]).unlink(missing_ok=True)
    except OSError: pass
    flash("Document deleted."); return redirect(url_for("dashboard"))
@app.post("/document/<int:doc_id>/grant")
@roles("owner")
def grant(doc_id):
    d=db().execute("SELECT * FROM documents WHERE id=? AND owner_id=?",(doc_id,g.user["id"])).fetchone()
    if not d: abort(403)
    username=request.form.get("username","").strip()
    permission=request.form.get("permission","read")
    target=db().execute("SELECT * FROM users WHERE username=? AND active=1",(username,)).fetchone()
    if not target or target["role"]=="admin" or target["id"]==g.user["id"]: abort(400,"Choose an active non-admin user.")
    if permission not in ("read","edit"): abort(400)
    db().execute("INSERT INTO grants(document_id,user_id,permission,created_at) VALUES(?,?,?,?) ON CONFLICT(document_id,user_id) DO UPDATE SET permission=excluded.permission,created_at=excluded.created_at",
      (doc_id,target["id"],permission,now()))
    audit(g.user["id"],"permission_grant",doc_id,target["id"],permission)
    flash("Access granted."); return redirect(url_for("detail",doc_id=doc_id))
@app.post("/document/<int:doc_id>/revoke/<int:user_id>")
@roles("owner")
def revoke(doc_id,user_id):
    d=db().execute("SELECT * FROM documents WHERE id=? AND owner_id=?",(doc_id,g.user["id"])).fetchone()
    if not d: abort(403)
    db().execute("DELETE FROM grants WHERE document_id=? AND user_id=?",(doc_id,user_id))
    audit(g.user["id"],"permission_revoke",doc_id,user_id,"grant removed immediately")
    flash("Access revoked."); return redirect(url_for("detail",doc_id=doc_id))
@app.get("/admin")
@roles("admin")
def admin():
    events=db().execute("""SELECT a.*,u.username actor,t.username target FROM audit a
      LEFT JOIN users u ON u.id=a.actor_id LEFT JOIN users t ON t.id=a.target_user_id ORDER BY a.id DESC LIMIT 250""").fetchall()
    users=db().execute("SELECT id,username,role,active,created_at FROM users ORDER BY id").fetchall()
    return render_template("admin.html",events=events,users=users,integrity=verify_audit())
@app.post("/admin/user/<int:user_id>/toggle")
@roles("admin")
def toggle_user(user_id):
    if user_id==g.user["id"]: abort(400,"You cannot deactivate yourself.")
    row=db().execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
    if not row: abort(404)
    db().execute("UPDATE users SET active=? WHERE id=?",(0 if row["active"] else 1,user_id))
    audit(g.user["id"],"user_deactivated" if row["active"] else "user_activated",target=user_id)
    flash("User status updated."); return redirect(url_for("admin"))
@app.errorhandler(403)
def forbidden(e):
    # Record refused object-level requests as evidence, without exposing whether an ID exists.
    try:
        if getattr(g, "user", None):
            doc_id = (request.view_args or {}).get("doc_id")
            audit(g.user["id"], "access_denied", doc_id,
                  detail="endpoint=" + str(request.endpoint))
    except Exception:
        # A logging failure must not turn a denied request into an allowed one.
        app.logger.exception("Could not record denied request")
    return render_template("error.html",code=403,message="You are not authorised to access this resource."),403
@app.errorhandler(400)
def bad_request(e): return render_template("error.html",code=400,message=getattr(e,"description","Invalid request.")),400
@app.errorhandler(404)
def not_found(e): return render_template("error.html",code=404,message="The requested resource was not found."),404
@app.errorhandler(413)
def too_large(e): return render_template("error.html",code=413,message="Maximum upload size is 10 MB."),413

if __name__=="__main__":
    init_db()
    app.run(host="127.0.0.1",port=int(os.getenv("PORT","5000")),debug=False)
