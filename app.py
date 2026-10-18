import os, sqlite3, secrets, smtplib, logging
from pathlib import Path
from datetime import datetime, timezone
from email.message import EmailMessage
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()
ROOT=Path(__file__).resolve().parent
DB=ROOT/"larp.db"
UPLOADS=ROOT/"uploads"; UPLOADS.mkdir(exist_ok=True)
app=Flask(__name__)
app.secret_key=os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config.update(MAX_CONTENT_LENGTH=15*1024*1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
logging.basicConfig(level=logging.INFO)
serializer=URLSafeTimedSerializer(app.secret_key)
ALLOWED={"txt","md","pdf","docx","csv","json","png","jpg","jpeg","webp"}

def connect():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); return c

def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,verified INTEGER NOT NULL DEFAULT 0,is_admin INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,role TEXT NOT NULL,content TEXT NOT NULL,created_at TEXT NOT NULL);
        """)
        email=os.getenv("ADMIN_EMAIL","").strip().lower(); password=os.getenv("ADMIN_PASSWORD","")
        if email and password:
            row=c.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone()
            if row: c.execute("UPDATE users SET is_admin=1,verified=1 WHERE email=?",(email,))
            else: c.execute("INSERT INTO users(email,password_hash,verified,is_admin,created_at) VALUES(?,?,?,?,?)",(email,generate_password_hash(password),1,1,datetime.now(timezone.utc).isoformat()))

def me():
    uid=session.get("user_id")
    if not uid:return None
    with connect() as c:return c.execute("SELECT id,email,verified,is_admin,created_at FROM users WHERE id=?",(uid,)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        if not me():return redirect(url_for("login"))
        return fn(*a,**kw)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        u=me()
        if not u or not u["is_admin"]:abort(403)
        return fn(*a,**kw)
    return wrapped

def send_mail(email,token):
    host=os.getenv("SMTP_HOST","").strip(); user=os.getenv("SMTP_USERNAME","").strip(); password=os.getenv("SMTP_PASSWORD",""); sender=os.getenv("SMTP_FROM",user).strip(); port=int(os.getenv("SMTP_PORT","465"))
    if not all([host,user,password,sender]):return False
    link=url_for("verify",token=token,_external=True)
    msg=EmailMessage(); msg["Subject"]="Подтверждение почты LARP"; msg["From"]=sender; msg["To"]=email
    msg.set_content(f"Подтверди почту по ссылке (действует 24 часа):\\n{link}")
    try:
        if port==465:
            with smtplib.SMTP_SSL(host,port,timeout=20) as s:s.login(user,password); s.send_message(msg)
        else:
            with smtplib.SMTP(host,port,timeout=20) as s:s.starttls(); s.login(user,password); s.send_message(msg)
        return True
    except Exception:app.logger.exception("SMTP error"); return False

@app.context_processor
def context():return {"user":me()}

@app.get("/")
def index():
    u=me()
    if not u:return render_template("landing.html")
    with connect() as c: rows=c.execute("SELECT role,content,created_at FROM messages WHERE user_id=? ORDER BY id DESC LIMIT 60",(u["id"],)).fetchall()
    return render_template("index.html",messages=list(reversed(rows)))

@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        email=request.form.get("email","").strip().lower(); password=request.form.get("password","")
        if "@" not in email:flash("Укажи корректный email.","error")
        elif len(password)<10:flash("Пароль должен быть не короче 10 символов.","error")
        else:
            try:
                with connect() as c:
                    cur=c.execute("INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)",(email,generate_password_hash(password),datetime.now(timezone.utc).isoformat())); uid=cur.lastrowid
                token=serializer.dumps({"email":email},salt="email-verify")
                if send_mail(email,token):flash("Аккаунт создан. Проверь почту и подтверди email.","success")
                else:
                    with connect() as c:c.execute("DELETE FROM users WHERE id=? AND verified=0",(uid,))
                    flash("Письмо не отправлено. Проверь SMTP-настройки в .env.","error")
            except sqlite3.IntegrityError:flash("Такой email уже зарегистрирован.","error")
        return redirect(url_for("register"))
    return render_template("auth.html",mode="register")

@app.get("/verify/<token>")
def verify(token):
    try: email=serializer.loads(token,salt="email-verify",max_age=86400).get("email","").lower()
    except SignatureExpired:return render_template("message.html",title="Ссылка устарела",message="Ссылка действует 24 часа. Зарегистрируйся ещё раз.")
    except BadSignature:return render_template("message.html",title="Ссылка недействительна",message="Запроси новую ссылку регистрации.")
    with connect() as c:
        c.execute("UPDATE users SET verified=1 WHERE email=?",(email,)); row=c.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone()
    if not row:return render_template("message.html",title="Аккаунт не найден",message="Зарегистрируйся ещё раз.")
    session.clear(); session["user_id"]=row["id"]; session.permanent=True
    return redirect(url_for("index"))

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form.get("email","").strip().lower(); password=request.form.get("password","")
        with connect() as c: row=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        if not row or not check_password_hash(row["password_hash"],password):flash("Неверный email или пароль.","error")
        elif not row["verified"] and not row["is_admin"]:flash("Сначала подтверди почту.","error")
        else:session.clear(); session["user_id"]=row["id"]; session.permanent=True; return redirect(url_for("index"))
    return render_template("auth.html",mode="login")

@app.post("/logout")
@login_required
def logout():session.clear(); return redirect(url_for("index"))

@app.post("/api/chat")
@login_required
def chat():
    text=request.form.get("message","").strip()
    if not text:return jsonify(error="Напиши сообщение."),400
    if len(text)>12000:return jsonify(error="Максимум 12 000 символов."),400
    uid=me()["id"]
    with connect() as c:
        c.execute("INSERT INTO messages(user_id,role,content,created_at) VALUES(?,?,?,?)",(uid,"user",text,datetime.now(timezone.utc).isoformat()))
        history=c.execute("SELECT role,content FROM messages WHERE user_id=? ORDER BY id DESC LIMIT 12",(uid,)).fetchall()
    key=os.getenv("OPENAI_API_KEY","").strip()
    if not key:answer="LARP работает, но ИИ не подключён. Добавь OPENAI_API_KEY в .env и перезапусти приложение."
    else:
        try:
            from openai import OpenAI
            client=OpenAI(api_key=key); msgs=[{"role":"system","content":"Ты — полезный ИИ-ассистент LARP. Отвечай на языке пользователя; честно указывай ограничения и неопределённость."}]
            msgs += [{"role":r["role"],"content":r["content"]} for r in reversed(history)]
            res=client.chat.completions.create(model=os.getenv("OPENAI_MODEL","gpt-4o-mini"),messages=msgs,max_tokens=1500)
            answer=res.choices[0].message.content or "Пустой ответ."
        except Exception:
            app.logger.exception("OpenAI error"); return jsonify(error="Не удалось получить ответ ИИ. Проверь API-ключ, доступ и оплату API."),502
    with connect() as c:c.execute("INSERT INTO messages(user_id,role,content,created_at) VALUES(?,?,?,?)",(uid,"assistant",answer,datetime.now(timezone.utc).isoformat()))
    return jsonify(answer=answer)

@app.post("/api/upload")
@login_required
def upload():
    f=request.files.get("file")
    if not f or not f.filename:return jsonify(error="Выбери файл."),400
    name=secure_filename(f.filename); ext=name.rsplit(".",1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED:return jsonify(error="Тип файла не разрешён."),400
    f.save(UPLOADS/(secrets.token_hex(12)+"_"+name))
    return jsonify(filename=name,message="Файл загружен. Полный анализ документов нужно подключить отдельно.")

@app.get("/admin")
@login_required
@admin_required
def admin():
    with connect() as c:users=c.execute("SELECT id,email,verified,is_admin,created_at FROM users ORDER BY id DESC LIMIT 200").fetchall()
    return render_template("admin.html",users=users)

@app.post("/admin/user/<int:uid>/toggle")
@login_required
@admin_required
def toggle(uid):
    if uid==me()["id"]:flash("Нельзя изменить собственную роль здесь.","error")
    else:
        with connect() as c:
            r=c.execute("SELECT is_admin FROM users WHERE id=?",(uid,)).fetchone()
            if r:c.execute("UPDATE users SET is_admin=? WHERE id=?",(0 if r["is_admin"] else 1,uid)); flash("Роль обновлена.","success")
    return redirect(url_for("admin"))

@app.get("/health")
def health():return jsonify(ok=True,app="larp")

@app.errorhandler(403)
def forbidden(e):return render_template("message.html",title="Доступ запрещён",message="Нет прав администратора."),403
@app.errorhandler(413)
def too_large(e):return render_template("message.html",title="Файл слишком большой",message="Максимальный размер — 15 МБ."),413

init_db()
if __name__=="__main__":app.run(host="127.0.0.1",port=int(os.getenv("PORT","5000")),debug=False)
