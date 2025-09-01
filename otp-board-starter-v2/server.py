# -*- coding: utf-8 -*-
import os, json, sqlite3, re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# ---------- Config ----------
DB_DIR = Path(os.getenv("DB_DIR", "data")); DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "otp_store.sqlite3"
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-me")
OTP_TTL_SEC = int(os.getenv("OTP_TTL_SEC", "600"))  # ברירת מחדל: 10 דק'
AUTH = HTTPBearer(auto_error=False)

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def normalize_phone(p: str) -> str:
    # שומר רק ספרות; הופך 9725... ל-05...
    digits = re.sub(r"\D+", "", p or "")
    if digits.startswith("972") and len(digits) >= 11:
        digits = "0" + digits[3:]
    return digits

def normalize_code(c: str) -> str:
    return re.sub(r"\D+", "", c or "")

def connect():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    # קצת כיוונוני יציבות
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")
    # סכמות
    c.execute("""
    CREATE TABLE IF NOT EXISTS otps(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT NOT NULL,
        code TEXT NOT NULL,
        created_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS login_queue(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        payload TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL
    )""")
    # אינדקסים שימושיים
    c.execute("CREATE INDEX IF NOT EXISTS idx_otps_phone_created ON otps(phone, created_at DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_login_queue_status_created ON login_queue(status, created_at)")
    return c

# אם אין תיקיית static, לא למפות
if Path("static").exists():
    app = FastAPI(title="OTP Board")
    app.mount("/static", StaticFiles(directory="static"), name="static")
else:
    app = FastAPI(title="OTP Board")

# ---------- Auth ----------
def require_token(creds: HTTPAuthorizationCredentials = Depends(AUTH)):
    if not creds or creds.credentials != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

# ---------- UI ----------
@app.get("/", response_class=HTMLResponse)
def index():
    return """<!doctype html><html dir="rtl" lang="he"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OTP Board</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
</head><body class="bg-light"><div class="container py-5">
  <h3 class="mb-4">בקשת התחברות + זימון תור</h3>
  <form method="post" action="/login_request" class="row g-3 mb-5">
    <div class="col-md-3">
      <label class="form-label">טלפון (05X...)</label>
      <input name="phone" class="form-control" required>
    </div>
    <div class="col-md-3">
      <label class="form-label">מספר זהות (9 ספרות)</label>
      <input name="id_number" class="form-control" minlength="9" maxlength="9" pattern="\\d{9}">
    </div>
    <div class="col-md-3">
      <label class="form-label">עיר/אזור</label>
      <input name="city" class="form-control" placeholder="חיפה / חולון / ירושלים">
    </div>
    <div class="col-md-3">
      <label class="form-label">סניף מועדף</label>
      <input name="branch" class="form-control" placeholder="לדוגמה: סניף חיפה">
    </div>
    <div class="col-md-3">
      <label class="form-label">תאריך (YYYY-MM-DD)</label>
      <input name="date" class="form-control" placeholder="2025-09-08">
    </div>
    <div class="col-md-3">
      <label class="form-label">שעת התחלה (HH:MM)</label>
      <input name="time_from" class="form-control" placeholder="08:00">
    </div>
    <div class="col-md-3">
      <label class="form-label">שעת סיום (HH:MM)</label>
      <input name="time_to" class="form-control" placeholder="12:00">
    </div>
    <div class="col-md-12">
      <button class="btn btn-success">התחל התחברות וזימון</button>
    </div>
  </form>

  <h3 class="mb-3">הזנת OTP ידני</h3>
  <form method="post" action="/submit" class="row g-3">
    <div class="col-sm-4">
      <label class="form-label">טלפון</label>
      <input name="phone" class="form-control" required>
    </div>
    <div class="col-sm-3">
      <label class="form-label">קוד OTP</label>
      <input name="code" class="form-control" required>
    </div>
    <div class="col-sm-3 align-self-end">
      <button class="btn btn-primary w-100">שמירה</button>
    </div>
  </form>
</div></body></html>"""

# ---------- UI handlers ----------
@app.post("/login_request")
def login_request(
    phone: str = Form(...),
    id_number: str = Form(default=""),
    city: str = Form(default=""),
    branch: str = Form(default=""),
    date: str = Form(default=""),
    time_from: str = Form(default=""),
    time_to: str = Form(default="")
):
    payload = {
        "id_number": (id_number or "").strip(),
        "city": (city or "").strip(),
        "branch": (branch or "").strip(),
        "date": (date or "").strip(),
        "time_from": (time_from or "").strip(),
        "time_to": (time_to or "").strip(),
    }
    p = normalize_phone(phone)
    if not p:
        raise HTTPException(400, "Phone is required")

    with connect() as c:
        c.execute(
            "INSERT INTO login_queue(phone, status, payload, created_at) VALUES(?, 'queued', ?, ?)",
            (p, json.dumps(payload, ensure_ascii=False), utcnow_iso())
        )
    return RedirectResponse("/", status_code=303)

@app.post("/submit")
def submit(phone: str = Form(...), code: str = Form(...)):
    p = normalize_phone(phone)
    k = normalize_code(code)
    if not p or not k:
        raise HTTPException(400, "Phone and code are required")

    with connect() as c:
        c.execute(
            "INSERT INTO otps(phone, code, created_at, used) VALUES(?,?,?,0)",
            (p, k, utcnow_iso())
        )
    return RedirectResponse("/", status_code=303)

# ---------- API used by ה-worker ----------
@app.get("/api/login/next")
def api_login_next(_: bool = Depends(require_token)):
    with connect() as c:
        row = c.execute(
            """SELECT id, phone, payload, created_at
               FROM login_queue
               WHERE status='queued'
               ORDER BY created_at ASC
               LIMIT 1"""
        ).fetchone()
        if not row:
            return {"id": None}
        c.execute("UPDATE login_queue SET status='processing' WHERE id=?", (row["id"],))
        return {
            "id": row["id"],
            "phone": row["phone"],
            "payload": json.loads(row["payload"] or "{}"),
            "created_at": row["created_at"],
        }

@app.post("/api/login/mark")
def api_login_mark(id: int, status: str, _: bool = Depends(require_token)):
    if status not in ("done", "failed", "queued", "processing"):
        raise HTTPException(400, "invalid status")
    with connect() as c:
        cur = c.execute("UPDATE login_queue SET status=? WHERE id=?", (status, id))
        if cur.rowcount == 0:
            raise HTTPException(404, "job not found")
    return {"ok": True}

@app.get("/api/otp/latest")
def api_get_latest(phone: str, _: bool = Depends(require_token)):
    p = normalize_phone(phone)
    with connect() as c:
        row = c.execute(
            "SELECT id, code, created_at FROM otps WHERE phone=? AND used=0 ORDER BY created_at DESC LIMIT 1",
            (p,)
        ).fetchone()
        if not row:
            return {"code": None}
        # TTL?
        if OTP_TTL_SEC > 0:
            try:
                created = datetime.fromisoformat(row["created_at"])
            except Exception:
                created = datetime.now(timezone.utc) - timedelta(days=1)
            if datetime.now(timezone.utc) - created > timedelta(seconds=OTP_TTL_SEC):
                return {"code": None}
        return {"id": row["id"], "code": row["code"]}

@app.post("/api/otp/mark_used")
def api_mark_used(id: int, _: bool = Depends(require_token)):
    with connect() as c:
        c.execute("UPDATE otps SET used=1 WHERE id=?", (id,))
    return {"ok": True}
