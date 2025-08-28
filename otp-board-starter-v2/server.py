# -*- coding: utf-8 -*-
import os, json, sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

DB_DIR = Path(os.getenv("DB_DIR", "data")); DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "otp_store.sqlite3"
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-me")
app = FastAPI(title="OTP Board")
app.mount("/static", StaticFiles(directory="static"), name="static")
auth_scheme = HTTPBearer(auto_error=False)

def conn():
    c = sqlite3.connect(DB_PATH)
    c.execute('''CREATE TABLE IF NOT EXISTS otps(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT NOT NULL,
        code TEXT NOT NULL,
        created_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS login_queue(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        payload TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL
    )''')
    cols = [r[1] for r in c.execute("PRAGMA table_info(login_queue)").fetchall()]
    if 'payload' not in cols:
        c.execute("ALTER TABLE login_queue ADD COLUMN payload TEXT NOT NULL DEFAULT '{}'")
    return c

def require_token(creds: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    if not creds or creds.credentials != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

@app.get("/", response_class=HTMLResponse)
def index():
    return """<!doctype html><html dir='rtl' lang='he'><head>
<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>OTP Board</title>
<link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css'>
</head><body class='bg-light'><div class='container py-5'>
  <h3 class='mb-4'>בקשת התחברות + זימון תור</h3>
  <form method='post' action='/login_request' class='row g-3 mb-5'>
    <div class='col-md-3'><label class='form-label'>טלפון (05X...)</label><input name='phone' class='form-control' required></div>
    <div class='col-md-3'><label class='form-label'>מספר זהות (9 ספרות)</label><input name='id_number' class='form-control' minlength='9' maxlength='9' pattern='\d{9}'></div>
    <div class='col-md-3'><label class='form-label'>עיר/אזור</label><input name='city' class='form-control' placeholder='חיפה / חולון / ירושלים'></div>
    <div class='col-md-3'><label class='form-label'>סניף מועדף</label><input name='branch' class='form-control' placeholder='לדוגמה: סניף חיפה'></div>
    <div class='col-md-3'><label class='form-label'>תאריך (YYYY-MM-DD)</label><input name='date' class='form-control' placeholder='2025-09-08'></div>
    <div class='col-md-3'><label class='form-label'>שעת התחלה (HH:MM)</label><input name='time_from' class='form-control' placeholder='08:00'></div>
    <div class='col-md-3'><label class='form-label'>שעת סיום (HH:MM)</label><input name='time_to' class='form-control' placeholder='12:00'></div>
    <div class='col-md-12'><button class='btn btn-success'>התחל התחברות וזימון</button></div>
  </form>
  <h3 class='mb-3'>הזנת OTP ידני</h3>
  <form method='post' action='/submit' class='row g-3'>
    <div class='col-sm-4'><label class='form-label'>טלפון</label><input name='phone' class='form-control' required></div>
    <div class='col-sm-3'><label class='form-label'>קוד OTP</label><input name='code' class='form-control' required></div>
    <div class='col-sm-3 align-self-end'><button class='btn btn-primary w-100'>שמירה</button></div>
  </form>
</div></body></html>"""

@app.post('/login_request')
def login_request(phone: str = Form(...), id_number: str = Form(default=''), city: str = Form(default=''),
                  branch: str = Form(default=''), date: str = Form(default=''), time_from: str = Form(default=''),
                  time_to: str = Form(default='')):
    payload = {'id_number': id_number.strip(), 'city': city.strip(), 'branch': branch.strip(),
               'date': date.strip(), 'time_from': time_from.strip(), 'time_to': time_to.strip()}
    c = conn()
    c.execute("INSERT INTO login_queue(phone, payload, created_at) VALUES(?, ?, datetime('now'))",
              (phone.strip(), json.dumps(payload, ensure_ascii=False)))
    c.commit(); c.close()
    return RedirectResponse('/', status_code=303)

@app.post('/submit')
def submit(phone: str = Form(...), code: str = Form(...)):
    c = conn()
    c.execute('INSERT INTO otps(phone, code, created_at) VALUES(?,?,?)',
              (phone.strip(), code.strip(), datetime.utcnow().isoformat()))
    c.commit(); c.close()
    return RedirectResponse('/', status_code=303)

@app.get('/api/login/next')
def api_login_next(creds: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    if not creds or creds.credentials != ADMIN_TOKEN: raise HTTPException(401, 'Unauthorized')
    c = conn()
    row = c.execute("""SELECT id, phone, payload, created_at FROM login_queue
                     WHERE status='queued' ORDER BY created_at ASC LIMIT 1""").fetchone()
    if not row: return JSONResponse({'id': None})
    c.execute('UPDATE login_queue SET status="processing" WHERE id=?', (row[0],))
    c.commit(); c.close()
    return {'id': row[0], 'phone': row[1], 'payload': json.loads(row[2] or '{}'), 'created_at': row[3]}

@app.get('/api/otp/latest')
def api_get_latest(phone: str, creds: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    if not creds or creds.credentials != ADMIN_TOKEN: raise HTTPException(401, 'Unauthorized')
    c = conn()
    row = c.execute('SELECT id, code FROM otps WHERE phone=? AND used=0 ORDER BY created_at DESC LIMIT 1',
                    (phone.strip(),)).fetchone()
    if not row: return JSONResponse({'code': None})
    return {'id': row[0], 'code': row[1]}

@app.post('/api/otp/mark_used')
def api_mark_used(id: int, creds: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    if not creds or creds.credentials != ADMIN_TOKEN: raise HTTPException(401, 'Unauthorized')
    c = conn(); c.execute('UPDATE otps SET used=1 WHERE id=?', (id,)); c.commit(); c.close(); return {'ok': True}
