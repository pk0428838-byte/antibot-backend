import os
import json
import time
import hmac
import hashlib
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple, List

import httpx
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field


# -----------------------------
# ENV
# -----------------------------
DB_PATH = os.getenv("DB_PATH", "/data/antibot.db")

# Админ-ключ для ручной блокировки/разблокировки (обязательно задай в .env)
ADMIN_KEY = os.getenv("ADMIN_KEY", "")

# Телеграм (опционально, но если хочешь алерты по подозрительным — нужно)
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")

# Секрет для капчи (если не задан — генерим при старте, но лучше зафиксировать в .env)
CAPTCHA_SECRET = os.getenv("CAPTCHA_SECRET", "")

# Тюнинг
SUSPICIOUS_SCORE_THRESHOLD = int(os.getenv("SUSPICIOUS_SCORE_THRESHOLD", "4"))
REPEAT_WINDOW_HOURS = int(os.getenv("REPEAT_WINDOW_HOURS", "24"))

# Чтобы не спамить TG одинаковыми алертами
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "600"))  # 10 минут


# -----------------------------
# Helpers
# -----------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def normalize_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None
    s = phone.strip()
    # оставим + и цифры
    out = []
    for ch in s:
        if ch.isdigit() or ch == "+":
            out.append(ch)
    t = "".join(out)
    return t if t else None


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def hmac_hex(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def require_admin(x_admin_key: Optional[str]) -> None:
    if not ADMIN_KEY:
        raise HTTPException(status_code=503, detail="ADMIN_KEY is not set on server")
    if not x_admin_key or x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")


async def tg_send(text: str) -> None:
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TG_CHAT_ID, "text": text}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(url, json=payload)
    except Exception:
        # не валим весь запрос из-за TG
        pass


def init_db() -> None:
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        site TEXT NOT NULL,
        vid TEXT NOT NULL,
        ip TEXT,
        ua TEXT,
        phone TEXT,
        name TEXT,
        meta_json TEXT,
        suspicious INTEGER NOT NULL DEFAULT 0,
        suspicious_score INTEGER NOT NULL DEFAULT 0,
        suspicious_reasons TEXT,
        accepted INTEGER NOT NULL DEFAULT 1
    )
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_sub_vid_time ON submissions(vid, created_at)
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocked_visitors (
        vid TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        reason TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        reason TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS captcha_challenges (
        captcha_id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        vid TEXT NOT NULL,
        site TEXT NOT NULL,
        question TEXT NOT NULL,
        answer_hmac TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        key TEXT PRIMARY KEY,
        last_sent_at TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


def get_client_ip(req: Request) -> str:
    # nginx прокидывает эти заголовки
    xff = req.headers.get("x-forwarded-for")
    if xff:
        # первый — реальный клиент
        return xff.split(",")[0].strip()
    xrip = req.headers.get("x-real-ip")
    if xrip:
        return xrip.strip()
    if req.client and req.client.host:
        return req.client.host
    return ""


def build_bridge_html() -> str:
    # отдаём стабильный visitorId через localStorage + postMessage
    return """<!doctype html><html><head><meta charset="utf-8"></head><body>
<script>
(function(){
  var KEY="svf_global_vid";
  function gen(){
    try { return (crypto && crypto.randomUUID) ? crypto.randomUUID() : ("g_"+Math.random().toString(16).slice(2)+Date.now().toString(16)); }
    catch(e){ return ("g_"+Math.random().toString(16).slice(2)+Date.now().toString(16)); }
  }
  function get(){
    try{
      var v=localStorage.getItem(KEY);
      if(!v){ v=gen(); localStorage.setItem(KEY,v); }
      return v;
    } catch(e){
      return gen();
    }
  }
  window.addEventListener("message", function(ev){
    if(ev && ev.data && ev.data.type==="svf_vid_req"){
      parent.postMessage({type:"svf_vid", vid:get()}, ev.origin || "*");
    }
  });
})();
</script></body></html>"""


def gen_math_captcha() -> Tuple[str, str]:
    # простая мат.капча (без сторонних сервисов и доменов)
    a = secrets.randbelow(9) + 1
    b = secrets.randbelow(9) + 1
    op = "+" if secrets.randbelow(2) == 0 else "-"
    if op == "-" and b > a:
        a, b = b, a
    ans = str(a + b) if op == "+" else str(a - b)
    q = f"Сколько будет {a} {op} {b}?"
    return q, ans


def captcha_make_record(vid: str, site: str) -> Dict[str, Any]:
    global CAPTCHA_SECRET
    if not CAPTCHA_SECRET:
        CAPTCHA_SECRET = secrets.token_hex(32)

    captcha_id = secrets.token_urlsafe(16)
    q, ans = gen_math_captcha()
    ans_h = hmac_hex(CAPTCHA_SECRET, f"{captcha_id}:{ans}")
    now = utcnow()
    exp = now + timedelta(minutes=5)

    conn = db_connect()
    conn.execute(
        "INSERT INTO captcha_challenges(captcha_id, created_at, expires_at, vid, site, question, answer_hmac, used) VALUES(?,?,?,?,?,?,?,0)",
        (captcha_id, now.isoformat(), exp.isoformat(), vid, site, q, ans_h),
    )
    conn.commit()
    conn.close()

    return {"captcha_id": captcha_id, "question": q, "expires_in_sec": 300}


def captcha_verify(captcha_id: str, answer: str, vid: str, site: str) -> bool:
    global CAPTCHA_SECRET
    if not CAPTCHA_SECRET:
        return False

    conn = db_connect()
    row = conn.execute(
        "SELECT * FROM captcha_challenges WHERE captcha_id=?",
        (captcha_id,),
    ).fetchone()

    if not row:
        conn.close()
        return False

    if int(row["used"]) == 1:
        conn.close()
        return False

    if row["vid"] != vid or row["site"] != site:
        conn.close()
        return False

    expires_at = datetime.fromisoformat(row["expires_at"])
    if utcnow() > expires_at:
        conn.close()
        return False

    expected = row["answer_hmac"]
    got = hmac_hex(CAPTCHA_SECRET, f"{captcha_id}:{answer.strip()}")
    ok = hmac.compare_digest(expected, got)

    if ok:
        conn.execute("UPDATE captcha_challenges SET used=1 WHERE captcha_id=?", (captcha_id,))
        conn.commit()

    conn.close()
    return ok


def history_stats(vid: str, window_hours: int) -> Dict[str, Any]:
    conn = db_connect()
    since = (utcnow() - timedelta(hours=window_hours)).isoformat()
    rows = conn.execute(
        "SELECT phone, name FROM submissions WHERE vid=? AND created_at>=? AND accepted=1",
        (vid, since),
    ).fetchall()
    conn.close()

    phones = set()
    names = set()
    for r in rows:
        if r["phone"]:
            phones.add(r["phone"])
        if r["name"]:
            names.add(r["name"])

    return {
        "count": len(rows),
        "distinct_phones": len(phones),
        "distinct_names": len(names),
        "phones": list(phones),
        "names": list(names),
    }


def behavioral_score(meta: Dict[str, Any]) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []

    dur = int(meta.get("duration_ms") or 0)
    mouse = int(meta.get("mouse_moves") or 0)
    scroll = int(meta.get("scrolls") or 0)
    keydowns = int(meta.get("keydowns") or 0)
    pasted_phone = bool(meta.get("pasted_phone") or False)

    # супер быстрый “лид”
    if 0 < dur < 6000:
        score += 2
        reasons.append("слишком быстро (<6с)")

    # ноль движений + быстро
    if dur < 12000 and mouse == 0 and scroll == 0:
        score += 2
        reasons.append("нет мыши/скролла и быстро")

    # паста телефона + почти нет клавиш
    if pasted_phone and keydowns < 3:
        score += 2
        reasons.append("телефон вставлен paste + мало клавиш")

    return score, reasons


def repeat_score(stats: Dict[str, Any], phone: Optional[str], name: Optional[str]) -> Tuple[int, List[str], bool]:
    score = 0
    reasons: List[str] = []
    captcha_needed = False

    cnt = stats["count"]
    dph = stats["distinct_phones"]
    dnm = stats["distinct_names"]

    if cnt >= 1:
        # уже есть заявки => подозрительно
        score += 2
        reasons.append(f"повторная заявка ({cnt+1}-я за {REPEAT_WINDOW_HOURS}ч)")
        captcha_needed = True

    if cnt >= 1 and phone and dph >= 1 and phone not in stats["phones"]:
        score += 2
        reasons.append("меняет телефон")
        captcha_needed = True

    if cnt >= 1 and name and dnm >= 1 and name not in stats["names"]:
        score += 1
        reasons.append("меняет имя")
        captcha_needed = True

    if cnt >= 3:
        score += 2
        reasons.append("много заявок (>=4)")
        captcha_needed = True

    return score, reasons, captcha_needed


def is_blocked(vid: str, ip: str) -> Tuple[bool, str]:
    conn = db_connect()
    row_v = conn.execute("SELECT reason FROM blocked_visitors WHERE vid=?", (vid,)).fetchone()
    if row_v:
        conn.close()
        return True, f"blocked visitorId: {row_v['reason'] or ''}".strip()

    if ip:
        row_i = conn.execute("SELECT reason FROM blocked_ips WHERE ip=?", (ip,)).fetchone()
        if row_i:
            conn.close()
            return True, f"blocked ip: {row_i['reason'] or ''}".strip()

    conn.close()
    return False, ""


def alert_should_send(key: str) -> bool:
    conn = db_connect()
    row = conn.execute("SELECT last_sent_at FROM alerts WHERE key=?", (key,)).fetchone()
    now = utcnow()
    if not row:
        conn.execute("INSERT INTO alerts(key, last_sent_at) VALUES(?,?)", (key, now.isoformat()))
        conn.commit()
        conn.close()
        return True

    last = datetime.fromisoformat(row["last_sent_at"])
    if (now - last).total_seconds() >= ALERT_COOLDOWN_SECONDS:
        conn.execute("UPDATE alerts SET last_sent_at=? WHERE key=?", (now.isoformat(), key))
        conn.commit()
        conn.close()
        return True

    conn.close()
    return False


# -----------------------------
# API models
# -----------------------------
class CaptchaObj(BaseModel):
    captcha_id: str = Field(..., alias="captcha_id")
    answer: str


class CollectIn(BaseModel):
    site: str
    visitorId: str
    phone: Optional[str] = None
    name: Optional[str] = None
    meta: Dict[str, Any] = {}
    captcha: Optional[CaptchaObj] = None


# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # скрипт будет работать на любых сайтах
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup():
    init_db()


@app.api_route("/bridge", methods=["GET", "HEAD"])
async def bridge():
    return HTMLResponse(build_bridge_html())


@app.api_route("/health", methods=["GET", "HEAD"])
async def health():
    return JSONResponse({"ok": True, "ts": utcnow().isoformat()})


@app.get("/is_blocked")
async def api_is_blocked(vid: str, request: Request):
    ip = get_client_ip(request)
    blocked, reason = is_blocked(vid, ip)
    return {"blocked": blocked, "reason": reason}


@app.get("/risk")
async def risk(vid: str, site: str, request: Request):
    ip = get_client_ip(request)
    blocked, reason = is_blocked(vid, ip)
    if blocked:
        return {
            "blocked": True,
            "suspicious": False,
            "captcha_required": False,
            "score": 999,
            "reasons": [reason],
        }

    stats = history_stats(vid, REPEAT_WINDOW_HOURS)
    # На /risk мы оцениваем только “повторность”, т.к. поведение ещё не знаем.
    rep_score, rep_reasons, captcha_needed = repeat_score(stats, None, None)

    suspicious = rep_score >= 2
    return {
        "blocked": False,
        "suspicious": suspicious,
        "captcha_required": captcha_needed,
        "score": rep_score,
        "reasons": rep_reasons,
        "history": {"count": stats["count"], "distinct_phones": stats["distinct_phones"], "distinct_names": stats["distinct_names"]},
    }


@app.get("/captcha/new")
async def captcha_new(vid: str, site: str, request: Request):
    ip = get_client_ip(request)
    blocked, reason = is_blocked(vid, ip)
    if blocked:
        raise HTTPException(status_code=403, detail={"blocked": True, "reason": reason})
    return captcha_make_record(vid, site)


@app.post("/collect")
async def collect(payload: CollectIn, request: Request):
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "")

    vid = payload.visitorId.strip()
    site = payload.site.strip()

    blocked, reason = is_blocked(vid, ip)
    if blocked:
        return JSONResponse(status_code=403, content={"blocked": True, "reason": reason})

    phone = normalize_phone(payload.phone)
    name = (payload.name or "").strip() or None
    meta = payload.meta or {}

    # 1) История
    stats = history_stats(vid, REPEAT_WINDOW_HOURS)
    rep_score, rep_reasons, rep_captcha_needed = repeat_score(stats, phone, name)

    # 2) Поведение
    beh_score, beh_reasons = behavioral_score(meta)

    # Итог
    score = rep_score + beh_score
    reasons = rep_reasons + beh_reasons
    suspicious = score >= SUSPICIOUS_SCORE_THRESHOLD or rep_captcha_needed

    # Если подозрительный — требуем капчу
    if suspicious:
        if not payload.captcha:
            # отдаём капчу
            cap = captcha_make_record(vid, site)
            return JSONResponse(
                status_code=428,
                content={
                    "ok": False,
                    "captcha_required": True,
                    "suspicious": True,
                    "score": score,
                    "reasons": reasons,
                    "captcha": cap,
                },
            )

        # проверяем капчу
        if not captcha_verify(payload.captcha.captcha_id, payload.captcha.answer, vid, site):
            cap = captcha_make_record(vid, site)
            return JSONResponse(
                status_code=428,
                content={
                    "ok": False,
                    "captcha_required": True,
                    "suspicious": True,
                    "score": score,
                    "reasons": reasons + ["неверная капча"],
                    "captcha": cap,
                },
            )

    # Записываем в БД (accepted=1)
    conn = db_connect()
    conn.execute(
        "INSERT INTO submissions(created_at, site, vid, ip, ua, phone, name, meta_json, suspicious, suspicious_score, suspicious_reasons, accepted) VALUES(?,?,?,?,?,?,?,?,?,?,?,1)",
        (
            utcnow().isoformat(),
            site,
            vid,
            ip,
            ua,
            phone,
            name,
            json.dumps(meta, ensure_ascii=False),
            1 if suspicious else 0,
            int(score),
            ", ".join(reasons),
        ),
    )
    conn.commit()
    conn.close()

    # Уведомление ТОЛЬКО по подозрительным
    if suspicious:
        alert_key = sha256_hex(f"susp:{vid}:{site}")
        if alert_should_send(alert_key):
            text = (
                "⚠️ Подозрительный пользователь\n"
                f"site: {site}\n"
                f"vid: {vid}\n"
                f"ip: {ip}\n"
                f"phone: {phone or '-'}\n"
                f"name: {name or '-'}\n"
                f"score: {score}\n"
                f"reasons: {', '.join(reasons) if reasons else '-'}\n"
                f"history({REPEAT_WINDOW_HOURS}h): count={stats['count']}, phones={stats['distinct_phones']}, names={stats['distinct_names']}\n"
            )
            await tg_send(text)

    return {"ok": True, "suspicious": suspicious, "score": score, "reasons": reasons}


# -----------------------------
# Admin endpoints: block/unblock
# -----------------------------
class BlockIn(BaseModel):
    visitorId: Optional[str] = None
    ip: Optional[str] = None
    reason: Optional[str] = None


@app.post("/admin/block")
async def admin_block(payload: BlockIn, x_admin_key: Optional[str] = Header(default=None)):
    require_admin(x_admin_key)

    vid = (payload.visitorId or "").strip() or None
    ip = (payload.ip or "").strip() or None
    reason = (payload.reason or "").strip() or None

    if not vid and not ip:
        raise HTTPException(status_code=400, detail="visitorId or ip is required")

    conn = db_connect()
    now = utcnow().isoformat()

    if vid:
        conn.execute(
            "INSERT OR REPLACE INTO blocked_visitors(vid, created_at, reason) VALUES(?,?,?)",
            (vid, now, reason),
        )
    if ip:
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips(ip, created_at, reason) VALUES(?,?,?)",
            (ip, now, reason),
        )

    conn.commit()
    conn.close()
    return {"ok": True, "blocked": {"visitorId": vid, "ip": ip, "reason": reason}}


@app.post("/admin/unblock")
async def admin_unblock(payload: BlockIn, x_admin_key: Optional[str] = Header(default=None)):
    require_admin(x_admin_key)

    vid = (payload.visitorId or "").strip() or None
    ip = (payload.ip or "").strip() or None

    if not vid and not ip:
        raise HTTPException(status_code=400, detail="visitorId or ip is required")

    conn = db_connect()
    if vid:
        conn.execute("DELETE FROM blocked_visitors WHERE vid=?", (vid,))
    if ip:
        conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/admin/blocked")
async def admin_blocked(x_admin_key: Optional[str] = Header(default=None)):
    require_admin(x_admin_key)

    conn = db_connect()
    vids = conn.execute("SELECT * FROM blocked_visitors ORDER BY created_at DESC LIMIT 200").fetchall()
    ips = conn.execute("SELECT * FROM blocked_ips ORDER BY created_at DESC LIMIT 200").fetchall()
    conn.close()

    return {
        "visitors": [dict(r) for r in vids],
        "ips": [dict(r) for r in ips],
    }
