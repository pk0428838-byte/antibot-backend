import os
import json
import time
import sqlite3
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import PlainTextResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

APP_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.getenv("DB_PATH", "/data/antibot.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
CAPTCHA_TTL_SEC = int(os.getenv("CAPTCHA_TTL_SEC", "600"))  # 10 минут

# пороги
CAPTCHA_SCORE_THRESHOLD = int(os.getenv("CAPTCHA_SCORE_THRESHOLD", "40"))
ALERT_SCORE_THRESHOLD = int(os.getenv("ALERT_SCORE_THRESHOLD", "60"))

# сколько дней хранить события (чтобы БД не пухла)
EVENTS_TTL_DAYS = int(os.getenv("EVENTS_TTL_DAYS", "14"))

app = FastAPI(title="antibot")

STATIC_DIR = os.path.join(APP_DIR, "static")
os.makedirs(STATIC_DIR, exist_ok=True)

# Если antibot.js лежит в корне (как ты раньше делал) — скопируем в static, чтобы всегда отдавался
# (а ты при этом можешь держать оригинал в корне репы).
def _ensure_antibot_js_present():
    root_js = os.path.join(APP_DIR, "antibot.js")
    static_js = os.path.join(STATIC_DIR, "antibot.js")
    if os.path.exists(root_js):
        # обновляем static, если отличается
        try:
            with open(root_js, "rb") as f1, open(static_js, "rb") as f2:
                if f1.read() == f2.read():
                    return
        except Exception:
            pass
        try:
            with open(root_js, "rb") as src, open(static_js, "wb") as dst:
                dst.write(src.read())
        except Exception:
            pass

_ensure_antibot_js_present()
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        site TEXT NOT NULL,
        vid TEXT NOT NULL,
        ip TEXT,
        ua TEXT,
        name TEXT,
        phone TEXT,
        email TEXT,
        form_action TEXT,
        form_id TEXT,
        payload_json TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        site TEXT NOT NULL,
        vid TEXT NOT NULL,
        ip TEXT,
        ua TEXT,
        path TEXT,
        ref TEXT,
        kind TEXT NOT NULL,
        payload_json TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS visitors (
        vid TEXT NOT NULL,
        site TEXT NOT NULL,
        first_ts TEXT NOT NULL,
        last_ts TEXT NOT NULL,
        last_ip TEXT,
        last_ua TEXT,
        last_path TEXT,
        interaction_json TEXT,
        last_score INTEGER NOT NULL DEFAULT 0,
        last_reasons_json TEXT,
        captcha_required INTEGER NOT NULL DEFAULT 0,
        suspicious INTEGER NOT NULL DEFAULT 0,
        blocked INTEGER NOT NULL DEFAULT 0,
        lead_count INTEGER NOT NULL DEFAULT 0,
        last_phone TEXT,
        last_name TEXT,
        PRIMARY KEY (vid, site)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocked_phones (
        phone TEXT PRIMARY KEY,
        ts TEXT NOT NULL,
        reason TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocked_vids (
        vid TEXT PRIMARY KEY,
        ts TEXT NOT NULL,
        reason TEXT,
        phone TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        site TEXT NOT NULL,
        vid TEXT NOT NULL,
        phone TEXT,
        name TEXT,
        score INTEGER NOT NULL,
        reasons_json TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS captcha_challenges (
        id TEXT PRIMARY KEY,
        ts INTEGER NOT NULL,
        vid TEXT NOT NULL,
        site TEXT NOT NULL,
        question TEXT NOT NULL,
        answer TEXT NOT NULL
    )
    """)

    con.commit()
    con.close()


def cleanup_db():
    """Удаляем старые события и старые капчи."""
    con = db()
    cur = con.cursor()

    cutoff = datetime.now(timezone.utc) - timedelta(days=EVENTS_TTL_DAYS)
    cur.execute("DELETE FROM events WHERE ts < ?", (cutoff.isoformat(),))

    cutoff_captcha = int(time.time()) - CAPTCHA_TTL_SEC
    cur.execute("DELETE FROM captcha_challenges WHERE ts < ?", (cutoff_captcha,))

    con.commit()
    con.close()


@app.on_event("startup")
def on_startup():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    init_db()
    cleanup_db()


def require_admin(x_admin_token: Optional[str]):
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=500, detail="ADMIN_TOKEN is not set on server")
    if not x_admin_token or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")


def norm_phone(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    s = "".join(ch for ch in p if ch.isdigit() or ch == "+")
    s = s.replace("++", "+")
    digits = "".join(ch for ch in s if ch.isdigit())
    # RU нормализация (простая)
    if digits.startswith("8") and len(digits) == 11:
        return "+7" + digits[1:]
    if digits.startswith("7") and len(digits) == 11:
        return "+7" + digits[1:]
    if s.startswith("+") and len(digits) >= 10:
        return "+" + digits
    if len(digits) >= 10:
        return "+" + digits
    return s


def get_visitor(con, site: str, vid: str) -> Optional[sqlite3.Row]:
    cur = con.cursor()
    cur.execute("SELECT * FROM visitors WHERE site=? AND vid=?", (site, vid))
    return cur.fetchone()


def upsert_visitor(con, site: str, vid: str, ip: str, ua: str, path: Optional[str], interaction: Optional[dict] = None):
    cur = con.cursor()
    existing = get_visitor(con, site, vid)
    ts = now_iso()
    if existing is None:
        cur.execute("""
            INSERT INTO visitors (vid, site, first_ts, last_ts, last_ip, last_ua, last_path, interaction_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (vid, site, ts, ts, ip, ua, path, json.dumps(interaction or {})))
    else:
        # merge interaction
        old = {}
        try:
            old = json.loads(existing["interaction_json"] or "{}")
        except Exception:
            old = {}
        newi = old
        if interaction:
            # обновим только известные поля
            for k, v in interaction.items():
                newi[k] = v
        cur.execute("""
            UPDATE visitors
            SET last_ts=?, last_ip=?, last_ua=?, last_path=?, interaction_json=?
            WHERE site=? AND vid=?
        """, (ts, ip, ua, path, json.dumps(newi), site, vid))


def is_blocked(con, vid: str, phone: Optional[str]) -> bool:
    cur = con.cursor()
    cur.execute("SELECT 1 FROM blocked_vids WHERE vid=? LIMIT 1", (vid,))
    if cur.fetchone():
        return True
    if phone:
        cur.execute("SELECT 1 FROM blocked_phones WHERE phone=? LIMIT 1", (phone,))
        if cur.fetchone():
            return True
    return False


def lead_history_stats(con, site: str, vid: str, phone: Optional[str]) -> dict:
    cur = con.cursor()

    # для текущего VID
    cur.execute("SELECT COUNT(*) as c FROM leads WHERE site=? AND vid=?", (site, vid))
    vid_count = int(cur.fetchone()["c"])

    cur.execute("SELECT COUNT(DISTINCT COALESCE(phone,'')) as c FROM leads WHERE site=? AND vid=?", (site, vid))
    distinct_phones = int(cur.fetchone()["c"])

    cur.execute("SELECT COUNT(DISTINCT COALESCE(name,'')) as c FROM leads WHERE site=? AND vid=?", (site, vid))
    distinct_names = int(cur.fetchone()["c"])

    # для телефона (если есть)
    phone_count = 0
    if phone:
        cur.execute("SELECT COUNT(*) as c FROM leads WHERE site=? AND phone=?", (site, phone))
        phone_count = int(cur.fetchone()["c"])

    return {
        "vid_count": vid_count,
        "distinct_phones": distinct_phones,
        "distinct_names": distinct_names,
        "phone_count": phone_count,
    }


def score_suspicion(site: str, vid: str, interaction: dict, history: dict, lead: Optional[dict]) -> (int, List[str], bool, bool):
    """
    Возвращает: score, reasons[], captcha_required, suspicious_alert
    """
    score = 0
    reasons = []

    # 1) поведение на странице (минимальный интерактив + слишком быстро)
    dur = int(interaction.get("duration_ms") or 0)
    moves = int(interaction.get("mouse_moves") or 0)
    scrolls = int(interaction.get("scrolls") or 0)
    keys = int(interaction.get("keydowns") or 0)

    if dur and dur < 4000:
        score += 25
        reasons.append("fast_submit(<4s)")
    if (moves + scrolls + keys) < 3:
        score += 25
        reasons.append("low_interaction")

    # 2) повторные заявки
    if history["vid_count"] >= 2:
        score += 60
        reasons.append("repeat_leads_same_vid(>=2)")
    if history["distinct_phones"] >= 2:
        score += 60
        reasons.append("different_phones_same_vid")
    if history["distinct_names"] >= 2:
        score += 30
        reasons.append("different_names_same_vid")

    # 3) повторные заявки по телефону
    if history["phone_count"] >= 2:
        score += 40
        reasons.append("repeat_leads_same_phone(>=2)")

    # 4) специфично для лида (если прилетел)
    if lead:
        name = (lead.get("name") or "").strip()
        phone = (lead.get("phone") or "").strip()
        if phone and len(phone) < 10:
            score += 10
            reasons.append("short_phone")
        if name and len(name) < 2:
            score += 10
            reasons.append("short_name")

    captcha_required = score >= CAPTCHA_SCORE_THRESHOLD
    suspicious_alert = score >= ALERT_SCORE_THRESHOLD

    return score, reasons, captcha_required, suspicious_alert


def create_alert(con, site: str, vid: str, phone: Optional[str], name: Optional[str], score: int, reasons: List[str]):
    cur = con.cursor()
    cur.execute("""
        INSERT INTO alerts (ts, site, vid, phone, name, score, reasons_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (now_iso(), site, vid, phone, name, score, json.dumps(reasons, ensure_ascii=False)))
    con.commit()


class CollectIn(BaseModel):
    site: str
    vid: str
    path: Optional[str] = None
    ref: Optional[str] = None
    kind: str = Field(..., description="event|lead|heartbeat")
    interaction: Optional[Dict[str, Any]] = None
    lead: Optional[Dict[str, Any]] = None
    captcha: Optional[Dict[str, Any]] = None


@app.get("/health")
def health():
    return {"ok": True, "ts": now_iso()}


@app.get("/bridge", response_class=HTMLResponse)
def bridge():
    # простая страница-бридж (если нужно iFrame/bridge на сайт)
    return HTMLResponse("""<!doctype html><html><head><meta charset="utf-8"></head><body>
<script>
(function(){
  var KEY="svf_global_vid";
  function gen(){ return (crypto && crypto.randomUUID) ? crypto.randomUUID() : ("g_"+Math.random().toString(16).slice(2)+Date.now().toString(16)); }
  function get(){
    try{ var v=localStorage.getItem(KEY); if(!v){ v=gen(); localStorage.setItem(KEY,v); } return v; }
    catch(e){ return gen(); }
  }
  window.addEventListener("message", function(ev){
    if(ev && ev.data && ev.data.type==="svf_vid_req"){
      parent.postMessage({type:"svf_vid", vid:get()}, ev.origin || "*");
    }
  });
})();
</script></body></html>""")


@app.get("/antibot.js", response_class=PlainTextResponse)
def antibot_js():
    # отдаём JS из static
    js_path = os.path.join(STATIC_DIR, "antibot.js")
    if not os.path.exists(js_path):
        raise HTTPException(status_code=404, detail="antibot.js not found on server")
    with open(js_path, "r", encoding="utf-8") as f:
        return PlainTextResponse(f.read(), media_type="application/javascript")


@app.post("/collect")
async def collect(payload: CollectIn, request: Request):
    con = db()
    try:
        ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent", "")

        site = (payload.site or "").strip()[:200]
        vid = (payload.vid or "").strip()[:200]
        if not site or not vid:
            raise HTTPException(status_code=400, detail="site and vid are required")

        # обновляем визитора
        upsert_visitor(con, site, vid, ip or "", ua or "", payload.path, payload.interaction or {})

        cur = con.cursor()

        # пишем event/heartbeat
        if payload.kind in ("event", "heartbeat"):
            cur.execute("""
                INSERT INTO events (ts, site, vid, ip, ua, path, ref, kind, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (now_iso(), site, vid, ip, ua, payload.path, payload.ref, payload.kind, json.dumps({
                "interaction": payload.interaction,
                "extra": payload.lead  # на всякий
            }, ensure_ascii=False)))
            con.commit()

        # лид
        if payload.kind == "lead":
            lead = payload.lead or {}
            name = (lead.get("name") or "").strip()
            phone = norm_phone(lead.get("phone"))
            email = (lead.get("email") or "").strip()
            form_action = (lead.get("form_action") or "").strip()
            form_id = (lead.get("form_id") or "").strip()

            # если нужна капча — проверяем
            captcha_ok = True
            vrow = get_visitor(con, site, vid)
            need_captcha = int(vrow["captcha_required"]) == 1 if vrow else False

            if need_captcha:
                captcha_ok = False
                cap = payload.captcha or {}
                cid = (cap.get("id") or "").strip()
                ans = (cap.get("answer") or "").strip()
                if cid and ans:
                    cur.execute("SELECT * FROM captcha_challenges WHERE id=? LIMIT 1", (cid,))
                    ch = cur.fetchone()
                    if ch:
                        # проверка TTL
                        if int(time.time()) - int(ch["ts"]) <= CAPTCHA_TTL_SEC:
                            if ch["vid"] == vid and ch["site"] == site and (ch["answer"].strip() == ans.strip()):
                                captcha_ok = True

            if need_captcha and not captcha_ok:
                raise HTTPException(status_code=403, detail="captcha_required")

            cur.execute("""
                INSERT INTO leads (ts, site, vid, ip, ua, name, phone, email, form_action, form_id, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (now_iso(), site, vid, ip, ua, name, phone, email, form_action, form_id, json.dumps(lead, ensure_ascii=False)))
            con.commit()

            # обновим счётчик лидов визитора
            cur.execute("""
                UPDATE visitors
                SET lead_count = lead_count + 1,
                    last_phone=?,
                    last_name=?
                WHERE site=? AND vid=?
            """, (phone, name, site, vid))
            con.commit()

            # пересчёт риска после лида
            vrow = get_visitor(con, site, vid)
            interaction = {}
            try:
                interaction = json.loads(vrow["interaction_json"] or "{}") if vrow else {}
            except Exception:
                interaction = {}

            history = lead_history_stats(con, site, vid, phone)
            score, reasons, cap_req, susp = score_suspicion(site, vid, interaction, history, {"name": name, "phone": phone, "email": email})

            blocked = is_blocked(con, vid, phone)

            cur.execute("""
                UPDATE visitors
                SET last_score=?,
                    last_reasons_json=?,
                    captcha_required=?,
                    suspicious=?,
                    blocked=?
                WHERE site=? AND vid=?
            """, (score, json.dumps(reasons, ensure_ascii=False), int(cap_req), int(susp), int(blocked), site, vid))
            con.commit()

            if susp:
                # алерт только по подозрительным
                create_alert(con, site, vid, phone, name, score, reasons)

        return {"ok": True}
    finally:
        con.close()


@app.get("/risk")
def risk(site: str, vid: str):
    con = db()
    try:
        site = (site or "").strip()[:200]
        vid = (vid or "").strip()[:200]
        if not site or not vid:
            raise HTTPException(status_code=400, detail="site and vid are required")

        v = get_visitor(con, site, vid)
        if not v:
            return {
                "blocked": False,
                "suspicious": False,
                "captcha_required": False,
                "score": 0,
                "reasons": [],
                "history": {"count": 0, "distinct_phones": 0, "distinct_names": 0},
            }

        phone = v["last_phone"]
        blocked = is_blocked(con, vid, phone)

        reasons = []
        try:
            reasons = json.loads(v["last_reasons_json"] or "[]")
        except Exception:
            reasons = []

        # историю покажем как раньше (тебе удобно)
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) as c FROM leads WHERE site=? AND vid=?", (site, vid))
        count = int(cur.fetchone()["c"])
        cur.execute("SELECT COUNT(DISTINCT COALESCE(phone,'')) as c FROM leads WHERE site=? AND vid=?", (site, vid))
        distinct_phones = int(cur.fetchone()["c"])
        cur.execute("SELECT COUNT(DISTINCT COALESCE(name,'')) as c FROM leads WHERE site=? AND vid=?", (site, vid))
        distinct_names = int(cur.fetchone()["c"])

        return {
            "blocked": bool(blocked),
            "suspicious": bool(int(v["suspicious"])),
            "captcha_required": bool(int(v["captcha_required"])),
            "score": int(v["last_score"]),
            "reasons": reasons,
            "history": {
                "count": count,
                "distinct_phones": distinct_phones,
                "distinct_names": distinct_names
            }
        }
    finally:
        con.close()


# ---- CAPTCHA (простая математическая, без доменов/turnstile) ----

@app.get("/captcha/new")
def captcha_new(site: str, vid: str):
    con = db()
    try:
        site = (site or "").strip()[:200]
        vid = (vid or "").strip()[:200]
        if not site or not vid:
            raise HTTPException(status_code=400, detail="site and vid are required")

        a = secrets.randbelow(8) + 2   # 2..9
        b = secrets.randbelow(8) + 2   # 2..9
        cid = secrets.token_urlsafe(16)
        q = f"Сколько будет {a}+{b}?"
        ans = str(a + b)

        cur = con.cursor()
        cur.execute("""
            INSERT INTO captcha_challenges (id, ts, vid, site, question, answer)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (cid, int(time.time()), vid, site, q, ans))
        con.commit()

        return {"id": cid, "question": q}
    finally:
        con.close()


# ---- ADMIN API (для TG-бота) ----

class AdminBlockPhoneIn(BaseModel):
    phone: str
    reason: Optional[str] = None

class AdminBlockLeadIn(BaseModel):
    lead_id: int
    reason: Optional[str] = None

@app.post("/admin/block_phone")
def admin_block_phone(data: AdminBlockPhoneIn, x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    con = db()
    try:
        phone = norm_phone(data.phone)
        if not phone:
            raise HTTPException(status_code=400, detail="bad phone")
        reason = (data.reason or "").strip()[:300] or "blocked via tg"

        cur = con.cursor()
        cur.execute("INSERT OR REPLACE INTO blocked_phones (phone, ts, reason) VALUES (?, ?, ?)",
                    (phone, now_iso(), reason))

        # найдём все vid, кто оставлял заявки с этим телефоном
        cur.execute("SELECT DISTINCT vid FROM leads WHERE phone=?", (phone,))
        vids = [r["vid"] for r in cur.fetchall()]

        for v in vids:
            cur.execute("INSERT OR REPLACE INTO blocked_vids (vid, ts, reason, phone) VALUES (?, ?, ?, ?)",
                        (v, now_iso(), reason, phone))
            cur.execute("UPDATE visitors SET blocked=1 WHERE vid=?", (v,))

        con.commit()
        return {"ok": True, "phone": phone, "vids_blocked": len(vids), "vids": vids[:50]}
    finally:
        con.close()


@app.post("/admin/unblock_phone")
def admin_unblock_phone(data: AdminBlockPhoneIn, x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    con = db()
    try:
        phone = norm_phone(data.phone)
        if not phone:
            raise HTTPException(status_code=400, detail="bad phone")
        cur = con.cursor()
        cur.execute("DELETE FROM blocked_phones WHERE phone=?", (phone,))
        con.commit()
        return {"ok": True, "phone": phone}
    finally:
        con.close()


@app.post("/admin/block_lead")
def admin_block_lead(data: AdminBlockLeadIn, x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    con = db()
    try:
        cur = con.cursor()
        cur.execute("SELECT * FROM leads WHERE id=? LIMIT 1", (data.lead_id,))
        lead = cur.fetchone()
        if not lead:
            raise HTTPException(status_code=404, detail="lead not found")

        phone = lead["phone"]
        vid = lead["vid"]
        reason = (data.reason or "").strip()[:300] or f"blocked by lead_id={data.lead_id}"

        # блок телефона + связанного vid
        if phone:
            cur.execute("INSERT OR REPLACE INTO blocked_phones (phone, ts, reason) VALUES (?, ?, ?)",
                        (phone, now_iso(), reason))
            cur.execute("SELECT DISTINCT vid FROM leads WHERE phone=?", (phone,))
            vids = [r["vid"] for r in cur.fetchall()]
        else:
            vids = [vid]

        for v in vids:
            cur.execute("INSERT OR REPLACE INTO blocked_vids (vid, ts, reason, phone) VALUES (?, ?, ?, ?)",
                        (v, now_iso(), reason, phone))
            cur.execute("UPDATE visitors SET blocked=1 WHERE vid=?", (v,))

        con.commit()
        return {"ok": True, "lead_id": data.lead_id, "phone": phone, "vids_blocked": len(vids), "vids": vids[:50]}
    finally:
        con.close()


@app.get("/admin/lookup_phone")
def admin_lookup_phone(phone: str, x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    con = db()
    try:
        p = norm_phone(phone)
        if not p:
            raise HTTPException(status_code=400, detail="bad phone")
        cur = con.cursor()
        cur.execute("""
            SELECT id, ts, site, vid, name, phone
            FROM leads
            WHERE phone=?
            ORDER BY id DESC
            LIMIT 50
        """, (p,))
        leads = [dict(r) for r in cur.fetchall()]

        vids = sorted(list({l["vid"] for l in leads}))

        cur.execute("SELECT 1 FROM blocked_phones WHERE phone=? LIMIT 1", (p,))
        phone_blocked = bool(cur.fetchone())

        # какие из этих vids заблокированы
        blocked_vids = []
        for v in vids:
            cur.execute("SELECT 1 FROM blocked_vids WHERE vid=? LIMIT 1", (v,))
            if cur.fetchone():
                blocked_vids.append(v)

        return {
            "phone": p,
            "phone_blocked": phone_blocked,
            "vids": vids,
            "blocked_vids": blocked_vids,
            "leads": leads
        }
    finally:
        con.close()


@app.get("/admin/alerts")
def admin_alerts(since_id: int = 0, limit: int = 20, x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    con = db()
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT * FROM alerts
            WHERE id > ?
            ORDER BY id ASC
            LIMIT ?
        """, (since_id, max(1, min(limit, 100))))
        rows = [dict(r) for r in cur.fetchall()]
        # распарсим reasons
        for r in rows:
            try:
                r["reasons"] = json.loads(r.get("reasons_json") or "[]")
            except Exception:
                r["reasons"] = []
        return {"ok": True, "items": rows}
    finally:
        con.close()
