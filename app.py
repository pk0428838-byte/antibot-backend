import os
import time
import sqlite3
from typing import Optional, Dict, Any

import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, Response


# ===== ENV =====
DB_PATH = os.environ.get("DB_PATH", "/data/antibot.db")

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
TG_SECRET = os.environ.get("TG_SECRET", "").strip()

ADMIN_CHAT_IDS = [
    x.strip() for x in os.environ.get("ADMIN_CHAT_IDS", "").split(",") if x.strip()
]


# ===== APP =====
app = FastAPI(title="Antibot Backend", version="1.0.0")


# ===== DB =====
def db() -> sqlite3.Connection:
    # DB_PATH может быть просто "antibot.db" без директории
    d = os.path.dirname(DB_PATH)
    if d:
        os.makedirs(d, exist_ok=True)

    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")

    con.execute("""
        CREATE TABLE IF NOT EXISTS leads(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts INTEGER NOT NULL,
          site TEXT NOT NULL,
          visitor_id TEXT NOT NULL,
          phone_digits TEXT DEFAULT '',
          phone_raw TEXT DEFAULT '',
          name TEXT DEFAULT '',
          page_url TEXT DEFAULT '',
          ip TEXT DEFAULT '',
          ua TEXT DEFAULT ''
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS blocks(
          visitor_id TEXT PRIMARY KEY,
          ts INTEGER NOT NULL,
          reason TEXT DEFAULT ''
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS alerts_sent(
          visitor_id TEXT,
          kind TEXT,
          value TEXT,
          ts INTEGER,
          PRIMARY KEY(visitor_id, kind, value)
        )
    """)

    con.execute("CREATE INDEX IF NOT EXISTS idx_leads_vid_ts ON leads(visitor_id, ts);")
    con.execute("CREATE INDEX IF NOT EXISTS idx_leads_phone ON leads(phone_digits, ts);")
    con.execute("CREATE INDEX IF NOT EXISTS idx_leads_site_ts ON leads(site, ts);")

    con.commit()
    return con


def norm_phone_digits(raw: str) -> str:
    d = "".join(ch for ch in (raw or "") if ch.isdigit())
    # Россия: 8XXXXXXXXXX -> 7XXXXXXXXXX
    if len(d) == 11 and d.startswith("8"):
        d = "7" + d[1:]
    return d


# ===== TG =====
def tg_send(chat_id: str, text: str) -> None:
    if not TG_BOT_TOKEN or not chat_id:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
            timeout=10,
        )
    except Exception:
        pass


def tg_broadcast(text: str) -> None:
    for cid in ADMIN_CHAT_IDS:
        tg_send(cid, text)


def ensure_admin(chat_id: str) -> bool:
    # если админы не заданы — считаем всех админами (для первого запуска)
    if not ADMIN_CHAT_IDS:
        return True
    return chat_id in ADMIN_CHAT_IDS


# ===== BRIDGE (глобальный visitor_id между сайтами) =====
BRIDGE_HTML = """<!doctype html><html><head><meta charset="utf-8"></head><body>
<script>
(function(){
  var KEY="svf_global_vid";
  function gen(){ return (crypto && crypto.randomUUID) ? crypto.randomUUID() : ("g_"+Math.random().toString(16).slice(2)+Date.now().toString(16)); }
  function get(){
    try{ var v=localStorage.getItem(KEY); if(!v){ v=gen(); localStorage.setItem(KEY,v); } return v; }
    catch(e){ return gen(); }
  }
  window.addEventListener("message", function(ev){
    try{
      if(ev && ev.data && ev.data.type==="svf_vid_req"){
        parent.postMessage({type:"svf_vid", vid:get()}, ev.origin || "*");
      }
    }catch(e){}
  });
})();
</script></body></html>
"""


@app.get("/healthz")
def healthz():
    return {"ok": True, "ts": int(time.time())}


@app.get("/bridge", response_class=HTMLResponse)
def bridge_get():
    return HTMLResponse(BRIDGE_HTML)


# чтобы curl -I /bridge не давал 405
@app.head("/bridge")
def bridge_head():
    return Response(status_code=200)


@app.get("/is_blocked")
def is_blocked(vid: str = ""):
    if not vid:
        return {"blocked": False}
    con = db()
    row = con.execute("SELECT 1 FROM blocks WHERE visitor_id = ?", (vid,)).fetchone()
    con.close()
    return {"blocked": bool(row)}


@app.post("/collect")
async def collect(req: Request):
    body: Dict[str, Any] = await req.json()

    site = str(body.get("site") or "").strip() or "unknown"
    visitor_id = str(body.get("visitorId") or "").strip()

    phone_raw = str(body.get("phone") or "").strip()
    name = str(body.get("name") or "").strip()

    page_url = str(body.get("url") or "").strip()
    ip = (req.headers.get("x-real-ip") or "").strip() or (req.client.host if req.client else "")
    ua = str(req.headers.get("user-agent") or "").strip()

    if not visitor_id:
        raise HTTPException(400, "visitorId missing")

    phone_digits = norm_phone_digits(phone_raw)
    ts = int(time.time())

    con = db()

    prev_phones = {r[0] for r in con.execute(
        "SELECT DISTINCT phone_digits FROM leads WHERE visitor_id=? AND phone_digits!=''",
        (visitor_id,)
    ).fetchall()}

    prev_names = {r[0] for r in con.execute(
        "SELECT DISTINCT name FROM leads WHERE visitor_id=? AND name!=''",
        (visitor_id,)
    ).fetchall()}

    con.execute(
        """
        INSERT INTO leads(ts, site, visitor_id, phone_digits, phone_raw, name, page_url, ip, ua)
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (ts, site, visitor_id, phone_digits, phone_raw, name, page_url, ip, ua),
    )

    # Уведомление: один visitor_id -> разные телефоны
    if phone_digits and (len(prev_phones) >= 1 and phone_digits not in prev_phones):
        try:
            con.execute(
                "INSERT INTO alerts_sent(visitor_id, kind, value, ts) VALUES(?,?,?,?)",
                (visitor_id, "phone", phone_digits, ts),
            )
            con.commit()
            tg_broadcast(
                "⚠️ Один visitor_id использует разные телефоны\n"
                f"site: {site}\n"
                f"vid: {visitor_id}\n"
                f"новый: {phone_raw or phone_digits}\n"
                f"были: {', '.join(sorted(prev_phones))}\n"
                f"url: {page_url or '-'}\n"
                f"/blockvid {visitor_id}"
            )
        except sqlite3.IntegrityError:
            pass

    # Уведомление: один visitor_id -> разные имена
    if name and (len(prev_names) >= 1 and name not in prev_names):
        try:
            con.execute(
                "INSERT INTO alerts_sent(visitor_id, kind, value, ts) VALUES(?,?,?,?)",
                (visitor_id, "name", name, ts),
            )
            con.commit()
            tg_broadcast(
                "⚠️ Один visitor_id использует разные имена\n"
                f"site: {site}\n"
                f"vid: {visitor_id}\n"
                f"новое: {name}\n"
                f"были: {', '.join(sorted(prev_names))}\n"
                f"url: {page_url or '-'}\n"
                f"/blockvid {visitor_id}"
            )
        except sqlite3.IntegrityError:
            pass

    con.commit()
    con.close()
    return {"ok": True}


@app.post("/tg")
async def tg_webhook(req: Request):
    # секретный заголовок от телеги
    if TG_SECRET:
        hdr = req.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if hdr != TG_SECRET:
            # молча игнорим
            return {"ok": True}

    upd = await req.json()
    msg = upd.get("message") or upd.get("edited_message") or {}
    chat_id = str((msg.get("chat") or {}).get("id") or "")
    text = str(msg.get("text") or "").strip()

    if not chat_id or not text:
        return {"ok": True}

    if not ensure_admin(chat_id):
        tg_send(chat_id, "Нет доступа.")
        return {"ok": True}

    con = db()

    def reply(s: str):
        tg_send(chat_id, s)

    parts = text.split(maxsplit=1)
    cmd = parts[0]
    arg = parts[1].strip() if len(parts) > 1 else ""

    if cmd == "/help":
        reply("Команды:\n/find <phone>\n/blockvid <vid>\n/unblockvid <vid>")

    elif cmd == "/find":
        pd = norm_phone_digits(arg)
        if not pd:
            reply("Формат: /find +79991234567")
        else:
            rows = con.execute(
                """
                SELECT ts, site, visitor_id, phone_raw, name, page_url
                FROM leads
                WHERE phone_digits=?
                ORDER BY ts DESC
                LIMIT 5
                """,
                (pd,),
            ).fetchall()
            if not rows:
                reply("Не найдено.")
            else:
                out = ["Найдено (последние 5):"]
                for ts, site, vid, ph, nm, url in rows:
                    out.append(
                        f"- {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} | {site}\n"
                        f"  vid: {vid}\n"
                        f"  phone: {ph or '-'}\n"
                        f"  name: {nm or '-'}\n"
                        f"  url: {url or '-'}"
                    )
                reply("\n".join(out))

    elif cmd == "/blockvid":
        vid = arg
        if not vid:
            reply("Формат: /blockvid <visitor_id>")
        else:
            con.execute(
                "INSERT OR REPLACE INTO blocks(visitor_id, ts, reason) VALUES(?,?,?)",
                (vid, int(time.time()), "manual_tg"),
            )
            con.commit()
            reply(f"Заблокирован:\n{vid}")

    elif cmd == "/unblockvid":
        vid = arg
        if not vid:
            reply("Формат: /unblockvid <visitor_id>")
        else:
            con.execute("DELETE FROM blocks WHERE visitor_id=?", (vid,))
            con.commit()
            reply(f"Разблокирован:\n{vid}")

    else:
        reply("Не понял. /help")

    con.close()
    return {"ok": True}


# если хочешь проверять curl-ом без телеги
@app.get("/", response_class=PlainTextResponse)
def root():
    return "ok"
