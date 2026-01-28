import os, time, sqlite3
import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

DB_PATH = os.environ.get("DB_PATH", "/data/antibot.db")

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_SECRET = os.environ.get("TG_SECRET", "")
ADMIN_CHAT_IDS = [x.strip() for x in os.environ.get("ADMIN_CHAT_IDS", "").split(",") if x.strip()]

app = FastAPI()

# CORS чтобы сайты могли дергать /collect из браузера
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # потом можно сузить
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("""
        CREATE TABLE IF NOT EXISTS leads(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts INTEGER,
          site TEXT,
          visitor_id TEXT,
          phone_digits TEXT,
          phone_raw TEXT,
          name TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS blocks(
          visitor_id TEXT PRIMARY KEY,
          ts INTEGER,
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
    con.commit()
    return con


def norm_phone_digits(raw: str) -> str:
    d = "".join(ch for ch in (raw or "") if ch.isdigit())
    if len(d) == 11 and d.startswith("8"):
        d = "7" + d[1:]
    return d


def tg_send(chat_id: str, text: str):
    if not TG_BOT_TOKEN:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
            timeout=10,
        )
    except Exception:
        pass


def tg_broadcast(text: str):
    for cid in ADMIN_CHAT_IDS:
        tg_send(cid, text)


def ensure_admin(chat_id: str) -> bool:
    if not ADMIN_CHAT_IDS:
        return True
    return chat_id in ADMIN_CHAT_IDS


# ----- bridge для "глобального visitor_id" (для мультисайта) -----
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
    if(ev && ev.data && ev.data.type==="svf_vid_req"){
      parent.postMessage({type:"svf_vid", vid:get()}, ev.origin || "*");
    }
  });
})();
</script></body></html>
"""

@app.get("/bridge", response_class=HTMLResponse)
def bridge():
    return HTMLResponse(BRIDGE_HTML)


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
    body = await req.json()
    site = str(body.get("site") or "").strip() or "unknown"
    visitor_id = str(body.get("visitorId") or "").strip()
    phone_raw = str(body.get("phone") or "").strip()
    name = str(body.get("name") or "").strip()

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
        "INSERT INTO leads(ts, site, visitor_id, phone_digits, phone_raw, name) VALUES(?,?,?,?,?,?)",
        (ts, site, visitor_id, phone_digits, phone_raw, name),
    )

    if phone_digits and (len(prev_phones) >= 1 and phone_digits not in prev_phones):
        try:
            con.execute("INSERT INTO alerts_sent(visitor_id, kind, value, ts) VALUES(?,?,?,?)",
                        (visitor_id, "phone", phone_digits, ts))
            tg_broadcast(
                "⚠️ Один visitor_id использует разные телефоны\n"
                f"site: {site}\nvid: {visitor_id}\nновый: {phone_raw or phone_digits}\n"
                f"были: {', '.join(sorted(prev_phones))}\n"
                f"/blockvid {visitor_id}"
            )
        except sqlite3.IntegrityError:
            pass

    if name and (len(prev_names) >= 1 and name not in prev_names):
        try:
            con.execute("INSERT INTO alerts_sent(visitor_id, kind, value, ts) VALUES(?,?,?,?)",
                        (visitor_id, "name", name, ts))
            tg_broadcast(
                "⚠️ Один visitor_id использует разные имена\n"
                f"site: {site}\nvid: {visitor_id}\nновое: {name}\n"
                f"были: {', '.join(sorted(prev_names))}\n"
                f"/blockvid {visitor_id}"
            )
        except sqlite3.IntegrityError:
            pass

    con.commit()
    con.close()
    return {"ok": True}


@app.post("/tg")
async def tg_webhook(req: Request):
    if TG_SECRET:
        hdr = req.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if hdr != TG_SECRET:
            return {"ok": True}

    upd = await req.json()
    msg = upd.get("message") or {}
    chat_id = str((msg.get("chat") or {}).get("id") or "")
    text = str(msg.get("text") or "").strip()

    if not chat_id or not text:
        return {"ok": True}
    if not ensure_admin(chat_id):
        tg_send(chat_id, "Нет доступа.")
        return {"ok": True}

    con = db()

    def reply(s: str): tg_send(chat_id, s)

    parts = text.split(maxsplit=1)
    cmd = parts[0]
    arg = parts[1].strip() if len(parts) > 1 else ""

    if cmd == "/find":
        pd = norm_phone_digits(arg)
        if not pd:
            reply("Формат: /find +79991234567")
        else:
            rows = con.execute(
                "SELECT ts, site, visitor_id, phone_raw, name FROM leads WHERE phone_digits=? ORDER BY ts DESC LIMIT 5",
                (pd,)
            ).fetchall()
            if not rows:
                reply("Не найдено.")
            else:
                out = ["Найдено:"]
                for ts, site, vid, ph, nm in rows:
                    out.append(
                        f"- {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} | {site}\n"
                        f"  vid: {vid}\n"
                        f"  phone: {ph}\n"
                        f"  name: {nm or '-'}"
                    )
                reply("\n".join(out))

    elif cmd == "/blockvid":
        vid = arg
        if not vid:
            reply("Формат: /blockvid <visitor_id>")
        else:
            con.execute("INSERT OR REPLACE INTO blocks(visitor_id, ts, reason) VALUES(?,?,?)",
                        (vid, int(time.time()), "manual_tg"))
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
        reply("Команды:\n/find <phone>\n/blockvid <vid>\n/unblockvid <vid>")

    con.close()
    return {"ok": True
    }
