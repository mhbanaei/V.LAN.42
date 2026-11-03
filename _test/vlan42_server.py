# -*- coding: utf-8 -*-
"""
V.Lan.42 - central server (run this on your VPS)

Architecture:
  * Control channel : TCP, JSON messages, X25519 handshake + AES-GCM session encryption
  * Data channel    : UDP relay - clients send encrypted virtual-LAN packets to the server,
                      the server forwards them to the other members of the room
  * Persistence     : SQLite (users, rooms, memberships, bans, friends)

Everything (signaling + game traffic) goes through this server, so every player gets
the low, stable ping of your VPS instead of relying on public MQTT brokers and NAT tricks.

Run:   python vlan42_server.py            (config in vlan42_server.json, DB in vlan42_data/)
coded by Hossein & Erfan  -  https://github.com/mhbanaei
"""
import os, sys, json, time, socket, sqlite3, secrets, hashlib, base64, struct, threading, traceback

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CFG_FILE = os.path.join(APP_DIR, "vlan42_server.json")
DATA_DIR = os.path.join(APP_DIR, "vlan42_data")
DB_FILE = os.path.join(DATA_DIR, "db.sqlite")
LOG_FILE = os.path.join(APP_DIR, "vlan42_server.log")

MAX_ROOMS_PER_USER = 3
DEFAULT_LIMIT = 16
UDP_TIMEOUT = 30          # seconds without UDP traffic -> member marked offline (timeout)
DEFAULT_TCP_PORT = 4242
DEFAULT_UDP_PORT = 4242
PERMS = ("kick", "ban", "unban", "limit")
INVITE_PREFIX = "vlan42://join/"

_logf = None
_log_lock = threading.Lock()


def log(msg):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + str(msg)
    print(line, flush=True)
    global _logf
    with _log_lock:
        try:
            if _logf is None:
                _logf = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
            _logf.write(line + "\n")
        except OSError:
            _logf = False


def load_cfg():
    try:
        with open(CFG_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


# ------------------------------------------------------------------ database
class DB:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.cx = sqlite3.connect(path, check_same_thread=False)
        self.cx.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self._init()

    def _init(self):
        with self.lock:
            self.cx.executescript("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE,
                salt TEXT, pwhash TEXT, token TEXT, created REAL);
            CREATE TABLE IF NOT EXISTS rooms(
                id INTEGER PRIMARY KEY, code TEXT UNIQUE, name TEXT,
                salt TEXT, pwhash TEXT, roomkey TEXT, pwd TEXT,
                owner_id INTEGER, member_limit INTEGER DEFAULT 16, created REAL);
            CREATE TABLE IF NOT EXISTS members(
                room_id INTEGER, user_id INTEGER, role TEXT DEFAULT 'member',
                perms TEXT DEFAULT '{}', vip TEXT, joined REAL,
                PRIMARY KEY(room_id, user_id));
            CREATE TABLE IF NOT EXISTS bans(
                room_id INTEGER, user_id INTEGER, by_id INTEGER, reason TEXT, ts REAL,
                PRIMARY KEY(room_id, user_id));
            CREATE TABLE IF NOT EXISTS freq(
                from_id INTEGER, to_id INTEGER, ts REAL, PRIMARY KEY(from_id, to_id));
            CREATE TABLE IF NOT EXISTS friends(
                a INTEGER, b INTEGER, PRIMARY KEY(a, b));
            """)
            self.cx.commit()

    def q(self, sql, args=()):
        with self.lock:
            return self.cx.execute(sql, args).fetchall()

    def one(self, sql, args=()):
        r = self.q(sql, args)
        return r[0] if r else None

    def run(self, sql, args=()):
        with self.lock:
            cur = self.cx.execute(sql, args)
            self.cx.commit()
            return cur


def pw_hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120_000).hex()


def make_vip(taken):
    """First free guest address in 10.77.x.y (owner always holds 10.77.0.1)."""
    for x in range(1, 251):
        for y in range(1, 251):
            ip = f"10.77.{x}.{y}"
            if ip not in taken:
                return ip
    return None


# ------------------------------------------------------------------ server
class Server:
    def __init__(self, cfg):
        self.tcp_port = int(cfg.get("tcp_port", DEFAULT_TCP_PORT))
        self.udp_port = int(cfg.get("udp_port", DEFAULT_UDP_PORT))
        self.udp_timeout = int(cfg.get("udp_timeout", UDP_TIMEOUT))
        self.db = DB(DB_FILE)
        self.lock = threading.RLock()
        self.conns = {}            # user_id -> Conn (latest login wins)
        self.udp_users = {}        # user_id -> {"ep": (ip,port), "last": t}
        self.ep_users = {}         # (ip,port) -> user_id
        self.tokens = {}           # raw 16-byte token -> user_id (cache)
        self.udp_ready = False

    # ---------------- helpers
    def user_by_name(self, name):
        return self.db.one("SELECT * FROM users WHERE username=?", (name,))

    def user_by_id(self, uid):
        return self.db.one("SELECT * FROM users WHERE id=?", (uid,))

    def room_by_id(self, rid):
        return self.db.one("SELECT * FROM rooms WHERE id=?", (rid,))

    def room_by_code(self, code):
        return self.db.one("SELECT * FROM rooms WHERE code=?", (code,))

    def member_row(self, rid, uid):
        return self.db.one("SELECT * FROM members WHERE room_id=? AND user_id=?", (rid, uid))

    def room_members(self, rid):
        return self.db.q("SELECT * FROM members WHERE room_id=? ORDER BY joined", (rid,))

    def is_banned(self, rid, uid):
        return self.db.one("SELECT * FROM bans WHERE room_id=? AND user_id=?", (rid, uid)) is not None

    def membership_count(self, uid):
        return len(self.db.q("SELECT room_id FROM members WHERE user_id=?", (uid,)))

    def online_uids(self, rid):
        """Users that have an activated connection for this room."""
        out = set()
        for c in list(self.conns.values()):
            if c.user and c.active_room == rid:
                out.add(c.user["id"])
        return out

    def push_room(self, rid, p, skip=None):
        """Push to every member of the room that has a live session.

        Members who only sit on the landing page are included on purpose: a kick,
        an admin change or a timeout must show up on both sides in the same second
        instead of after the next poll."""
        for mrow in self.room_members(rid):
            uid = mrow["user_id"]
            if uid == skip:
                continue
            c = self.conns.get(uid)
            if not c:
                continue
            try:
                c.push(p)
            except Exception:
                pass

    def push_state(self, rid, skip=None):
        """The roster of one room, personalised for whoever receives it."""
        for mrow in self.room_members(rid):
            uid = mrow["user_id"]
            if uid == skip:
                continue
            c = self.conns.get(uid)
            if not c:
                continue
            try:
                c.push({"t": "room_state", "room": self.room_json(rid, uid)})
            except Exception:
                pass

    def push_user(self, uid, p):
        c = self.conns.get(uid)
        if c:
            try:
                c.push(p)
            except Exception:
                pass

    # ---------------- auth
    def do_register(self, c, m):
        u = (m.get("u") or "").strip()
        p = m.get("p") or ""
        if not (3 <= len(u) <= 20) or not u.replace("_", "").replace(".", "").isalnum():
            return {"t": "register", "ok": False, "err": "Username must be 3-20 chars (letters, numbers, _ .)"}
        if len(p) < 4:
            return {"t": "register", "ok": False, "err": "Password must be at least 4 characters"}
        if self.user_by_name(u):
            return {"t": "register", "ok": False, "err": "This username is already taken"}
        salt = secrets.token_hex(16)
        token = secrets.token_hex(16)
        self.db.run("INSERT INTO users(username,salt,pwhash,token,created) VALUES(?,?,?,?,?)",
                    (u, salt, pw_hash(p, salt), token, time.time()))
        c.login(self.user_by_name(u))
        return {"t": "register", "ok": True, "token": token, "user": {"id": c.user["id"], "name": u}}

    def do_login(self, c, m):
        u = self.user_by_name((m.get("u") or "").strip())
        if not u or pw_hash(m.get("p") or "", u["salt"]) != u["pwhash"]:
            return {"t": "login", "ok": False, "err": "Wrong username or password"}
        token = secrets.token_hex(16)
        self.db.run("UPDATE users SET token=? WHERE id=?", (token, u["id"]))
        c.login(self.user_by_name(u["username"]))
        return {"t": "login", "ok": True, "token": token, "user": {"id": u["id"], "name": u["username"]}}

    def do_login_token(self, c, m):
        tok = m.get("token") or ""
        u = self.db.one("SELECT * FROM users WHERE token=?", (tok,))
        if not u:
            return {"t": "login_token", "ok": False, "err": "Session expired - please log in again"}
        c.login(u)
        return {"t": "login_token", "ok": True, "token": tok, "user": {"id": u["id"], "name": u["username"]}}

    # ---------------- rooms
    def room_json(self, rid, uid):
        r = self.room_by_id(rid)
        if not r:
            return None
        me = self.member_row(rid, uid)
        online = self.online_uids(rid)
        members = []
        for mrow in self.room_members(rid):
            u = self.user_by_id(mrow["user_id"])
            if not u:
                continue
            members.append({"id": u["id"], "name": u["username"], "role": mrow["role"],
                            "perms": json.loads(mrow["perms"] or "{}"), "vip": mrow["vip"],
                            "online": u["id"] in online})
        return {"id": r["id"], "code": r["code"], "name": r["name"], "pwd": r["pwd"],
                "key": r["roomkey"], "limit": r["member_limit"], "members": members,
                "my_role": me["role"] if me else None, "my_perms": json.loads(me["perms"] or "{}") if me else {}}

    def make_invite(self, r):
        raw = json.dumps({"c": r["code"], "p": r["pwd"]}, separators=(",", ":")).encode()
        return INVITE_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def can(self, uid, rid, perm):
        me = self.member_row(rid, uid)
        if not me:
            return False
        if me["role"] == "owner":
            return True
        if me["role"] == "admin":
            return bool(json.loads(me["perms"] or "{}").get(perm))
        return False

    def do_create_room(self, c, m):
        uid = c.user["id"]
        name = (m.get("name") or "").strip()[:32] or "room"
        pwd = (m.get("pwd") or "").strip()
        if not (3 <= len(name)) or len(pwd) < 4:
            return {"t": "create_room", "ok": False, "err": "Room name min 3 chars, password min 4 chars"}
        if self.membership_count(uid) >= MAX_ROOMS_PER_USER:
            return {"t": "create_room", "ok": False,
                    "err": f"You are in {MAX_ROOMS_PER_USER} rooms already - remove one from your list first"}
        code = secrets.token_hex(3)
        roomkey = secrets.token_hex(32)
        cur = self.db.run("INSERT INTO rooms(code,name,salt,pwhash,roomkey,pwd,owner_id,member_limit,created)"
                          " VALUES(?,?,?,?,?,?,?,?,?)",
                          (code, name, "", "", roomkey, pwd, uid, DEFAULT_LIMIT, time.time()))
        rid = cur.lastrowid
        self.db.run("INSERT INTO members(room_id,user_id,role,perms,vip,joined) VALUES(?,?,?,?,?,?)",
                    (rid, uid, "owner", "{}", "10.77.0.1", time.time()))
        r = self.room_by_id(rid)
        return {"t": "create_room", "ok": True, "room": self.room_json(rid, uid),
                "invite": self.make_invite(r)}

    def do_join_room(self, c, m):
        uid = c.user["id"]
        code = (m.get("code") or "").strip()
        pwd = m.get("pwd") or ""
        r = self.room_by_code(code)
        if not r:
            return {"t": "join_room", "ok": False, "err": "No room with this invite"}
        if pwd != r["pwd"]:
            return {"t": "join_room", "ok": False, "err": "Wrong room password"}
        if self.is_banned(r["id"], uid):
            return {"t": "join_room", "ok": False, "err": "You are banned from this room"}
        if self.member_row(r["id"], uid):
            return {"t": "join_room", "ok": True, "room": self.room_json(r["id"], uid),
                    "invite": self.make_invite(r)}
        if self.membership_count(uid) >= MAX_ROOMS_PER_USER:
            return {"t": "join_room", "ok": False,
                    "err": f"You are in {MAX_ROOMS_PER_USER} rooms already - remove one from your list first"}
        if len(self.room_members(r["id"])) >= r["member_limit"]:
            return {"t": "join_room", "ok": False, "err": "This room is full"}
        taken = {row["vip"] for row in self.room_members(r["id"])}
        vip = make_vip(taken)
        self.db.run("INSERT INTO members(room_id,user_id,role,perms,vip,joined) VALUES(?,?,?,?,?,?)",
                    (r["id"], uid, "member", "{}", vip, time.time()))
        self.push_state(r["id"])
        return {"t": "join_room", "ok": True, "room": self.room_json(r["id"], uid),
                "invite": self.make_invite(r)}

    def do_remove_room(self, c, m):
        uid = c.user["id"]
        rid = int(m.get("room") or 0)
        me = self.member_row(rid, uid)
        if not me:
            return {"t": "remove_room", "ok": False, "err": "You are not in this room"}
        self.db.run("DELETE FROM members WHERE room_id=? AND user_id=?", (rid, uid))
        if me["role"] == "owner":
            # transfer ownership to the longest-serving admin, then member; else delete the room
            rows = self.room_members(rid)
            heir = next((x for x in rows if x["role"] == "admin"), None) or \
                   (rows[0] if rows else None)
            if heir:
                self.db.run("UPDATE members SET role='owner', perms='{}' WHERE room_id=? AND user_id=?",
                            (rid, heir["user_id"]))
                self.db.run("UPDATE rooms SET owner_id=? WHERE id=?", (heir["user_id"], rid))
            else:
                self.db.run("DELETE FROM members WHERE room_id=?", (rid,))
                self.db.run("DELETE FROM bans WHERE room_id=?", (rid,))
                self.db.run("DELETE FROM rooms WHERE id=?", (rid,))
                return {"t": "remove_room", "ok": True}
        if c.active_room == rid:
            c.active_room = None
        self.push_state(rid)
        return {"t": "remove_room", "ok": True}

    # ---------------- moderation
    def do_kick(self, c, m):
        uid, rid, target = c.user["id"], int(m.get("room") or 0), int(m.get("user") or 0)
        if not self.can(uid, rid, "kick"):
            return {"t": "kick", "ok": False, "err": "You do not have permission to kick"}
        me = self.member_row(rid, uid)
        t = self.member_row(rid, target)
        if not t:
            return {"t": "kick", "ok": False, "err": "That user is not a member"}
        if t["role"] != "member" and me["role"] != "owner":
            return {"t": "kick", "ok": False, "err": "Only the owner can kick admins"}
        self.db.run("DELETE FROM members WHERE room_id=? AND user_id=?", (rid, target))
        tu = self.user_by_id(target)
        self.push_user(target, {"t": "kicked", "room": rid, "by": c.user["username"]})
        tc = self.conns.get(target)
        if tc and tc.active_room == rid:
            tc.active_room = None
        if self.udp_users.get(target):
            self.udp_drop(target)
        self.push_state(rid)
        log(f"kick: {tu['username']} out of room {rid} by {c.user['username']}")
        return {"t": "kick", "ok": True}

    def do_ban(self, c, m):
        uid, rid, target = c.user["id"], int(m.get("room") or 0), int(m.get("user") or 0)
        if not self.can(uid, rid, "ban"):
            return {"t": "ban", "ok": False, "err": "You do not have permission to ban"}
        me = self.member_row(rid, uid)
        t = self.member_row(rid, target)
        if not t:
            return {"t": "ban", "ok": False, "err": "That user is not a member"}
        if t["role"] != "member" and me["role"] != "owner":
            return {"t": "ban", "ok": False, "err": "Only the owner can ban admins"}
        reason = (m.get("reason") or "").strip()[:120]
        self.db.run("INSERT OR REPLACE INTO bans(room_id,user_id,by_id,reason,ts) VALUES(?,?,?,?,?)",
                    (rid, target, uid, reason, time.time()))
        self.db.run("DELETE FROM members WHERE room_id=? AND user_id=?", (rid, target))
        self.push_user(target, {"t": "banned", "room": rid, "by": c.user["username"], "reason": reason})
        tc = self.conns.get(target)
        if tc and tc.active_room == rid:
            tc.active_room = None
        if self.udp_users.get(target):
            self.udp_drop(target)
        self.push_state(rid)
        log(f"ban: user {target} from room {rid} by {c.user['username']} ({reason})")
        return {"t": "ban", "ok": True}

    def do_unban(self, c, m):
        uid, rid, target = c.user["id"], int(m.get("room") or 0), int(m.get("user") or 0)
        if not self.can(uid, rid, "unban"):
            return {"t": "unban", "ok": False, "err": "You do not have permission to unban"}
        self.db.run("DELETE FROM bans WHERE room_id=? AND user_id=?", (rid, target))
        return {"t": "unban", "ok": True}

    def do_ban_list(self, c, m):
        rid = int(m.get("room") or 0)
        if not self.member_row(rid, c.user["id"]):
            return {"t": "ban_list", "ok": False, "err": "You are not in this room"}
        out = []
        for b in self.db.q("SELECT * FROM bans WHERE room_id=?", (rid,)):
            u = self.user_by_id(b["user_id"])
            by = self.user_by_id(b["by_id"])
            out.append({"id": b["user_id"], "name": u["username"] if u else "?",
                        "by": by["username"] if by else "?", "reason": b["reason"], "ts": b["ts"]})
        return {"t": "ban_list", "ok": True, "bans": out}

    def do_set_admin(self, c, m):
        uid, rid, target = c.user["id"], int(m.get("room") or 0), int(m.get("user") or 0)
        me = self.member_row(rid, uid)
        if not me or me["role"] != "owner":
            return {"t": "set_admin", "ok": False, "err": "Only the owner can manage admins"}
        t = self.member_row(rid, target)
        if not t or t["role"] == "owner":
            return {"t": "set_admin", "ok": False, "err": "Invalid target"}
        if m.get("admin"):
            perms = {k: bool(m.get("perms", {}).get(k)) for k in PERMS}
            self.db.run("UPDATE members SET role='admin', perms=? WHERE room_id=? AND user_id=?",
                        (json.dumps(perms), rid, target))
        else:
            self.db.run("UPDATE members SET role='member', perms='{}' WHERE room_id=? AND user_id=?",
                        (rid, target))
        self.push_state(rid)
        return {"t": "set_admin", "ok": True}

    def do_set_limit(self, c, m):
        uid, rid = c.user["id"], int(m.get("room") or 0)
        if not self.can(uid, rid, "limit"):
            return {"t": "set_limit", "ok": False, "err": "You do not have permission to set the limit"}
        try:
            lim = int(m.get("limit"))
        except (TypeError, ValueError):
            lim = 0
        if not (2 <= lim <= 64):
            return {"t": "set_limit", "ok": False, "err": "Member limit must be 2-64"}
        if len(self.room_members(rid)) > lim:
            return {"t": "set_limit", "ok": False, "err": "There are already more members than that"}
        self.db.run("UPDATE rooms SET member_limit=? WHERE id=?", (lim, rid))
        self.push_state(rid)
        return {"t": "set_limit", "ok": True}

    # ---------------- friends
    def friends_json(self, uid):
        ids = set()
        for r in self.db.q("SELECT * FROM friends WHERE a=? OR b=?", (uid, uid)):
            ids.add(r["a"] if r["b"] == uid else r["b"])
        out = []
        for fid in sorted(ids):
            u = self.user_by_id(fid)
            if u:
                out.append({"id": fid, "name": u["username"], "online": fid in self.conns})
        reqs = []
        for r in self.db.q("SELECT * FROM freq WHERE to_id=?", (uid,)):
            u = self.user_by_id(r["from_id"])
            if u:
                reqs.append({"id": r["from_id"], "name": u["username"]})
        return {"friends": out, "requests": reqs}

    def do_search(self, c, m):
        q = (m.get("q") or "").strip()
        if len(q) < 2:
            return {"t": "search", "ok": True, "users": []}
        rows = self.db.q("SELECT id,username FROM users WHERE username LIKE ? AND id<>? LIMIT 20",
                         (q + "%", c.user["id"]))
        return {"t": "search", "ok": True,
                "users": [{"id": r["id"], "name": r["username"]} for r in rows]}

    def do_add_friend(self, c, m):
        uid = c.user["id"]
        target = self.user_by_name((m.get("user") or "").strip())
        if not target:
            return {"t": "add_friend", "ok": False, "err": "No user with that name"}
        tid = target["id"]
        if tid == uid:
            return {"t": "add_friend", "ok": False, "err": "That is you"}
        pair = self.db.one("SELECT * FROM friends WHERE (a=? AND b=?) OR (a=? AND b=?)", (uid, tid, tid, uid))
        if pair:
            return {"t": "add_friend", "ok": False, "err": "You are already friends"}
        if self.db.one("SELECT * FROM freq WHERE from_id=? AND to_id=?", (tid, uid)):
            # they already asked us: accept both sides
            self.db.run("DELETE FROM freq WHERE from_id=? AND to_id=?", (tid, uid))
            self.db.run("INSERT OR IGNORE INTO friends(a,b) VALUES(?,?)", (*sorted((uid, tid)),))
            self.push_user(tid, {"t": "friend_upd", **self.friends_json(tid)})
            return {"t": "add_friend", "ok": True, "accepted": True, **self.friends_json(uid)}
        self.db.run("INSERT OR IGNORE INTO freq(from_id,to_id,ts) VALUES(?,?,?)", (uid, tid, time.time()))
        self.push_user(tid, {"t": "friend_req", "from": c.user["username"]})
        self.push_user(tid, {"t": "friend_upd", **self.friends_json(tid)})
        return {"t": "add_friend", "ok": True, **self.friends_json(uid)}

    def do_friend_resp(self, c, m):
        uid = c.user["id"]
        target = self.user_by_name((m.get("user") or "").strip())
        if not target:
            return {"t": "friend_resp", "ok": False, "err": "No user with that name"}
        tid = target["id"]
        if not self.db.one("SELECT * FROM freq WHERE from_id=? AND to_id=?", (tid, uid)):
            return {"t": "friend_resp", "ok": False, "err": "No pending request from that user"}
        self.db.run("DELETE FROM freq WHERE from_id=? AND to_id=?", (tid, uid))
        if m.get("accept"):
            self.db.run("INSERT OR IGNORE INTO friends(a,b) VALUES(?,?)", (*sorted((uid, tid)),))
        self.push_user(tid, {"t": "friend_upd", **self.friends_json(tid)})
        return {"t": "friend_resp", "ok": True, **self.friends_json(uid)}

    def do_remove_friend(self, c, m):
        uid = c.user["id"]
        target = self.user_by_name((m.get("user") or "").strip())
        if not target:
            return {"t": "remove_friend", "ok": False, "err": "No user with that name"}
        tid = target["id"]
        self.db.run("DELETE FROM friends WHERE (a=? AND b=?) OR (a=? AND b=?)", (uid, tid, tid, uid))
        self.db.run("DELETE FROM freq WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)",
                    (uid, tid, tid, uid))
        self.push_user(tid, {"t": "friend_upd", **self.friends_json(tid)})
        return {"t": "remove_friend", "ok": True, **self.friends_json(uid)}

    def do_pm(self, c, m):
        """One private message between two friends, relayed through this server."""
        uid = c.user["id"]
        target = self.user_by_name((m.get("user") or "").strip())
        if not target:
            return {"t": "pm", "ok": False, "err": "No user with that name"}
        tid = target["id"]
        if not self.db.one("SELECT * FROM friends WHERE (a=? AND b=?) OR (a=? AND b=?)", (uid, tid, tid, uid)):
            return {"t": "pm", "ok": False, "err": "You can write to a friend only"}
        text = (m.get("text") or "").strip()[:1000]
        if not text:
            return {"t": "pm", "ok": False, "err": "Nothing to send"}
        ts = time.time()
        tc = self.conns.get(tid)
        if tc:
            try:
                tc.push({"t": "pm", "from": c.user["username"], "text": text, "ts": ts})
            except Exception:
                tc = None
        return {"t": "pm", "ok": True, "delivered": bool(tc), "ts": ts}

    def do_invite(self, c, m):
        uid = c.user["id"]
        rid = int(m.get("room") or 0)
        target = self.user_by_name((m.get("user") or "").strip())
        if not target:
            return {"t": "invite", "ok": False, "err": "No user with that name"}
        r = self.room_by_id(rid)
        if not r or not self.member_row(rid, uid):
            return {"t": "invite", "ok": False, "err": "You are not in that room"}
        self.push_user(target["id"], {"t": "invite", "from": c.user["username"], "room": r["name"],
                                      "code": r["code"], "pwd": r["pwd"]})
        return {"t": "invite", "ok": True}

    # ---------------- UDP relay
    def udp_drop(self, uid):
        with self.lock:
            u = self.udp_users.pop(uid, None)
            if u and self.ep_users.get(u["ep"]) == uid:
                del self.ep_users[u["ep"]]

    def udp_open(self):
        """Bind the relay socket, shouting and retrying if something holds the port."""
        while True:
            cand = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cand.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
            cand.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
            try:
                cand.bind(("0.0.0.0", self.udp_port))
                return cand
            except OSError as ex:
                cand.close()
                log(f"UDP {self.udp_port} COULD NOT BE OPENED: {ex}")
                log("   players cannot join rooms. Close the other V.Lan.42 server window")
                log("   (or the program holding that port) - retrying in 3s.")
                self.udp_ready = False
                time.sleep(3)

    def udp_loop(self):
        s = self.udp_open()
        self.udp_ready = True
        log(f"UDP relay listening on port {self.udp_port}")
        while True:
            try:
                data, addr = s.recvfrom(2048)
            except OSError:
                continue
            try:
                self.on_udp(s, data, addr)
            except Exception:
                log("UDP error:\n" + traceback.format_exc())

    def on_udp(self, s, data, addr):
        if data.startswith(b"V42BIND") and len(data) >= 7 + 16:
            token = data[7:23]
            uid = self.db.one("SELECT id FROM users WHERE token=?", (token.hex(),))
            if not uid:
                s.sendto(b"V42BAD", addr)
                return
            uid = uid["id"]
            with self.lock:
                self.udp_drop(uid)
                self.udp_users[uid] = {"ep": addr, "last": time.time()}
                self.ep_users[addr] = uid
            s.sendto(b"V42OK", addr)
            return
        if data == b"V42PING":
            # a lone player keeps the room dormant but still proves it is alive
            with self.lock:
                uid = self.ep_users.get(addr)
                u = self.udp_users.get(uid) if uid is not None else None
                if u:
                    u["last"] = time.time()
            s.sendto(b"V42PONG", addr)
            return
        uid = self.ep_users.get(addr)
        if uid is None or len(data) < 10 or not data.startswith(b"V42D"):
            return
        with self.lock:
            u = self.udp_users.get(uid)
            if not u:
                return
            u["last"] = time.time()
            rid = struct.unpack("!I", data[4:8])[0]
            mode = data[8]
            c = self.conns.get(uid)
            if not c or c.active_room != rid:
                return
            online = self.online_uids(rid)
            if len(online) < 2:      # dormant: nobody to relay to
                return
            if mode == 1 and len(data) >= 13:   # targeted: next 4 bytes = target user id
                target = struct.unpack("!I", data[9:13])[0]
                tu = self.udp_users.get(target)
                if tu and target != uid and target in online:
                    try:
                        s.sendto(data[13:], tu["ep"])
                    except OSError:
                        pass
                return
            payload = data[9:]
            for mid, mu in list(self.udp_users.items()):
                if mid == uid:
                    continue
                mc = self.conns.get(mid)
                if mc and mc.active_room == rid:
                    try:
                        s.sendto(payload, mu["ep"])
                    except OSError:
                        pass

    def timeout_loop(self):
        while True:
            time.sleep(min(5.0, self.udp_timeout / 2.0))
            now = time.time()
            expired = []
            with self.lock:
                for uid, u in list(self.udp_users.items()):
                    if now - u["last"] > self.udp_timeout:
                        c = self.conns.get(uid)
                        expired.append((uid, c.active_room if c else None))
                        self.udp_drop(uid)
            for uid, rid in expired:          # pushes stay out of the relay lock
                usr = self.user_by_id(uid)
                name = usr["username"] if usr else "?"
                if not rid:
                    # not standing in a room (e.g. sitting on the main page) - just forget the socket
                    log(f"UDP binding expired for {name}")
                    continue
                reason = f"timeout: no data for {self.udp_timeout}s"
                log(f"member offline: {name} ({reason})")
                self.push_room(rid, {"t": "member_offline", "room": rid, "user": uid,
                                     "name": name, "reason": reason}, skip=uid)
                self.push_state(rid)

    # ---------------- TCP accept
    def other_instance(self):
        """A second server on the same machine steals connections and leaves UDP dead."""
        try:
            s = socket.create_connection(("127.0.0.1", self.tcp_port), timeout=2)
        except OSError:
            return False
        try:
            s.settimeout(2)
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            buf = b""
        finally:
            s.close()
        return b'"hello"' in buf

    def run(self):
        if self.other_instance():
            log(f"A V.Lan.42 server is already running on port {self.tcp_port}.")
            log("Close that window first - two servers on one VPS break the UDP relay.")
            sys.exit(1)
        threading.Thread(target=self.udp_loop, daemon=True).start()
        threading.Thread(target=self.timeout_loop, daemon=True).start()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.tcp_port))
        srv.listen(64)
        log(f"V.Lan.42 server ready - TCP {self.tcp_port} / UDP {self.udp_port}")
        log(f"coded by Hossein & Erfan - https://github.com/mhbanaei")
        time.sleep(2)            # let the UDP thread report the truth
        if self.udp_ready:
            log(f"Players can join now. Still need inbound {self.tcp_port} TCP *and* UDP")
            log(f"   in the firewall of your hosting panel, not only inside Windows.")
        while True:
            try:
                sock, addr = srv.accept()
            except OSError:
                continue
            threading.Thread(target=Conn(self, sock, addr).run, daemon=True).start()


class Conn:
    BUFSZ = 1 << 16

    def __init__(self, srv, sock, addr):
        self.srv, self.sock, self.addr = srv, sock, addr
        self.aead = None
        self.user = None
        self.active_room = None
        self.alive = True
        self.send_lock = threading.Lock()

    # ---- crypto handshake
    def handshake(self):
        self.sock.settimeout(15)
        eph = X25519PrivateKey.generate()
        pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        nonce = secrets.token_bytes(16)
        self.send_plain({"t": "hello", "pub": pub.hex(), "nonce": nonce.hex()})
        m = self.recv_plain()
        if not m or m.get("t") != "auth1":
            return False
        try:
            shared = eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(m["pub"])))
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce, info=b"vlan42-ctl").derive(shared)
            self.aead = AESGCM(key)
        except Exception as ex:
            log(f"handshake failed {self.addr}: {ex}")
            return False
        return True

    # ---- line transport
    def send_plain(self, obj):
        self.sock.sendall(json.dumps(obj, separators=(",", ":")).encode() + b"\n")

    def recv_plain(self):
        buf = b""
        while b"\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            buf += chunk
            if len(buf) > self.BUFSZ:
                return None
        line, _, rest = buf.partition(b"\n")
        self._rest = rest
        return json.loads(line.decode())

    def recv_line(self):
        buf = getattr(self, "_rest", b"")
        self._rest = b""
        while b"\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            buf += chunk
            if len(buf) > self.BUFSZ:
                return None
        line, _, rest = buf.partition(b"\n")
        self._rest = rest
        return line

    def send(self, obj):
        raw = json.dumps(obj, separators=(",", ":")).encode()
        n = secrets.token_bytes(12)
        with self.send_lock:
            self.sock.sendall(base64.b64encode(n + self.aead.encrypt(n, raw, b"vlan42-ctl")) + b"\n")

    def push(self, p):
        self.send({"t": "push", "p": p})

    def recv(self):
        line = self.recv_line()
        if not line:
            return None
        d = base64.b64decode(line.strip())
        return json.loads(self.aead.decrypt(d[:12], d[12:], b"vlan42-ctl"))

    # ---- lifecycle
    def login(self, user):
        old = self.srv.conns.get(user["id"])
        self.srv.conns[user["id"]] = self
        self.user = user
        if old is not None and old is not self:
            old.supersede()     # one live session per account
        # notify friends that we are online
        for f in self.srv.friends_json(user["id"])["friends"]:
            self.srv.push_user(f["id"], {"t": "friend_upd", **self.srv.friends_json(f["id"])})

    def supersede(self):
        try:
            self.push({"t": "signed_elsewhere", "err": "This account signed in somewhere else"})
        except Exception:
            pass
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)   # wakes the recv loop of the old session
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def logout(self):
        if not self.user:
            return
        uid = self.user["id"]
        rid = self.active_room
        self.active_room = None
        if self.srv.conns.get(uid) is not self:
            return            # an older session already replaced by a new sign-in
        del self.srv.conns[uid]
        self.srv.udp_drop(uid)
        for f in self.srv.friends_json(uid)["friends"]:
            self.srv.push_user(f["id"], {"t": "friend_upd", **self.srv.friends_json(f["id"])})
        if rid:
            self.srv.push_state(rid)

    def run(self):
        try:
            if not self.handshake():
                return
            self.sock.settimeout(None)
            while self.alive:
                m = self.recv()
                if m is None:
                    break
                if not isinstance(m, dict):
                    continue
                t = m.get("t")
                s = self.srv
                if t == "logout":
                    self.logout()
                    self.alive = False
                    break
                if t in ("register", "login", "login_token"):
                    if t == "register":
                        r = s.do_register(self, m)
                    elif t == "login":
                        r = s.do_login(self, m)
                    else:
                        r = s.do_login_token(self, m)
                    if r.get("ok"):
                        log(f"{t}: {self.user['username']} from {self.addr[0]}")
                    self.send(r)
                    continue
                if not self.user:
                    self.send({"t": t, "ok": False, "err": "Not logged in"})
                    continue
                if self.srv.conns.get(self.user["id"]) is not self:
                    self.alive = False        # a newer sign-in took this session over
                    break
                handlers = {
                    "ping": lambda: {"t": "ping", "ok": True, "ts": time.time()},
                    "my_rooms": lambda: {"t": "my_rooms", "ok": True,
                                         "rooms": [s.room_json(r["room_id"], self.user["id"])
                                                   for r in s.db.q("SELECT room_id FROM members WHERE user_id=?",
                                                                   (self.user["id"],))
                                                   if s.room_json(r["room_id"], self.user["id"])]},
                    "create_room": lambda: s.do_create_room(self, m),
                    "join_room": lambda: s.do_join_room(self, m),
                    "remove_room": lambda: s.do_remove_room(self, m),
                    "activate": lambda: self._do_activate(m),
                    "deactivate": lambda: self._do_deactivate(m),
                    "chat": lambda: self._do_chat(m),
                    "kick": lambda: s.do_kick(self, m),
                    "ban": lambda: s.do_ban(self, m),
                    "unban": lambda: s.do_unban(self, m),
                    "ban_list": lambda: s.do_ban_list(self, m),
                    "set_admin": lambda: s.do_set_admin(self, m),
                    "set_limit": lambda: s.do_set_limit(self, m),
                    "search": lambda: s.do_search(self, m),
                    "friends": lambda: {"t": "friends", "ok": True, **s.friends_json(self.user["id"])},
                    "add_friend": lambda: s.do_add_friend(self, m),
                    "friend_resp": lambda: s.do_friend_resp(self, m),
                    "remove_friend": lambda: s.do_remove_friend(self, m),
                    "pm": lambda: s.do_pm(self, m),
                    "invite": lambda: s.do_invite(self, m),
                }
                h = handlers.get(t)
                try:
                    r = h() if h else {"t": t, "ok": False, "err": "Unknown command"}
                except Exception:
                    log(f"handler {t} error:\n{traceback.format_exc()}")
                    r = {"t": t, "ok": False, "err": "Server error (see server log)"}
                try:
                    self.send(r)
                except OSError:
                    break
        except Exception:
            log(f"conn {self.addr} error:\n{traceback.format_exc()}")
        finally:
            self.logout()
            try:
                self.sock.close()
            except OSError:
                pass

    def _do_activate(self, m=None):
        rid = int((m or {}).get("room") or 0)
        if not self.srv.member_row(rid, self.user["id"]):
            return {"t": "activate", "ok": False, "err": "You are not a member of that room"}
        self.active_room = rid
        self.srv.push_state(rid)
        return {"t": "activate", "ok": True}

    def _do_deactivate(self, m=None):
        rid, self.active_room = self.active_room, None
        if rid:
            self.srv.push_state(rid)
        return {"t": "deactivate", "ok": True}

    def _do_chat(self, m):
        text = (m.get("text") or "").strip()[:500]
        rid = self.active_room
        if not rid or not text:
            return {"t": "chat", "ok": False, "err": "Not in a room"}
        self.srv.push_room(rid, {"t": "chat", "room": rid, "from": self.user["username"],
                                 "text": text, "ts": time.time()})
        return {"t": "chat", "ok": True}


def main():
    cfg = load_cfg()
    if not os.path.exists(CFG_FILE):
        with open(CFG_FILE, "w", encoding="utf-8") as f:
            json.dump({"tcp_port": DEFAULT_TCP_PORT, "udp_port": DEFAULT_UDP_PORT}, f, indent=2)
    Server(cfg).run()


if __name__ == "__main__":
    main()
