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
import os, sys, json, time, socket, sqlite3, secrets, hashlib, base64, struct, re
import threading, traceback

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CFG_FILE = os.path.join(APP_DIR, "vlan42_server.json")
DATA_DIR = os.path.join(APP_DIR, "vlan42_data")
DB_FILE = os.path.join(DATA_DIR, "db.sqlite")

MAX_ROOMS_PER_USER = 3
MAX_ACCOUNTS_PER_MACHINE = 3   # one box hosts three players, no more
DEFAULT_LIMIT = 16
UDP_TIMEOUT = 30          # seconds without UDP traffic -> member marked offline (timeout)
DEFAULT_TCP_PORT = 4242
DEFAULT_UDP_PORT = 4242
PERMS = ("kick", "ban", "unban", "limit", "approve", "invite")

# ---------------------------------------------------------- management console
# The team's own door. Its key is made on the first run and lives in one file next to
# the database; nothing of it ships to a player, so reading vplan42.py - or the whole
# of this file - gives nobody the right to name an admin. The console proves itself
# with a stamp that only the same key can make, and the stamp is worth one minute.
STAFF_FILE = os.path.join(APP_DIR, "vlan42_staff.key")
STAFF_AAD = b"vlan42-staff"
STAFF_WINDOW = 60
STAFF_MIN_PW = 8

# What each role may do in a room before the owner ticks anything. A member is a guest
# with a virtual cable: no moderating and no inviting. An admin may bring friends in and
# may remove and block people, but sets no limits, approves nobody and manages nobody.
ROLE_DEFAULTS = {"member": {k: False for k in PERMS},
                 "admin": {k: (k in ("kick", "ban", "unban", "invite")) for k in PERMS}}
JOIN_TRY_LIMIT = 6            # wrong invites/passwords per account before a cooloff
JOIN_COOLDOWN = 120           # seconds
JOIN_WINDOW = 600             # the tries that count are the last ten minutes
INVITE_PFX = "vlan42://join/"    # only for the OS deep link; the code itself is not a link
INVITE_AAD = b"vlan42-invite"     # a sealed code is valid as an invite and as nothing else
PUBLIC_HOST = "v42.ir"          # the address players dial; point its A record at this VPS

def log(msg):
    """The console is the only place a server writes: start_server.bat keeps the window open
    (and can redirect it wherever the team likes). Nothing is left behind as a log file."""
    print(time.strftime("%Y-%m-%d %H:%M:%S ") + str(msg), flush=True)


def staff_key():
    """The one secret that says who may run the management commands."""
    try:
        raw = open(STAFF_FILE, encoding="utf-8").read().strip()
    except OSError:
        raw = ""
    if re.fullmatch(r"[0-9a-f]{64}", raw):
        return bytes.fromhex(raw)
    key = secrets.token_bytes(32)
    try:
        with open(STAFF_FILE, "w", encoding="utf-8") as f:
            f.write(key.hex())
        try:
            os.chmod(STAFF_FILE, 0o600)
        except OSError:
            pass
    except OSError:
        log("staff key: the file is unwritable, so the management console cannot sign in")
    return key


def staff_stamp(ahead=None):
    """A stamp naming the window it was made in - what the console hands over as its
    credentials. It stays good through the window after that, so a slow trip is fine,
    and then it is worthless: a copy of it is no use tomorrow."""
    win = (time.time() + (ahead or 0)) // STAFF_WINDOW
    win = int(win)
    nonce = struct.pack(">QI", win, 0)
    return base64.urlsafe_b64encode(nonce + AESGCM(staff_key()).encrypt(
        nonce, str(win).encode(), STAFF_AAD)).decode().rstrip("=")


def staff_ok(stamp):
    """Does this stamp come from a process that holds the key? Only the window it names,
    or the one before it, is accepted - a captured stamp stops being useful in a minute."""
    try:
        raw = base64.urlsafe_b64decode((stamp or "") + "=" * (-len(stamp or "") % 4))
        win = int(AESGCM(staff_key()).decrypt(raw[:12], raw[12:], STAFF_AAD))
    except Exception:
        return False
    now = int(time.time() // STAFF_WINDOW)
    return win in (now, now - 1)


def staff_users(cfg=None):
    """The names the team vouched for. They are the only accounts that can read the
    management panel, and they live in the server's own config."""
    cfg = cfg if cfg is not None else load_cfg()
    return {str(x).lower() for x in (cfg.get("staff") or [])}


def load_cfg():
    try:
        with open(CFG_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


# --------------------------------------------------------------- invite codes
# An invite is a sealed note, not a link. The server keeps one random key that never
# leaves the VPS; a code is the room code plus a fingerprint of its password, sealed with
# AES-GCM under that key. Nobody outside the server can read one, and nobody can make a
# code up: guessing the 128-bit tag is the only way in, and the cooloff says no long
# before that becomes a plan. Re-rolling a password retires every code handed out before.

def invite_key(cfg):
    """The one key that mints codes: made on the first run, kept in the config after."""
    raw = str(cfg.get("invite_key") or "")
    if raw:
        try:
            k = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            if len(k) == 32:
                return k
        except Exception:
            pass
    k = secrets.token_bytes(32)
    cfg["invite_key"] = base64.urlsafe_b64encode(k).decode().rstrip("=")
    try:
        saved = load_cfg()                     # keep whatever the team already typed in
        saved["invite_key"] = cfg["invite_key"]
        with open(CFG_FILE, "w", encoding="utf-8") as f:
            json.dump(saved, f, indent=2)
    except OSError:
        log("invite key: the config is unwritable, so codes die with this run")
    return k


def pwd_fp(pwd):
    return hashlib.sha256(str(pwd).encode()).digest()[:6]


def unseal_text(text):
    """A code as it was pasted - with dots, spaces, or a leftover deep link - to bare base64.
    Only characters that can never be part of a code are dropped: "-" belongs to the alphabet."""
    s = str(text or "").strip()
    if INVITE_PFX in s:
        s = s.split(INVITE_PFX, 1)[1]
    return "".join(ch for ch in s if ch not in " \t\r\n.:|,")


def make_invite(r, key):
    raw = r["code"].encode() + b"|" + pwd_fp(r["pwd"])
    nonce = secrets.token_bytes(12)
    sealed = base64.urlsafe_b64encode(nonce + AESGCM(key).encrypt(nonce, raw, INVITE_AAD))
    token = sealed.decode().rstrip("=")
    return ".".join(token[i:i + 4] for i in range(0, len(token), 4))


def open_invite(text, key):
    """(room code, password fingerprint) out of a pasted code, or None if it is not ours."""
    raw = unseal_text(text)
    if not (48 <= len(raw) <= 200) or not re.fullmatch(r"[A-Za-z0-9_-]+", raw):
        return None
    try:
        blob = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        code, fp = AESGCM(key).decrypt(blob[:12], blob[12:], INVITE_AAD).split(b"|", 1)
        return code.decode(), fp
    except Exception:
        return None


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
                salt TEXT, pwhash TEXT, token TEXT, created REAL, last REAL);
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
            -- the room's own defaults for what a member and an admin may do
            CREATE TABLE IF NOT EXISTS room_perms(
                room_id INTEGER PRIMARY KEY, defaults TEXT DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS jreq(
                room_id INTEGER, user_id INTEGER, ts REAL,
                PRIMARY KEY(room_id, user_id));
            CREATE TABLE IF NOT EXISTS traffic(
                user_id INTEGER, day TEXT, bytes INTEGER,
                PRIMARY KEY(user_id, day));
            """)
            # which box made the account - on a fresh database and on one that predates
            # the rule alike, the column is added before anything reads the table
            for column in ("machine TEXT", "last REAL"):
                try:
                    self.cx.execute(f"ALTER TABLE users ADD COLUMN {column}")
                except sqlite3.OperationalError:
                    pass                  # a database that already grew it
            self.cx.execute("CREATE INDEX IF NOT EXISTS users_machine ON users(machine)")
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
        self.join_fails = []       # [(user_id, when)] - the anti-guessing counter
        self.tally = {}            # user_id -> bytes relayed since the last flush
        self.cfg = cfg               # the server's own file: the staff list lives here
        self.invkey = invite_key(cfg)
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

    def machine_accounts(self, machine):
        """How many accounts this PC already carries. A box whose hash could not be read
        is not counted at all - see do_register - so this only ever answers for a real
        machine, and three is the most any of them may hold."""
        return len(self.db.q("SELECT id FROM users WHERE machine=?", (machine,)))

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
        # a box that cannot be read at all (a stripped WMI, another OS) is not punished for
        # it: it registers uncounted, and the log says so the team can see the stragglers
        machine = re.fullmatch(r"[0-9a-f]{16,128}", (m.get("hw") or "").strip().lower())
        machine = machine.group(0) if machine else ""
        if not machine:
            log(f"register '{u}': this PC gave no hardware hash, so it is not counted")
        if machine and self.machine_accounts(machine) >= MAX_ACCOUNTS_PER_MACHINE:
            return {"t": "register", "ok": False,
                    "err": f"This PC already has {MAX_ACCOUNTS_PER_MACHINE} accounts - "
                           f"sign in to one of them instead"}
        salt = secrets.token_hex(16)
        token = secrets.token_hex(16)
        self.db.run("INSERT INTO users(username,salt,pwhash,token,created,machine) "
                    "VALUES(?,?,?,?,?,?)",
                    (u, salt, pw_hash(p, salt), token, time.time(), machine))
        c.login(self.user_by_name(u))
        return {"t": "register", "ok": True, "token": token, "user": {"id": c.user["id"], "name": u},
                "staff": u.lower() in staff_users(self.cfg)}

    def do_login(self, c, m):
        u = self.user_by_name((m.get("u") or "").strip())
        if not u or pw_hash(m.get("p") or "", u["salt"]) != u["pwhash"]:
            return {"t": "login", "ok": False, "err": "Wrong username or password"}
        if not self.note_machine(u, m):
            return {"t": "login", "ok": False,
                    "err": f"This PC already has {MAX_ACCOUNTS_PER_MACHINE} accounts - "
                           f"sign in to one of them instead"}
        token = secrets.token_hex(16)
        self.db.run("UPDATE users SET token=?, last=? WHERE id=?", (token, time.time(), u["id"]))
        c.login(self.user_by_name(u["username"]))
        return {"t": "login", "ok": True, "token": token, "user": {"id": u["id"], "name": u["username"]},
                "staff": u["username"].lower() in staff_users(self.cfg)}

    def note_machine(self, u, m):
        """An account made before this rule still gets a home: the first PC it signs in
        from is the one it belongs to, and it counts against that PC's three places."""
        try:
            if u["machine"]:
                return True                      # it already has a home
        except (KeyError, IndexError):
            return True                          # an old row: leave it out of the count
        hw = re.fullmatch(r"[0-9a-f]{16,128}", (m.get("hw") or "").strip().lower())
        if not hw:
            return True                          # nothing to attribute; let them in
        if self.machine_accounts(hw.group(0)) >= MAX_ACCOUNTS_PER_MACHINE:
            return False
        self.db.run("UPDATE users SET machine=? WHERE id=?", (hw.group(0), u["id"]))
        return True

    def do_change_password(self, c, m):
        """Change the password of the account that is signed in - from the Settings page.
        The old one is asked for, so a seat left unlocked is not a way in, and every other
        session of the account is dropped: the new password is the only one that opens it."""
        uid = c.user["id"]
        u = self.user_by_id(uid)
        oldp, newp = m.get("old") or "", m.get("new") or ""
        if not u or pw_hash(oldp, u["salt"]) != u["pwhash"]:
            return {"t": "change_password", "ok": False, "err": "Current password is wrong"}
        if len(newp) < 6:
            return {"t": "change_password", "ok": False, "err": "New password must be at least 6 characters"}
        if newp == oldp:
            return {"t": "change_password", "ok": False, "err": "The new password is the same as the old one"}
        salt = secrets.token_hex(16)
        token = secrets.token_hex(16)
        self.db.run("UPDATE users SET salt=?, pwhash=?, token=? WHERE id=?",
                    (salt, pw_hash(newp, salt), token, uid))
        with self.lock:                          # every OTHER session of the account goes
            others = [x for x in list(self.conns.values())
                      if x is not c and x.user and x.user["id"] == uid]
        for other in others:                     # ...and this one stays to hear the answer
            other.supersede()
        log(f"password changed: {u['username']}")
        return {"t": "change_password", "ok": True, "token": token}

    def do_login_token(self, c, m):
        tok = m.get("token") or ""
        u = self.db.one("SELECT * FROM users WHERE token=?", (tok,))
        if not u:
            return {"t": "login_token", "ok": False, "err": "Session expired - please log in again"}
        c.login(u)
        return {"t": "login_token", "ok": True, "token": tok,
                "user": {"id": u["id"], "name": u["username"]},
                "staff": u["username"].lower() in staff_users(self.cfg)}

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
                            "perms": self.eff_perms(rid, mrow["role"], mrow["perms"]),
                            "vip": mrow["vip"], "online": u["id"] in online})
        return {"id": r["id"], "code": r["code"], "name": r["name"], "pwd": r["pwd"],
                "key": r["roomkey"], "limit": r["member_limit"], "members": members,
                "invite": make_invite(r, self.invkey),
                "my_role": me["role"] if me else None,
                "my_perms": self.eff_perms(rid, me["role"], me["perms"]) if me else {},
                # only the people who can answer see that a queue exists
                "pending": len(self.pending(rid)) if self.can(uid, rid, "approve") else 0}

    def make_invite(self, r):
        return make_invite(r, self.invkey)

    def room_defaults(self, rid):
        """What a member and an admin may do in this room until the owner says otherwise.
        Stored per room, so one room never borrows another room's rules."""
        row = self.db.one("SELECT defaults FROM room_perms WHERE room_id=?", (rid,))
        saved = json.loads(row["defaults"]) if row and row["defaults"] else {}
        out = {role: dict(d) for role, d in ROLE_DEFAULTS.items()}
        for role, d in (saved.get("defaults") or {}).items():
            if role in out:
                out[role] = {k: bool(d.get(k)) for k in PERMS}
        return out

    def eff_perms(self, rid, role, explicit):
        """The ticks that actually apply to a person: what the owner set for them, over
        what the room says for their role. A tick taken off is as loud as one put on."""
        own = json.loads(explicit or "{}") if isinstance(explicit, str) else (explicit or {})
        base = self.room_defaults(rid).get(role, {})
        return {k: bool(own[k]) if k in own else bool(base.get(k)) for k in PERMS}

    def can(self, uid, rid, perm):
        me = self.member_row(rid, uid)
        if not me:
            return False
        if me["role"] == "owner":
            return True
        return bool(self.eff_perms(rid, me["role"], me["perms"]).get(perm))

    def cooloff(self, uid, now):
        """Seconds an account must wait before it may try another invite code.
        Six misses in ten minutes is a human typo; more is a script."""
        with self.lock:
            self.join_fails = [(u, t) for (u, t) in self.join_fails if now - t < JOIN_WINDOW]
            hits = sorted(t for (u, t) in self.join_fails if u == uid)
            if len(hits) < JOIN_TRY_LIMIT:
                return 0
            return max(1, int(hits[0] + JOIN_COOLDOWN - now) + 1)

    def mark_fail(self, uid, now):
        with self.lock:
            self.join_fails.append((uid, now))

    def clear_fails(self, uid):
        with self.lock:
            self.join_fails = [(u, t) for (u, t) in self.join_fails if u != uid]

    def pending(self, rid):
        rows = self.db.q("SELECT user_id, ts FROM jreq WHERE room_id=? ORDER BY ts", (rid,))
        out = []
        for x in rows:
            u = self.user_by_id(x["user_id"])
            if u:
                out.append({"id": x["user_id"], "name": u["username"], "ts": x["ts"]})
        return out

    def gatekeepers(self, rid):
        """Who may answer a join request: the host, plus admins given the approve power."""
        out = []
        for mrow in self.room_members(rid):
            if mrow["role"] == "owner":
                out.append(mrow["user_id"])
            elif mrow["role"] == "admin" and json.loads(mrow["perms"] or "{}").get("approve"):
                out.append(mrow["user_id"])
        return out

    def push_gatekeepers(self, rid, payload):
        for uid in self.gatekeepers(rid):
            tc = self.conns.get(uid)
            if tc:
                try:
                    tc.push(payload)
                except Exception:
                    pass

    def do_create_room(self, c, m):
        uid = c.user["id"]
        name = (m.get("name") or "").strip()[:32] or "room"
        pwd = (m.get("pwd") or "").strip()
        if not (3 <= len(name)) or len(pwd) < 6:
            return {"t": "create_room", "ok": False,
                    "err": "Room name min 3 chars, room password min 6 chars (use the dice)"}
        if self.membership_count(uid) >= MAX_ROOMS_PER_USER:
            return {"t": "create_room", "ok": False,
                    "err": f"You are in {MAX_ROOMS_PER_USER} rooms already - remove one from your list first"}
        code = secrets.token_hex(4)
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
        now = time.time()
        wait = self.cooloff(uid, now)
        if wait:
            return {"t": "join_room", "ok": False,
                    "err": f"Too many wrong invites - wait {wait}s and try again"}
        # a sealed code is the normal way in; typing code + password by hand still works,
        # and both paths end in the same fingerprint check so neither leaks which rooms exist
        got = open_invite(m["inv"], self.invkey) if m.get("inv") else None
        if got is None and (m.get("code") or "").strip():
            got = (str(m["code"]).strip(), pwd_fp(m.get("pwd") or ""))
        r = self.room_by_code(got[0]) if got else None
        if not r or pwd_fp(r["pwd"]) != got[1]:
            # one answer for both cases: nothing here tells a script which codes exist
            self.mark_fail(uid, now)
            return {"t": "join_room", "ok": False, "err": "Wrong invite code or room password"}
        self.clear_fails(uid)
        if self.is_banned(r["id"], uid):
            return {"t": "join_room", "ok": False, "err": "You are banned from this room"}
        if self.member_row(r["id"], uid):
            self.db.run("DELETE FROM jreq WHERE room_id=? AND user_id=?", (r["id"], uid))
            return {"t": "join_room", "ok": True, "room": self.room_json(r["id"], uid),
                    "invite": self.make_invite(r)}
        if self.membership_count(uid) >= MAX_ROOMS_PER_USER:
            return {"t": "join_room", "ok": False,
                    "err": f"You are in {MAX_ROOMS_PER_USER} rooms already - remove one from your list first"}
        if len(self.room_members(r["id"])) >= r["member_limit"]:
            return {"t": "join_room", "ok": False, "err": "This room is full"}
        # the password only opens the door: a new face waits for the host's yes
        self.db.run("INSERT OR REPLACE INTO jreq(room_id,user_id,ts) VALUES(?,?,?)", (r["id"], uid, now))
        self.push_gatekeepers(r["id"], {"t": "jreq", "room": r["id"], "name": r["name"],
                                        "user": uid, "from": c.user["username"], "ts": now,
                                        "count": len(self.pending(r["id"]))})
        return {"t": "join_room", "ok": True, "pending": True, "room": r["id"],
                "room_name": r["name"], "invite": self.make_invite(r),
                "msg": "The host must approve you before you can enter"}

    def do_join_list(self, c, m):
        rid = int(m.get("room") or 0)
        if not self.can(c.user["id"], rid, "approve"):
            return {"t": "join_list", "ok": False, "err": "Only the host can review join requests"}
        return {"t": "join_list", "ok": True, "room": rid, "requests": self.pending(rid)}

    def do_join_resp(self, c, m):
        rid, target = int(m.get("room") or 0), int(m.get("user") or 0)
        if not self.can(c.user["id"], rid, "approve"):
            return {"t": "join_resp", "ok": False, "err": "Only the host can review join requests"}
        r = self.room_by_id(rid)
        if not r:
            return {"t": "join_resp", "ok": False, "err": "No such room"}
        self.db.run("DELETE FROM jreq WHERE room_id=? AND user_id=?", (rid, target))
        accepted = bool(m.get("accept"))
        if accepted and not self.member_row(rid, target):
            if len(self.room_members(rid)) < r["member_limit"]:
                taken = {row["vip"] for row in self.room_members(rid)}
                self.db.run("INSERT INTO members(room_id,user_id,role,perms,vip,joined) "
                            "VALUES(?,?,?,?,?,?)", (rid, target, "member", "{}", make_vip(taken), time.time()))
                self.push_state(rid)
            else:
                accepted = False
        self.push_user(target, {"t": "join_ok" if accepted else "join_no", "room": rid,
                                "name": r["name"], "by": c.user["username"]})
        self.push_gatekeepers(rid, {"t": "jreq_upd", "room": rid, "count": len(self.pending(rid))})
        return {"t": "join_resp", "ok": True, "room": rid, "requests": self.pending(rid)}

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
                self.db.run("DELETE FROM jreq WHERE room_id=?", (rid,))
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
        self.db.run("DELETE FROM jreq WHERE room_id=? AND user_id=?", (rid, target))
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
            # a fresh admin carries no tick of his own: he follows this room's defaults,
            # and the owner can still put a tick on him afterwards
            self.db.run("UPDATE members SET role='admin', perms=? WHERE room_id=? AND user_id=?",
                        ("{}", rid, target))
        else:
            self.db.run("UPDATE members SET role='member', perms='{}' WHERE room_id=? AND user_id=?",
                        (rid, target))
        self.push_state(rid)
        return {"t": "set_admin", "ok": True}

    def do_set_perms(self, c, m):
        """The owner ticks what one person may do in this room. It works for a member as
        well as an admin, and it is remembered for this room only - the same face in
        another room starts from that room's own defaults again."""
        uid, rid, target = c.user["id"], int(m.get("room") or 0), int(m.get("user") or 0)
        me = self.member_row(rid, uid)
        if not me or me["role"] != "owner":
            return {"t": "set_perms", "ok": False, "err": "Only the owner can set permissions"}
        t = self.member_row(rid, target)
        if not t or t["role"] == "owner":
            return {"t": "set_perms", "ok": False, "err": "Invalid target"}
        # only what differs from the room's own default is remembered for this person,
        # so changing the default still reaches everyone who was never ticked
        base = self.room_defaults(rid).get(t["role"], {})
        given = m.get("perms") or {}
        keep = {k: bool(given.get(k)) for k in PERMS if bool(given.get(k)) != bool(base.get(k))}
        self.db.run("UPDATE members SET perms=? WHERE room_id=? AND user_id=?",
                    (json.dumps(keep), rid, target))
        self.push_state(rid)
        return {"t": "set_perms", "ok": True}

    # ------------------------------------------------------------ management console
    def admin_rows(self, what):
        """Everything the team is allowed to know about the players of this network.
        It leaves the VPS only over the encrypted channel, and only to a process that
        can make a stamp from the staff key."""
        out = []
        if what == "users":
            for u in self.db.q("SELECT * FROM users ORDER BY username"):
                mine = self.db.q("SELECT room_id FROM members WHERE user_id=?", (u["id"],))
                used = sum(int(t["bytes"] or 0) for t in
                           self.db.q("SELECT bytes FROM traffic WHERE user_id=?", (u["id"],)))
                today = self.db.one("SELECT bytes FROM traffic WHERE user_id=? AND day=?",
                                    (u["id"], time.strftime("%Y-%m-%d")))
                out.append({"id": u["id"], "name": u["username"],
                            "created": u["created"], "last": u["last"] or u["created"],
                            "machine": (u["machine"] or "")[:12],
                            "staff": u["username"].lower() in staff_users(self.cfg),
                            "online": u["id"] in self.conns,
                            "rooms": len(mine), "room_ids": sorted(r["room_id"] for r in mine),
                            "bytes": used, "today": int(today["bytes"]) if today else 0})
        elif what == "rooms":
            for r in self.db.q("SELECT * FROM rooms ORDER BY id"):
                mem = self.db.q("SELECT user_id, role FROM members WHERE room_id=?", (r["id"],))
                owner = next((self.user_by_id(m["user_id"]) for m in mem if m["role"] == "owner"), None)
                out.append({"id": r["id"], "name": r["name"], "limit": r["member_limit"],
                            "created": r["created"],
                            "owner": owner["username"] if owner else "?",
                            "members": len(mem),
                            "online": sum(1 for m in mem if m["user_id"] in self.conns)})
        elif what == "traffic":
            for t in self.db.q("SELECT user_id, day, bytes FROM traffic ORDER BY day DESC, bytes DESC"):
                u = self.user_by_id(t["user_id"])
                out.append({"id": t["user_id"], "name": u["username"] if u else "?",
                            "day": t["day"], "bytes": int(t["bytes"] or 0)})
        return out

    def admin_text(self, what):
        """The same facts, as lines for the console window."""
        rows = self.admin_rows(what)
        if what == "users":
            head = f"{'name':<18}{'id':>5}{'made':>12}{'last seen':>12}{'machine':>14}"                    f"{'rooms':>7}{'online':>8}{'data':>10}  staff"
            lines = [head, "-" * len(head)]
            for r in rows:
                lines.append(f"{r['name']:<18}{r['id']:>5}{stamp_day(r['created']):>12}"
                             f"{stamp_day(r['last']):>12}{r['machine']:>14}{r['rooms']:>7}"
                             f"{('yes' if r['online'] else '-'):>8}{human_bytes(r['bytes']):>10}"
                             f"  {'ADMIN' if r['staff'] else ''}")
            return "\n".join(lines)
        if what == "rooms":
            head = f"{'id':>4} {'name':<22}{'owner':<16}{'members':>9}{'online':>8}{'limit':>7}  made"
            lines = [head, "-" * len(head)]
            for r in rows:
                lines.append(f"{r['id']:>4} {r['name']:<22}{r['owner']:<16}{r['members']:>9}"
                             f"{r['online']:>8}{r['limit']:>7}  {stamp_day(r['created'])}")
            return "\n".join(lines)
        head = f"{'user':<18}{'day':<12}{'bytes':>10}"
        lines = [head, "-" * len(head)]
        for r in rows:
            lines.append(f"{r['name']:<18}{r['day']:<12}{human_bytes(r['bytes']):>10}")
        return "\n".join(lines)

    def admin_staff(self, name, on):
        """Vouch for a name, or stop vouching for it. The list lives in the server's own
        config file, so no client and no copy of the source can add to it."""
        cfg = load_cfg()
        got = {str(x).lower() for x in (cfg.get("staff") or [])}
        was = name.lower() in got
        if on:
            got.add(name.lower())
        else:
            got.discard(name.lower())
        cfg["staff"] = sorted(got)
        save_cfg(cfg)
        self.cfg = cfg
        u = self.user_by_name(name)
        if u:                              # a panel already open on their screen answers now,
            c = self.conns.get(u["id"])    # not only after the next sign-in
            if c:
                try:
                    c.push({"t": "staff", "on": bool(on)})
                except Exception:
                    pass
        if on and not was:
            return f"{name} is management now: the app shows the admin panel to that account."
        if was and not on:
            return f"{name} is not management any more."
        return f"{name} was already {'management' if on else 'not management'}."

    def do_admin(self, c, m):
        """Two doors, each with its own key. A console running beside the server proves
        itself with a stamp made from vlan42_staff.key, so a copy of the source code gets
        nowhere. The app proves itself with the account it signed in as - and that name only
        ever gets on the list by somebody typing `set admin` at the server itself. Either
        key opens the same commands; a refusal never says which one was missing."""
        vouched = bool(c.user) and c.user["username"].lower() in staff_users(self.cfg)
        if not vouched and not staff_ok(m.get("stamp")):
            return {"t": "admin", "ok": False, "err": "This is not the management console"}
        return self.admin_cmd(m.get("cmd"))

    def admin_cmd(self, cmd):
        """The commands themselves. The server's own window runs them at once - whoever can
        type at that keyboard owns the machine, and that is the whole credential."""
        words = (cmd or "").split()
        pair = bool(words) and words[0].lower() in ("set", "remove")
        verb = " ".join(words[:2]).lower() if pair else (words[0].lower() if words else "")
        arg = " ".join(words[2:] if pair else words[1:]).strip()
        if verb in ("help", "-h", "?"):
            return {"t": "admin", "ok": True, "out": HELP}
        if verb in ("users", "rooms", "traffic"):
            return {"t": "admin", "ok": True, "rows": self.admin_rows(verb),
                    "out": self.admin_text(verb)}
        if verb == "status":
            n = self.db.q("SELECT COUNT(*) AS n FROM users")[0]["n"]
            r = self.db.q("SELECT COUNT(*) AS n FROM rooms")[0]["n"]
            return {"t": "admin", "ok": True,
                    "out": f"{n} accounts, {r} rooms, {len(self.conns)} signed in now, "
                           f"{len(self.udp_users)} moving game traffic"}
        if verb in ("set admin", "remove admin") and arg:
            u = self.user_by_name(arg)
            if not u:
                return {"t": "admin", "ok": False, "err": f"No user named {arg}"}
            return {"t": "admin", "ok": True, "out": self.admin_staff(arg, verb == "set admin")}
        if verb == "set limit" and arg:
            bits = arg.split()
            if len(bits) != 2 or not (bits[0].isdigit() and bits[1].isdigit()):
                return {"t": "admin", "ok": False, "err": "Use: set limit <room id> <2-64>"}
            rid, lim = int(bits[0]), int(bits[1])
            room = self.db.one("SELECT * FROM rooms WHERE id=?", (rid,))
            if not room:
                return {"t": "admin", "ok": False, "err": f"No room with id {rid}"}
            if not (2 <= lim <= 64):
                return {"t": "admin", "ok": False, "err": "Member limit must be 2-64"}
            if len(self.room_members(rid)) > lim:
                return {"t": "admin", "ok": False, "err": "That room already has more members"}
            self.db.run("UPDATE rooms SET member_limit=? WHERE id=?", (lim, rid))
            self.push_state(rid)
            return {"t": "admin", "ok": True,
                    "out": f"Room {rid} ({room['name']}) now takes {lim} players"}
        return {"t": "admin", "ok": False, "err": "Unknown command"}

    def do_room_state(self, c, m):
        """The room as it stands for the one asking - so a rule that just changed can be
        pulled at once instead of waiting for the next push."""
        rid = int(m.get("room") or 0)
        room = self.room_json(rid, c.user["id"])
        if not room:
            return {"t": "room_state", "ok": False, "err": "You are not in that room"}
        return {"t": "room_state", "ok": True, "room": room}

    def do_get_roles(self, c, m):
        rid = int(m.get("room") or 0)
        if not self.member_row(rid, c.user["id"]):
            return {"t": "get_roles", "ok": False, "err": "You are not in this room"}
        return {"t": "get_roles", "ok": True, "defaults": self.room_defaults(rid)}

    def do_set_roles(self, c, m):
        """The room's own defaults for member and admin. Saving here changes what the
        ticks mean for everyone in this room who has no tick of their own."""
        uid, rid = c.user["id"], int(m.get("room") or 0)
        me = self.member_row(rid, uid)
        if not me or me["role"] != "owner":
            return {"t": "set_roles", "ok": False, "err": "Only the owner can set the room defaults"}
        got = m.get("defaults") or {}
        out = {}
        for role in ("member", "admin"):
            out[role] = {k: bool((got.get(role) or {}).get(k)) for k in PERMS}
        self.db.run("INSERT OR IGNORE INTO room_perms(room_id,defaults) VALUES(?,?)", (rid, "{}"))
        self.db.run("UPDATE room_perms SET defaults=? WHERE room_id=?",
                    (json.dumps({"defaults": out}), rid))
        self.push_state(rid)
        return {"t": "set_roles", "ok": True, "defaults": out}

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
        if not self.can(uid, rid, "invite"):
            return {"t": "invite", "ok": False,
                    "err": "You may not invite people into this room"}
        self.push_user(target["id"], {"t": "invite", "from": c.user["username"], "room": r["name"],
                                      "code": r["code"], "token": self.make_invite(r)})
        return {"t": "invite", "ok": True}

    # ---------------- UDP relay
    def udp_drop(self, uid):
        with self.lock:
            u = self.udp_users.pop(uid, None)
            if u and self.ep_users.get(u["ep"]) == uid:
                del self.ep_users[u["ep"]]

    def flush_tally(self):
        """Write what the relay moved since the last sweep, per player per day. The panel
        reads it back as data use; a player only ever sees their own line."""
        with self.lock:
            tally, self.tally = self.tally, {}
        if not tally:
            return
        day = time.strftime("%Y-%m-%d")
        for uid, n in tally.items():
            self.db.run("INSERT INTO traffic(user_id,day,bytes) VALUES(?,?,?) "
                        "ON CONFLICT(user_id,day) DO UPDATE SET bytes=bytes+excluded.bytes",
                        (uid, day, int(n)))

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
            self.tally[uid] = self.tally.get(uid, 0) + len(data)
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
            self.flush_tally()
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

    def console_loop(self):
        """The team types right here, into the window the server runs in: `set admin erfan`.
        Nothing of this travels over the network and nothing of it is in the players' copy of
        the app - the credential is being the person standing at this keyboard."""
        while True:
            try:
                line = input("")
            except (EOFError, OSError, ValueError):
                log("console: this window has no keyboard to type in - "
                    "use the panel inside the app, or run the command next to the server.")
                return
            line = (line or "").strip()
            if not line:
                continue
            if line.lower() in ("exit", "quit"):
                print("This window is the server. Close it (or press Ctrl+C) to stop it.",
                      flush=True)
                continue
            r = self.admin_cmd(line)
            print((r.get("out") or "Done.") if r.get("ok")
                  else (r.get("err") or "The server refused that."), flush=True)

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
        log(f"Players reach this VPS at {PUBLIC_HOST}:{self.tcp_port} - they never type it themselves,")
        log(f"   the app falls back to the IPs in vlan42_servers.txt if the domain does not answer.")
        log(f"coded by Hossein & Erfan - https://github.com/mhbanaei")
        time.sleep(2)            # let the UDP thread report the truth
        if self.udp_ready:
            log(f"Players can join now. Still need inbound {self.tcp_port} TCP *and* UDP")
            log(f"   in the firewall of your hosting panel, not only inside Windows.")
        log("This window answers the team's commands too - type help to see them.")
        threading.Thread(target=self.console_loop, daemon=True).start()
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
                if t == "admin" and not self.user:
                    # the management console never signs in as a player: the stamp on the
                    # command is its whole identity, so it is answered before the login gate
                    self.send(s.do_admin(self, m))
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
                    "join_list": lambda: s.do_join_list(self, m),
                    "join_resp": lambda: s.do_join_resp(self, m),
                    "remove_room": lambda: s.do_remove_room(self, m),
                    "activate": lambda: self._do_activate(m),
                    "deactivate": lambda: self._do_deactivate(m),
                    "chat": lambda: self._do_chat(m),
                    "typing": lambda: self._do_typing(m),
                    "kick": lambda: s.do_kick(self, m),
                    "ban": lambda: s.do_ban(self, m),
                    "unban": lambda: s.do_unban(self, m),
                    "ban_list": lambda: s.do_ban_list(self, m),
                    "set_admin": lambda: s.do_set_admin(self, m),
                    "set_perms": lambda: s.do_set_perms(self, m),
                    "room_state": lambda: s.do_room_state(self, m),
                    "get_roles": lambda: s.do_get_roles(self, m),
                    "set_roles": lambda: s.do_set_roles(self, m),
                    "set_limit": lambda: s.do_set_limit(self, m),
                    "search": lambda: s.do_search(self, m),
                    "friends": lambda: {"t": "friends", "ok": True, **s.friends_json(self.user["id"])},
                    "add_friend": lambda: s.do_add_friend(self, m),
                    "friend_resp": lambda: s.do_friend_resp(self, m),
                    "remove_friend": lambda: s.do_remove_friend(self, m),
                    "pm": lambda: s.do_pm(self, m),
                    "invite": lambda: s.do_invite(self, m),
                    "change_password": lambda: s.do_change_password(self, m),
                    "admin": lambda: s.do_admin(self, m),
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
        except OSError as ex:
            # a player closing the app, or a network dropping, resets the socket - that is
            # how a session normally ends, and a traceback over it buries the lines that matter
            who = self.user["username"] if self.user else self.addr[0]
            log(f"conn closed: {who} ({getattr(ex, 'strerror', None) or ex})")
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

    def _do_typing(self, m):
        """The three dots. Fire and forget: the client never waits for the answer."""
        name = self.user["username"]
        uid = self.user["id"]
        to = (m.get("user") or "").strip()
        if to:
            t = self.srv.user_by_name(to)
            if not t:
                return {"t": "typing", "ok": False, "err": "No user with that name"}
            if not self.srv.db.one("SELECT * FROM friends WHERE (a=? AND b=?) OR (a=? AND b=?)",
                                   (uid, t["id"], t["id"], uid)):
                return {"t": "typing", "ok": False, "err": "Not friends"}
            tc = self.srv.conns.get(t["id"])
            if tc:
                try:
                    tc.push({"t": "typing", "from": name})
                except Exception:
                    pass
            return {"t": "typing", "ok": True}
        rid = self.active_room
        if rid:
            self.srv.push_room(rid, {"t": "typing", "room": rid, "from": name}, skip=uid)
        return {"t": "typing", "ok": True}

    def _do_chat(self, m):
        text = (m.get("text") or "").strip()[:500]
        rid = self.active_room
        if not rid or not text:
            return {"t": "chat", "ok": False, "err": "Not in a room"}
        me = self.srv.member_row(rid, self.user["id"])
        self.srv.push_room(rid, {"t": "chat", "room": rid, "from": self.user["username"],
                                 "role": me["role"] if me else "member",
                                 "text": text, "ts": time.time()})
        return {"t": "chat", "ok": True}


def stamp_day(t):
    """A day, short enough for a column."""
    try:
        return time.strftime("%Y-%m-%d", time.localtime(float(t)))
    except (TypeError, ValueError):
        return "-"


def human_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return ""


def save_cfg(cfg):
    try:
        tmp = CFG_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, CFG_FILE)
    except OSError:
        log("config: could not be written")


class Console:
    """The management console: `python vlan42_server.py set admin erfan`.

    It speaks the same encrypted protocol as the player app, over loopback only, and it
    carries no password - what makes it the team is a stamp that only a process able to
    read vlan42_staff.key can make. So the source code may sit on a player's PC: without
    that file on the VPS there is nothing in it to copy, and a stamp captured off the wire
    is worth one minute."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.host, self.port = "127.0.0.1", int(cfg.get("tcp_port") or DEFAULT_TCP_PORT)
        self.sock, self.aead, self.buf = None, None, b""

    def send(self, obj):
        raw = json.dumps(obj).encode()
        n = secrets.token_bytes(12)
        self.sock.sendall(base64.b64encode(n + self.aead.encrypt(n, raw, b"vlan42-ctl")) + b"\n")

    def recv(self):
        while True:
            if b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                d = base64.b64decode(line)
                return json.loads(self.aead.decrypt(d[:12], d[12:], b"vlan42-ctl"))
            chunk = self.sock.recv(65536)
            if not chunk:
                return None
            self.buf += chunk

    def run(self, words):
        cmd = " ".join(words).strip() or "status"
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=8)
        except OSError:
            print(f"No V.Lan.42 server answers on {self.host}:{self.port}.")
            return 1
        try:
            line = b""
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise OSError("the server closed the door")
                line += chunk
                if b"\n" in line:
                    break
            hello = json.loads(line.split(b"\n", 1)[0])
            eph = X25519PrivateKey.generate()
            shared = eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(hello["pub"])))
            self.aead = AESGCM(HKDF(algorithm=hashes.SHA256(), length=32,
                                    salt=bytes.fromhex(hello["nonce"]),
                                    info=b"vlan42-ctl").derive(shared))
            # the key is not agreed yet, so this first line goes out in the open, as
            # the player app sends it too
            self.sock.sendall(json.dumps({"t": "auth1", "pub": eph.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw).hex()}).encode() + b"\n")
            self.send({"t": "admin", "stamp": staff_stamp(), "cmd": cmd})
            r = self.recv() or {}
        finally:
            try:
                self.sock.close()
            except OSError:
                pass
        if not r.get("ok"):
            print(r.get("err") or "The server refused that.")
            return 1
        print(r.get("out") or "Done.")
        return 0


HELP = """V.Lan.42 - the team's own commands

Type them into the window that is running the server, or next to it:
    python vlan42_server.py set admin erfan

  status                 what is running right now
  users                  every account: made, last seen, its PC, its rooms, its data
  rooms                  every room: owner, members, who is in it now
  traffic                bytes the relay moved, per player per day
  set admin <name>       let <name> see the management panel inside the app
  remove admin <name>    take that right back
  set limit <room> <n>   how many players room <room> may hold (2-64)
  help                   this list

Nothing here needs a password: whoever can type in the server's window is whoever holds
the VPS. The same commands reach the server over the network only with a stamp made from
vlan42_staff.key, which lives on this machine alone - a stamp is worth one minute."""


def main():
    cfg = load_cfg()
    staff_key()                     # the management door exists from the first run onward
    if not os.path.exists(CFG_FILE):
        with open(CFG_FILE, "w", encoding="utf-8") as f:
            json.dump({"tcp_port": DEFAULT_TCP_PORT, "udp_port": DEFAULT_UDP_PORT}, f, indent=2)
    words = sys.argv[1:]
    if words and words[0].lower() in ("help", "-h", "--help"):
        print(HELP)
        return 0
    if words:
        return Console(cfg).run(words)
    Server(cfg).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
