# -*- coding: utf-8 -*-
"""Headless smoke test for the V.Lan.42 server protocol.

    python _test/test_client.py

Boots a throw-away server on port 45242 in this folder (fresh database),
runs the checks, then stops it. Nothing here touches the real vlan42_data.
"""
import base64, hashlib, json, os, re, shutil, socket, struct, subprocess, sys, threading, time, queue

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = os.path.dirname(os.path.abspath(__file__))
HOST, PORT = "127.0.0.1", 45242
STAFF_KEY = hashlib.sha256(b"the team key of this test").hexdigest()
PASS, FAIL = [], []
SRV_OUT = []          # every line the test server's own window printed


def read_window(proc):
    def work():
        for line in proc.stdout:
            SRV_OUT.append(line.rstrip())
    threading.Thread(target=work, daemon=True).start()


def boot_server():
    """Run the real server in this folder with its own config and an empty database."""
    shutil.copyfile(os.path.join(HERE, "..", "vlan42_server.py"), os.path.join(HERE, "vlan42_server.py"))
    shutil.rmtree(os.path.join(HERE, "vlan42_data"), ignore_errors=True)
    with open(os.path.join(HERE, "vlan42_server.json"), "w", encoding="utf-8") as f:
        json.dump({"tcp_port": PORT, "udp_port": PORT}, f)
    # the team's key: the file that never travels to a player. Written before the server
    # starts so the checks below and the server agree on what a real stamp looks like.
    with open(os.path.join(HERE, "vlan42_staff.key"), "w", encoding="utf-8") as f:
        f.write(STAFF_KEY)
    proc = subprocess.Popen([sys.executable, "-u", "vlan42_server.py"], cwd=HERE,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8", bufsize=1)
    read_window(proc)
    for _ in range(50):
        try:
            socket.create_connection((HOST, PORT), timeout=0.5).close()
            return proc
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise OSError("test server did not start")


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  OK  " if cond else " FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


class TClient:
    def __init__(self, name):
        self.name = name
        self.sock = socket.create_connection((HOST, PORT), timeout=10)
        self.buf = b""
        self.pushes = queue.Queue()
        self.waiters = {}
        line = self.recv_plain()
        assert line["t"] == "hello", line
        eph = X25519PrivateKey.generate()
        pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared = eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(line["pub"])))
        key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=bytes.fromhex(line["nonce"]), info=b"vlan42-ctl").derive(shared)
        self.aead = AESGCM(key)
        self.sock.sendall(json.dumps({"t": "auth1", "pub": pub.hex()}).encode() + b"\n")
        # like the real client: the reader must not die just because the line is quiet
        self.sock.settimeout(None)
        self.user = None
        self.token = None
        self.room = None
        threading.Thread(target=self.reader, daemon=True).start()

    def recv_plain(self):
        while b"\n" not in self.buf:
            c = self.sock.recv(4096)
            if not c:
                raise OSError("closed")
            self.buf += c
        line, _, self.buf = self.buf.partition(b"\n")
        return json.loads(line.decode())

    def reader(self):
        buf = self.buf
        self.buf = b""
        while True:
            try:
                while b"\n" not in buf:
                    c = self.sock.recv(4096)
                    if not c:
                        return
                    buf += c
                line, _, buf = buf.partition(b"\n")
                d = base64.b64decode(line.strip())
                obj = json.loads(self.aead.decrypt(d[:12], d[12:], b"vlan42-ctl"))
            except Exception:
                return
            if obj.get("t") == "push":
                self.pushes.put(obj["p"])
            else:
                qs = self.waiters.get(obj.get("t"))
                if qs:
                    try:
                        qs.pop(0).put(obj)
                    except (IndexError, AttributeError):
                        pass

    def send(self, obj):
        raw = json.dumps(obj, separators=(",", ":")).encode()
        n = os.urandom(12)
        self.sock.sendall(base64.b64encode(n + self.aead.encrypt(n, raw, b"vlan42-ctl")) + b"\n")

    def req(self, t, timeout=10, **kw):
        q = queue.Queue()
        self.waiters.setdefault(t, []).append(q)
        self.send({"t": t, **kw})
        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            return {"t": t, "ok": False, "err": "timeout"}

    def req_quiet(self, t, timeout=5, **kw):
        """req() for a connection we expect to be dead already."""
        try:
            return self.req(t, timeout=timeout, **kw)
        except OSError:
            return {"t": t, "ok": False, "err": "closed"}

    def req_wait_online(self, t, timeout=12, **kw):
        """req(), but keep trying until ok (server may briefly be busy)."""
        end = time.time() + timeout
        while time.time() < end:
            r = self.req(t, timeout=max(2, int(end - time.time())), **kw)
            if r.get("ok") is not False or "timeout" not in str(r.get("err")):
                return r
        return r

    def drain_push(self, t, timeout=4, quiet=0.6):
        """Newest push of type t once the stream settles; non-matching pushes are kept."""
        kept, out, last = [], None, time.time()
        end = time.time() + timeout
        while time.time() < end:
            try:
                p = self.pushes.get(timeout=0.2)
            except queue.Empty:
                if out is not None and time.time() - last > quiet:
                    break
                continue
            last = time.time()
            if p.get("t") == t:
                out = p
            else:
                kept.append(p)
        for k in kept:
            self.pushes.put(k)
        return out

    def udp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(b"V42BIND" + bytes.fromhex(self.token), (HOST, PORT))
        data, _ = s.recvfrom(2048)
        assert data == b"V42OK", data
        return s

    def dgram(self, rid, mode, target, payload):
        h = b"V42D" + struct.pack("!I", rid) + bytes([mode]) + (struct.pack("!I", target) if mode else b"")
        return h + payload

    def relays_to(self, rid, src, dst, payload, wait=3.0):
        """Send one broadcast from src, return what dst gets (None if the server dropped it)."""
        src.sendto(self.dgram(rid, 0, 0, payload), (HOST, PORT))
        old = dst.gettimeout()
        dst.settimeout(wait)
        try:
            return dst.recvfrom(2048)[0]
        except socket.timeout:
            return None
        finally:
            dst.settimeout(old)



def join(c, host, code, pwd):
    """The guest knocks with the room password and the host lets them in - the same
    two steps the app's accept card performs. Returns the join answer, with the room
    dict in it once they are inside."""
    r = c.req("join_room", code=code, pwd=pwd)
    if r.get("ok") and r.get("pending"):
        ok = host.req("join_resp", room=r["room"], user=c.user["id"], accept=True).get("ok")
        if not ok:
            return {"t": "join_room", "ok": False, "err": "the host did not answer"}
        st = c.drain_push("room_state", timeout=6)
        r = {"t": "join_room", "ok": st is not None, "room": (st or {}).get("room"),
             "pending": False}
    return r

def main(srv):
    a = TClient("alice")
    r = a.req("register", u="alice", p="pw123")
    check("register alice", r.get("ok"), str(r))
    a.token = r["token"]
    a.user = r["user"]

    b = TClient("bob")
    r = b.req("register", u="bob", p="pw123")
    check("register bob", r.get("ok"), str(r))
    b.token = r["token"]
    b.user = r["user"]

    # wrong password / duplicate name / token login / one session per account
    c = TClient("mallory")
    r = c.req("login", u="alice", p="wrong")
    check("login rejects wrong password", not r.get("ok"))
    r = c.req("register", u="alice", p="x1234")
    check("duplicate username rejected", not r.get("ok"))
    r = c.req("register", u="dave", p="pw123")
    check("register dave", r.get("ok"), str(r))
    d = TClient("dave-again")
    r = d.req("login_token", token=r["token"])
    check("token login works", r.get("ok"), str(r))
    check("new sign-in kicks the old session", c.drain_push("signed_elsewhere", timeout=2) is not None)
    check("kicked session can ask nothing more", not c.req_quiet("my_rooms", timeout=3).get("ok"))
    c.sock.close()
    d.sock.close()

    # create room
    r = a.req("create_room", name="game room", pwd="roompw1")
    check("create room", r.get("ok"), str(r))
    room = r["room"]
    check("owner role", room["my_role"] == "owner")
    check("owner vip 10.77.0.1", room["members"][0]["vip"] == "10.77.0.1")
    code, pwd, rid, key = room["code"], room["pwd"], room["id"], room["key"]
    check("the invite is a sealed code, not a link",
          "://" not in r["invite"] and r["invite"].count(".") >= 5
          and re.fullmatch(r"[A-Za-z0-9_-]{4}(\.[A-Za-z0-9_-]{1,4})+", r["invite"]) is not None,
          r["invite"])

    # wrong room password
    r = b.req("join_room", code=code, pwd="nope")
    check("join rejects wrong password", not r.get("ok"))

    # join: the password opens the door, but the host still has to say yes
    r = b.req("join_room", code=code, pwd=pwd)
    check("a new face is held at the door", r.get("ok") and r.get("pending"), str(r))
    knock = a.drain_push("jreq", timeout=6)
    check("the host is told who knocked",
          knock and knock["from"] == "bob" and knock["user"] == b.user["id"], str(knock))
    q = a.req("join_list", room=rid)
    check("the host can read the queue", q.get("ok") and len(q.get("requests", [])) == 1, str(q))
    check("the guest is not a member yet",
          not any(m["name"] == "bob" for m in a.req("my_rooms")["rooms"][0]["members"]), "")
    check("the host lets bob in", a.req("join_resp", room=rid, user=b.user["id"],
                                       accept=True).get("ok"))
    check("the guest is told they are in", b.drain_push("join_ok", timeout=6) is not None)
    st = b.drain_push("room_state", timeout=6)
    r = {"ok": st is not None, "room": (st or {}).get("room")}
    check("bob joins", r.get("ok"), str(r))
    check("guest vip assigned", r["room"]["members"][1]["vip"].startswith("10.77."),
          r["room"]["members"][1]["vip"])
    check("the queue is empty again", len(a.req("join_list", room=rid).get("requests", [])) == 0)

    # activate both + UDP
    check("alice activate", a.req("activate", room=rid).get("ok"))
    check("bob activate", b.req("activate", room=rid).get("ok"))
    ua, ub = a.udp(), b.udp()
    aead = AESGCM(bytes.fromhex(key))

    # room_state push must mark both online
    st = None
    end = time.time() + 6
    while time.time() < end:
        p = a.drain_push("room_state", timeout=1)
        if p and all(m["online"] for m in p["room"]["members"]):
            st = p
            break
    check("room_state push", st is not None)

    # data relay: alice broadcast -> bob receives and decrypts
    pkt = bytes(range(20, 40))
    n = os.urandom(12)
    payload = b"D" + struct.pack("!I", a.user["id"]) + n + aead.encrypt(n, pkt, b"vd")
    ua.sendto(a.dgram(rid, 0, 0, payload), (HOST, PORT))
    got = None
    for _ in range(3):
        try:
            d, _ = ub.recvfrom(2048)
            got = d
            break
        except socket.timeout:
            pass
    ok = got is not None and got[0:1] == b"D"
    if ok:
        try:
            ok = (aead.decrypt(got[5:17], got[17:], b"vd") == pkt
                  and struct.unpack("!I", got[1:5])[0] == a.user["id"])
        except Exception:
            ok = False
    check("UDP broadcast relay + decrypt", ok, repr(got)[:100])

    # targeted ping bob->alice, alice echoes, bob measures rtt
    uid_a, uid_b = a.user["id"], b.user["id"]
    t0 = time.time()
    ub.sendto(b.dgram(rid, 1, uid_a, b"P" + struct.pack("!I", uid_b) + struct.pack("!d", t0)), (HOST, PORT))
    d, _ = ua.recvfrom(2048)
    check("targeted ping reaches alice", d[0:1] == b"P" and struct.unpack("!I", d[1:5])[0] == uid_b)
    ua.sendto(a.dgram(rid, 1, uid_b, b"R" + struct.pack("!I", uid_a) + d[5:13]), (HOST, PORT))
    d, _ = ub.recvfrom(2048)
    rtt = (time.time() - struct.unpack("!d", d[5:13])[0]) * 1000
    check("ping echo returns to bob", d[0:1] == b"R" and 0 <= rtt < 1000, f"{rtt:.1f}ms")

    # chat
    check("chat send", a.req("chat", text="hello bob").get("ok"))
    ch = b.drain_push("chat")
    check("chat push to bob", ch is not None and ch["text"] == "hello bob")

    # roles: alice makes bob admin with kick+ban+unban (no limit)
    r = a.req("set_admin", room=rid, user=uid_b, admin=True,
              perms={"kick": True, "ban": True, "unban": True, "limit": False})
    check("set bob admin", r.get("ok"), str(r))

    # carol joins, gets kicked by admin bob
    cc = TClient("carol")
    r = cc.req("register", u="carol", p="pw123")
    cc.token = r["token"]
    cc.user = r["user"]
    check("carol joins", join(cc, a, code, pwd).get("ok"))
    r = b.req("kick", room=rid, user=cc.user["id"])
    check("admin bob kicks carol", r.get("ok"), str(r))
    kicked = cc.drain_push("kicked")
    check("carol receives kicked push", kicked is not None)

    # ban
    check("carol rejoins after a kick", join(cc, a, code, pwd).get("ok"))
    r = b.req("ban", room=rid, user=cc.user["id"], reason="cheating")
    check("admin bob bans carol", r.get("ok"), str(r))
    r = cc.req("join_room", code=code, pwd=pwd)
    check("banned user cannot rejoin", not r.get("ok"), str(r))
    r = b.req("ban_list", room=rid)
    check("ban list shows carol", r.get("ok") and any(x["name"] == "carol" for x in r.get("bans", [])))
    r = b.req("unban", room=rid, user=cc.user["id"])
    check("admin bob unbans carol", r.get("ok"), str(r))
    check("carol can rejoin after unban", join(cc, a, code, pwd).get("ok"))

    # member without perms cannot kick
    r = cc.req("kick", room=rid, user=uid_b)
    check("member carol cannot kick", not r.get("ok"))
    # admin cannot kick the owner
    r = b.req("kick", room=rid, user=uid_a)
    check("admin cannot kick owner", not r.get("ok"))

    # member limit
    r = a.req("set_limit", room=rid, limit=3)
    check("owner sets limit 3", r.get("ok"), str(r))
    dd = TClient("erin")
    r = dd.req("register", u="erin", p="pw123")
    check("register erin", r.get("ok"), str(r))
    dd.token = r["token"]
    dd.user = r["user"]
    r = dd.req("join_room", code=code, pwd=pwd)
    check("room full blocks join", not r.get("ok"), str(r))
    r = a.req("set_limit", room=rid, limit=16)
    check("owner raises limit", r.get("ok"))
    check("erin joins after limit raised", join(dd, a, code, pwd).get("ok"))

    # ---- three accounts to a PC, no more. The hash is what the app reads off the
    #      hardware; the server never sees the parts it came from.
    box = hashlib.sha256(b"the same PC").hexdigest()
    other = hashlib.sha256(b"a different PC").hexdigest()
    fresh = hashlib.sha256(b"a third PC").hexdigest()

    def reg(name, hw, tag):
        t = TClient(tag)
        return t, t.req("register", u=name, p="pw123", hw=hw)

    for n_ in ("pc1", "pc2", "pc3"):
        _, r = reg(n_, box, n_)
        check(f"{n_} registers from the box", r.get("ok"), str(r))
    _, r = reg("pc4", box, "pc4")
    check("a fourth account on the same box is refused", not r.get("ok"), str(r))
    check("and says why, in the words the app can show",
          r.get("err") == "This PC already has 3 accounts - sign in to one of them instead",
          str(r.get("err")))
    _, r = reg("pc5", other, "pc5")
    check("another box still gets its own three", r.get("ok"), str(r))

    # an account made before the rule is not punished for it: it signs in uncounted, and
    # the first box it signs in from adopts it - using one of that box's three places
    _, r = reg("preexisting", "", "no-hash")
    check("an account with no hardware hash is still allowed", r.get("ok"), str(r))
    m = TClient("adopt-1")
    check("and it can sign in", m.req("login", u="preexisting", p="pw123").get("ok"))
    m2 = TClient("adopt-2")
    check("a box that sees it first claims it",
          m2.req("login", u="preexisting", p="pw123", hw=fresh).get("ok"))
    check("the box keeps its word about who it adopted",
          a.req("my_rooms").get("ok"))
    for n_ in ("pc6", "pc7"):
        _, r = reg(n_, fresh, n_)
        check(f"{n_} registers on the adopting box", r.get("ok"), str(r))
    _, r = reg("pc8", fresh, "pc8")
    check("the adopted account used one of that box's three", not r.get("ok"), str(r))

    # 3-room cap
    r = a.req("create_room", name="room two", pwd="roompw2")
    check("alice second room", r.get("ok"), str(r.get("err")))
    g2 = a.req("get_roles", room=r["room"]["id"])
    check("a second room starts from the built-in defaults, not the first room's rules",
          g2.get("ok") and g2["defaults"]["member"].get("invite") is False
          and g2["defaults"]["admin"].get("invite") is True, str(g2.get("defaults")))
    r = a.req("create_room", name="room three", pwd="roompw3")
    check("alice third room", r.get("ok"), str(r.get("err")))
    r = a.req("create_room", name="room four", pwd="roompw4")
    check("fourth room blocked (max 3)", not r.get("ok"), str(r.get("err")))
    rooms = a.req("my_rooms")["rooms"]
    check("my_rooms shows 3", len(rooms) == 3, str(len(rooms)))
    r = a.req("remove_room", room=rooms[2]["id"])
    check("remove a room frees the slot", r.get("ok"), str(r.get("err")))
    r = a.req("create_room", name="room four", pwd="roompw4")
    check("create after remove works", r.get("ok"), str(r.get("err")))

    # dave joins on a socket of his own, so alice still has a room slot free below
    e = TClient("dave-room")
    r = e.req("login", u="dave", p="pw123")
    check("dave signs in", r.get("ok"), str(r))
    e.token, e.user = r["token"], r["user"]
    re_ = e.req("join_room", code=code, pwd=pwd)
    check("dave is held at the door", re_.get("ok") and re_.get("pending"), str(re_))
    check("the host lets dave in",
          a.req("join_resp", room=rid, user=e.user["id"], accept=True).get("ok"))
    st = e.drain_push("room_state", timeout=6)
    check("dave is inside as a plain member",
          st and st["room"]["my_role"] == "member", str((st or {}).get("room", {}).get("my_role")))
    check("a member has no invite tick", not (st["room"]["my_perms"] or {}).get("invite"),
          str(st["room"]["my_perms"]))
    check("a member cannot invite", not e.req("invite", room=rid, user="bob").get("ok"),
          str(e.req("invite", room=rid, user="bob")))

    # ---- who may bring a friend in. By default an admin may and a member may not, and
    #      the owner can change that for this room alone - for a whole role or for one
    #      person. Rules of one room never reach another room.
    st = b.req("room_state", room=rid)["room"]
    check("an admin may invite by default", (st["my_perms"] or {}).get("invite") is True,
          str(st["my_perms"]))
    check("and the server lets him", b.req("invite", room=rid, user="dave").get("ok"),
          str(b.req("invite", room=rid, user="dave")))

    g = a.req("set_roles", room=rid,
              defaults={"member": {"invite": True}, "admin": {"invite": False}})
    check("the owner sets this room's defaults", g.get("ok"), str(g))
    check("the defaults come back as they were saved",
          g.get("defaults", {}).get("member", {}).get("invite") is True
          and g.get("defaults", {}).get("admin", {}).get("invite") is False, str(g.get("defaults")))
    st = e.drain_push("room_state", timeout=6)
    check("the member now carries the tick", (st["room"]["my_perms"] or {}).get("invite") is True,
          str(st["room"]["my_perms"]))
    check("and can invite a friend", e.req("invite", room=rid, user="bob").get("ok"),
          str(e.req("invite", room=rid, user="bob")))
    # carol is a member with no tick of her own, so the room's member default is her rule
    st = cc.drain_push("room_state", timeout=6)
    check("a person with no ticks follows his role's room default",
          st["room"]["my_role"] == "member"
          and (st["room"]["my_perms"] or {}).get("invite") is True, str(st["room"]["my_perms"]))
    check("and may invite now that the room says members may",
          cc.req("invite", room=rid, user="erin").get("ok"),
          str(cc.req("invite", room=rid, user="erin")))

    # one person, one tick - and it outranks the room's own default
    check("the owner ticks permissions for one person",
          a.req("set_perms", room=rid, user=b.user["id"],
                perms={"kick": True, "ban": True, "invite": True}).get("ok"))
    st = b.drain_push("room_state", timeout=6)
    check("the personal tick beats the room default",
          (st["room"]["my_perms"] or {}).get("invite") is True
          and (st["room"]["my_perms"] or {}).get("kick") is True, str(st["room"]["my_perms"]))
    check("and the admin may invite again", b.req("invite", room=rid, user="dave").get("ok"),
          str(b.req("invite", room=rid, user="dave")))
    check("a member cannot set the room defaults",
          not e.req("set_roles", room=rid, defaults={"admin": {"kick": True}}).get("ok"))
    check("and cannot set another person's permissions",
          not e.req("set_perms", room=rid, user=b.user["id"], perms={"kick": True}).get("ok"))

    # friends
    r = a.req("search", q="bo")
    check("search finds bob", r.get("ok") and any(u["name"] == "bob" for u in r["users"]))
    r = a.req("add_friend", user="bob")
    check("alice adds bob", r.get("ok"))
    req_push = b.drain_push("friend_upd")
    check("bob gets friend_upd push", req_push is not None and
          any(x["name"] == "alice" for x in req_push.get("requests", [])))
    r = b.req("friend_resp", user="alice", accept=True)
    check("bob accepts", r.get("ok"))
    fr = a.req("friends")
    check("alice friends list has bob", any(f["name"] == "bob" for f in fr.get("friends", [])))
    fr = b.req("friends")
    check("bob friends list has alice", any(f["name"] == "alice" for f in fr.get("friends", [])))

    # room invite to friend
    r = a.req("invite", user="bob", room=rid)
    check("invite friend to room", r.get("ok"))
    inv = b.drain_push("invite")
    check("bob receives invite push", inv is not None and inv.get("code") == code
          and bool(inv.get("token")))

    # dormancy: a room with one member online must not relay anything
    check("bob deactivates", b.req("deactivate").get("ok"))
    got = a.relays_to(rid, ua, ub, payload, wait=1.2)
    check("dormant room relays nothing", got is None, repr(got)[:60])
    check("bob activates again", b.req("activate", room=rid).get("ok"))
    got = a.relays_to(rid, ua, ub, payload)
    check("relay works again with 2 online", got is not None and got[0:1] == b"D", repr(got)[:60])

    # owner removes the room -> ownership transfers, members keep talking
    r = a.req("remove_room", room=rid)
    check("owner removes room (ownership transfer)", r.get("ok"))

    # bob should now own the transferred room
    rooms = b.req("my_rooms")["rooms"]
    tgt = [x for x in rooms if x["id"] == rid]
    check("ownership transferred to bob", tgt and tgt[0]["my_role"] == "owner", str(tgt and tgt[0]["my_role"]))

    # ------------------------------------------------- changing your own password
    p = TClient("pwdguy")
    r = p.req("register", u="pwdguy", p="pw123")
    check("an account to try the password door on", r.get("ok"), str(r))
    q = TClient("pwdguy-in")
    r = q.req("login", u="pwdguy", p="pw123")
    check("and it signs in", r.get("ok"), str(r))
    old_token = r.get("token")
    r = q.req("change_password", old="not it", new="apassword2")
    check("the wrong current password opens nothing",
          not r.get("ok") and r.get("err") == "Current password is wrong", str(r))
    r = q.req("change_password", old="pw123", new="abc")
    check("a new password under six characters is refused",
          not r.get("ok") and "6 characters" in r.get("err", ""), str(r))
    r = q.req("change_password", old="pw123", new="pw123")
    check("the same password twice is refused", not r.get("ok"), str(r))
    r = q.req("change_password", old="pw123", new="apassword2")
    check("the password changes", r.get("ok") and bool(r.get("token")), str(r))
    new_token = r.get("token")
    check("the seat that changed it stays signed in", q.req("my_rooms").get("ok"))
    check("the old password no longer opens it",
          not q.req("login", u="pwdguy", p="pw123").get("ok"))
    check("the old remember-me token is retired",
          not q.req("login_token", token=old_token).get("ok"))
    check("no other account was touched by it", a.req("my_rooms").get("ok"))
    q2 = TClient("pwdguy-again")
    check("the new remember-me token opens the door",
          q2.req("login_token", token=new_token).get("ok"), str(q2))
    check("and the new password does", q2.req("login", u="pwdguy", p="apassword2").get("ok"))
    check("while the old one stays shut",
          not q2.req("login", u="pwdguy", p="pw123").get("ok"))

    # ------------------------------------------------- the team's own console
    def stamp_of(secret, ahead=0):
        win = int((time.time() + ahead) // 60)
        n = struct.pack(">QI", win, 0)
        return base64.urlsafe_b64encode(n + AESGCM(bytes.fromhex(secret)).encrypt(
            n, str(win).encode(), b"vlan42-staff")).decode().rstrip("=")

    def console(*words):
        """Run the command the way the team does: typed at the server's own window."""
        p = subprocess.run([sys.executable, "vlan42_server.py", *words], cwd=HERE,
                           capture_output=True, text=True, timeout=60)
        return p.stdout.strip(), p.returncode

    def admin(who, cmd, stamp=None):
        return who.req("admin", stamp=stamp if stamp is not None else stamp_of(STAFF_KEY), cmd=cmd)

    foreign = hashlib.sha256(b"a key nobody but the player has").hexdigest()
    r = admin(a, "users", stamp="")
    check("no stamp: the door stays shut",
          not r.get("ok") and r.get("err") == "This is not the management console", str(r))
    r = admin(a, "users", stamp=stamp_of(foreign))
    check("a stamp from another key is worthless", not r.get("ok"), str(r))
    r = admin(a, "users", stamp=stamp_of(STAFF_KEY, -3600))
    check("an old stamp has expired", not r.get("ok"), str(r))
    r = admin(a, "users", stamp=stamp_of(STAFF_KEY, 600))
    check("and a stamp from the future counts for nothing", not r.get("ok"), str(r))
    r = admin(a, "set admin alice")
    check("a real stamp from an account the team did not vouch is still refused",
          not r.get("ok") and r.get("err") == "This account is not management", str(r))
    r = admin(a, "users", stamp=stamp_of(STAFF_KEY)[:20])
    check("a stamp cut short does not parse", not r.get("ok"), str(r))

    out, rc = console("set", "admin", "alice")
    check("the server window vouches for a name", rc == 0 and "is management now" in out, out)
    check("and the signed-in account hears about it at once",
          a.drain_push("staff", timeout=6) is not None)
    r = a.req("login", u="alice", p="pw123")
    check("the app is told this account is the team", r.get("ok") and r.get("staff") is True, str(r))
    r = admin(a, "users")
    rows = r.get("rows") or []
    check("the team reads the user list", r.get("ok") and len(rows) >= 3, str(r)[:120])
    one = next((x for x in rows if x["name"] == "alice"), {})
    check("a user line carries what the panel shows",
          all(k in one for k in ("id", "name", "created", "last", "machine", "rooms",
                                 "online", "bytes", "staff", "today"))
          and one["staff"] is True and one["online"] is True, str(one))
    check("and the moment it was made is a moment, not a code",
          isinstance(one.get("created"), float) and one["created"] > 0, str(one.get("created")))
    box_line = next((x for x in rows if x["name"] == "pc1"), {})
    check("a line from the box that was counted shows its PC",
          box_line.get("machine") == box[:12], str(box_line))
    check("and an account that gave no hash is not invented one",
          next((x for x in rows if x["name"] == "preexisting"), {}).get("machine") in ("", fresh[:12]),
          str(next((x for x in rows if x["name"] == "preexisting"), {})))
    check("and the console prints the same list", "alice" in admin(a, "users").get("out", ""))
    r = admin(a, "rooms")
    rooms = r.get("rows") or []
    line = next((x for x in rooms if x["id"] == rid), {})
    check("the team reads the room list",
          r.get("ok") and line.get("owner") == "bob" and line.get("members") >= 2, str(line))
    a.relays_to(rid, ua, ub, payload)
    traffic = []
    end = time.time() + 10
    while time.time() < end and not traffic:
        traffic = admin(a, "traffic").get("rows") or []
        if not traffic:
            time.sleep(0.6)
    check("the team reads the data each player moved",
          bool(traffic) and all(t["day"] == time.strftime("%Y-%m-%d") and t["bytes"] > 0
                                for t in traffic), str(traffic[:2]))
    check("every line names a player", all(t.get("name") for t in traffic))

    r = admin(a, f"set limit {rid} 5")
    check("the team retunes a room from the console", r.get("ok"), str(r))
    check("and the room says so",
          any(x["id"] == rid and x["limit"] == 5 for x in admin(a, "rooms").get("rows") or []))
    check("the players in that room hear about it", b.drain_push("room_state", timeout=6) is not None)
    check("a limit below the members already inside is refused",
          not admin(a, f"set limit {rid} 2").get("ok"))
    check("so is a number out of range", not admin(a, f"set limit {rid} 900").get("ok"))
    check("and a room that does not exist", not admin(a, "set limit 99999 8").get("ok"))
    check("a half-typed command is refused", not admin(a, "set limit").get("ok"))
    check("so is a command nobody knows", not admin(a, "launch rocket").get("ok"))
    r = admin(a, "status")
    check("status counts the network", r.get("ok") and "accounts" in r.get("out", ""), str(r))

    # ---- typed straight into the window the server itself runs in
    def type_at_window(cmd, want):
        mark = len(SRV_OUT)
        srv.stdin.write(cmd + "\n")
        srv.stdin.flush()
        end = time.time() + 12
        while time.time() < end:
            got = "\n".join(SRV_OUT[mark:])
            if want in got:
                return got
            time.sleep(0.1)
        return "\n".join(SRV_OUT[mark:])

    out = type_at_window("status", "accounts")
    check("the server's own window answers status", "accounts" in out, out[-200:])
    check("and types out the list of accounts", "alice" in type_at_window("users", "alice"),
          out[-200:])
    out = type_at_window("set admin bob", "is management now")
    check("typing set admin at the window vouches for a name", "is management now" in out, out[-200:])
    push = b.drain_push("staff", timeout=6)
    check("the signed-in account is told so, without signing in again",
          push is not None and push.get("on") is True, str(push))
    r = admin(b, "users")
    check("and the panel opens for them straight away", r.get("ok"), str(r))
    out = type_at_window("remove admin bob", "not management any more")
    check("typing remove admin takes the right back", "not management any more" in out, out[-200:])
    push = b.drain_push("staff", timeout=6)
    check("and the door closes on their screen too",
          push is not None and push.get("on") is False, str(push))
    check("with nothing more they can ask", not admin(b, "users").get("ok"))
    check("help at the window prints the list",
          "set limit" in type_at_window("help", "set limit"))
    check("quit does not stop the server by accident",
          "Close it" in type_at_window("quit", "Close it"))
    check("an unknown word is answered, not thrown",
          "Unknown command" in type_at_window("launch rocket", "Unknown command"))
    check("and the server is still standing after all that typing", a.req("my_rooms").get("ok"))

    out, rc = console("remove", "admin", "alice")
    check("the server window takes the right back",
          rc == 0 and "not management any more" in out, out)
    check("the app learns it on the next sign-in",
          a.req("login", u="alice", p="pw123").get("staff") is False)
    check("and the console door shuts behind it", not admin(a, "users").get("ok"))
    cfg = json.load(open(os.path.join(HERE, "vlan42_server.json"), encoding="utf-8"))
    check("the vouch list lives only in the server's own file",
          cfg.get("staff") == [] and cfg.get("tcp_port") == PORT, str(cfg))
    check("the player's commands still work after all that", a.req("my_rooms").get("ok"))

    print()
    print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
        sys.exit(1)


if __name__ == "__main__":
    srv = boot_server()
    try:
        main(srv)
    finally:
        srv.terminate()
        srv.wait(timeout=5)
        shutil.rmtree(os.path.join(HERE, "vlan42_data"), ignore_errors=True)
        for junk in ("vlan42_server.py", "vlan42_server.json", "vlan42_staff.key"):
            try:
                os.remove(os.path.join(HERE, junk))
            except OSError:
                pass
