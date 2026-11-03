# -*- coding: utf-8 -*-
"""Headless smoke test for the V.Lan.42 server protocol.

    python _test/test_client.py

Boots a throw-away server on port 45242 in this folder (fresh database),
runs the checks, then stops it. Nothing here touches the real vlan42_data.
"""
import base64, json, os, shutil, socket, struct, subprocess, sys, threading, time, queue

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = os.path.dirname(os.path.abspath(__file__))
HOST, PORT = "127.0.0.1", 45242
PASS, FAIL = [], []


def boot_server():
    """Run the real server in this folder with its own config and an empty database."""
    shutil.copyfile(os.path.join(HERE, "..", "vlan42_server.py"), os.path.join(HERE, "vlan42_server.py"))
    shutil.rmtree(os.path.join(HERE, "vlan42_data"), ignore_errors=True)
    with open(os.path.join(HERE, "vlan42_server.json"), "w", encoding="utf-8") as f:
        json.dump({"tcp_port": PORT, "udp_port": PORT}, f)
    proc = subprocess.Popen([sys.executable, "vlan42_server.py"], cwd=HERE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
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

def main():
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
    check("invite link", r["invite"].startswith("vlan42://join/"))

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

    # 3-room cap
    r = a.req("create_room", name="room two", pwd="roompw2")
    check("alice second room", r.get("ok"), str(r.get("err")))
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
    check("bob receives invite push", inv is not None and inv.get("code") == code)

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

    print()
    print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
        sys.exit(1)


if __name__ == "__main__":
    srv = boot_server()
    try:
        main()
    finally:
        srv.terminate()
        srv.wait(timeout=5)
        shutil.rmtree(os.path.join(HERE, "vlan42_data"), ignore_errors=True)
