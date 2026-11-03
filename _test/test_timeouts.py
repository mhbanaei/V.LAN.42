# -*- coding: utf-8 -*-
"""Headless checks for the timeout rules.

    python _test/test_timeouts.py

A room member who really stops answering must still be reported as timed out,
but a player sitting on the main page must never be, and a lone player who only
keeps pinging must keep his relay. The server here runs with a short
udp_timeout so the whole thing takes seconds instead of half a minute.
"""
import json, os, shutil, socket, struct, subprocess, sys, tempfile, threading, time, types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
HOST, PORT = "127.0.0.1", 45243
IDLE = 3                      # the udp_timeout we tell the test server to use

import test_client as tc      # noqa: E402
tc.HOST, tc.PORT = HOST, PORT
TClient, check = tc.TClient, tc.check
import vplan42 as vp          # noqa: E402


def boot():
    d = tempfile.mkdtemp(prefix="vlan42_tmo_")
    shutil.copyfile(os.path.join(HERE, "..", "vlan42_server.py"), os.path.join(d, "vlan42_server.py"))
    with open(os.path.join(d, "vlan42_server.json"), "w", encoding="utf-8") as f:
        json.dump({"tcp_port": PORT, "udp_port": PORT, "udp_timeout": IDLE}, f)
    p = subprocess.Popen([sys.executable, "vlan42_server.py"], cwd=d,
                         stdout=open(os.path.join(d, "out.log"), "wb") if os.environ.get("TMO_DEBUG")
                         else subprocess.DEVNULL,
                         stderr=subprocess.STDOUT)
    for _ in range(50):
        try:
            socket.create_connection((HOST, PORT), timeout=0.5).close()
            return p, d
        except OSError:
            time.sleep(0.2)
    p.kill()
    raise OSError("test server did not start")


def keepalive(sock, stop):
    """What the real client does while it is alone in a room: ping, ping, ping.
    Only sending happens here so the test thread owns every read."""
    def work():
        while not stop.is_set():
            try:
                sock.sendto(b"V42PING", (HOST, PORT))
            except OSError:
                return
            stop.wait(0.7)
    t = threading.Thread(target=work, daemon=True)
    t.start()
    return t


def silent_for(c, kind, secs):
    """True when no push of this type arrives during the whole window."""
    end = time.time() + secs
    while time.time() < end:
        if c.drain_push(kind, timeout=0.4):
            return False
    return True


def recv_from(sock, secs):
    sock.settimeout(secs)
    try:
        return sock.recvfrom(2048)[0]
    except (socket.timeout, OSError):
        return None


def drain(sock):
    """Throw away whatever is queued (leftover V42PONGs) before the real read."""
    while True:
        sock.settimeout(0.05)
        try:
            sock.recvfrom(2048)
        except (socket.timeout, OSError):
            return


def peer_node():
    """A VpsNode with just what update_state touches, for the peer bookkeeping."""
    n = types.SimpleNamespace()
    n.uid, n.vip, n.peers, n.byip = 1, "10.77.0.1", {}, {}
    n.room = {"my_role": "owner", "my_perms": {}}
    n.update_state = types.MethodType(vp.VpsNode.update_state, n)
    return n


def state(n, rid, bob_online):
    n.update_state({"id": rid, "name": "tmo room", "my_role": "owner", "my_perms": {},
                    "members": [{"id": 1, "name": "alice", "role": "owner",
                                 "vip": "10.77.0.1", "online": True},
                                {"id": 2, "name": "bob", "role": "member",
                                 "vip": "10.77.0.2", "online": bob_online}]})


def main():
    srv, d = boot()
    try:
        a, b = TClient("alice"), TClient("bob")
        for c, nm in ((a, "alice"), (b, "bob")):
            r = c.req("register", u=nm, p="pw123")
            c.token, c.user = r["token"], r["user"]
        r = a.req("create_room", name="tmo room", pwd="roompw1")
        rid = r["room"]["id"]
        b.req("join_room", code=r["room"]["code"], pwd="roompw1")
        a.req("activate", room=rid)
        b.req("activate", room=rid)
        ua, ub = a.udp(), b.udp()
        stop = threading.Event()
        keepalive(ua, stop)      # alice stays alive, so only bob can time out

        # 1. inside a room, a member who really stops answering is still reported
        got = a.drain_push("member_offline", timeout=IDLE + 6)
        check("silent peer times out in the room", got and got.get("user") == b.user["id"], str(got))
        check("timeout carries a reason", bool(got and "timeout" in str(got.get("reason"))), str(got))
        check("the silent one is not told about himself", silent_for(b, "member_offline", 1.5))

        # 2. leaving for the main page must never produce a timeout for that player
        stop.set()
        a.req("deactivate")
        ua.close()
        check("no timeout while sitting on the main page", silent_for(a, "member_offline", IDLE * 3))

        # 3. a lone player who only pings keeps his relay across the idle window
        ub.close()
        b.req("activate", room=rid)
        ub2 = b.udp()
        stop2 = threading.Event()
        ka = keepalive(ub2, stop2)
        time.sleep(IDLE * 3)     # three idle timeouts, data-less
        drain(ub2)               # drop the queued V42PONGs before the real read
        a.req("activate", room=rid)
        ua2 = a.udp()
        ua2.sendto(b"V42D" + struct.pack("!I", rid) + b"\x00" + b"hello-again", (HOST, PORT))
        got = recv_from(ub2, IDLE + 2)
        check("lone pinger still gets relayed data", got == b"hello-again", str(got))
        stop2.set()
        ka.join(3)

        # 4. client side: a peer that just came online must not look 12s stale
        n = peer_node()
        state(n, rid, True)
        p = n.peers[2]
        check("fresh peer clock starts now", 0 <= time.time() - p["last"] < 2, str(p["last"]))
        check("fresh peer is not timed out", not p.get("timed_out"))
        state(n, rid, False)
        state(n, rid, True)
        p2 = n.peers[2]
        check("re-coming online resets the clock", 0 <= time.time() - p2["last"] < 2, str(p2["last"]))
        check("re-coming online clears the timeout", not p2.get("timed_out"))

        for s in (ua, ub, ub2, ua2):
            try:
                s.close()
            except OSError:
                pass
        a.sock.close()
        b.sock.close()
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            pass
        shutil.rmtree(d, ignore_errors=True)
    print(f"\nRESULT: {len(tc.PASS)} passed, {len(tc.FAIL)} failed")
    return 0 if not tc.FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
