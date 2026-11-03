# -*- coding: utf-8 -*-
"""Headless checks for the room entry path (VpsNode.start).

    python _test/test_enter_room.py

Entering a room used to fail for everybody with "UDP channel to the server
failed", even on a healthy server: the thread that reads the UDP socket was
started *after* the code waited for the "V42OK" answer of the server, so that
answer could never be seen. These checks run the real client classes against a
real server; only the Wintun adapter and the netsh firewall calls are stubbed.
"""
import json, os, shutil, socket, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
HOST, PORT = "127.0.0.1", 45443

import vplan42 as vp  # noqa: E402

results = []


def check(name, ok, extra=""):
    results.append(bool(ok))
    print(f"  {'OK ' if ok else 'FAIL'} {name}" + ("" if ok or not extra else f"  [{extra}]"))
    return ok


def boot():
    d = tempfile.mkdtemp(prefix="vlan42_ent_")
    shutil.copyfile(os.path.join(HERE, "..", "vlan42_server.py"), os.path.join(d, "vlan42_server.py"))
    with open(os.path.join(d, "vlan42_server.json"), "w", encoding="utf-8") as f:
        json.dump({"tcp_port": PORT, "udp_port": PORT}, f)
    p = subprocess.Popen([sys.executable, "vlan42_server.py"], cwd=d,
                         stdout=open(os.path.join(d, "out.log"), "wb") if os.environ.get("ENT_DEBUG")
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


class FakeTun:
    """Stands in for the Wintun adapter: records what the relay delivers."""

    def __init__(self, dll, name):
        self.packets, self.last_loop, self.vip = [], time.time(), None
        self.stop = threading.Event()

    def configure(self, vip):
        self.vip = vip

    def write(self, pkt):
        self.packets.append(pkt)

    def read_loop(self, cb):
        while not self.stop.is_set():
            self.last_loop = time.time()
            self.stop.wait(0.2)

    def close(self):
        self.stop.set()


def make_link(name, pw):
    link = vp.VpsLink(HOST, PORT, lambda m: None)
    link.connect()
    r = link.req("register", u=name, p=pw)
    if not r.get("ok"):
        raise OSError(f"register {name}: {r}")
    link.user, link.token = r["user"], r["token"]
    return link


def make_node(link, room):
    """Exactly what App.enter_room does before it lets the node start."""
    logs = []
    node = vp.VpsNode(link, room, logs.append, lambda e: None)
    node.firewall_rules = lambda: None          # netsh needs an admin shell
    node.update_state(room)
    return node, logs


def main():
    vp.ensure_wintun = lambda log=None: None
    vp.Tun = FakeTun
    proc, workdir = boot()
    nodes, links = [], []
    try:
        a = links.append(make_link("entry_a", "pw123")) or links[-1]
        b = links.append(make_link("entry_b", "pw123")) or links[-1]
        c = links.append(make_link("entry_c", "pw123")) or links[-1]
        d = links.append(make_link("entry_d", "pw123")) or links[-1]
        r = a.req("create_room", name="entry room", pwd="roompw1")
        check("room created", r.get("ok"), str(r))
        room = r["room"]

        # --- the path that used to raise for everybody
        node_a, logs_a = make_node(a, room)
        nodes.append(node_a)
        started = time.time()
        err = None
        try:
            node_a.start()
        except Exception as ex:
            err = ex
        took = time.time() - started
        check("joining a room works (no more false UDP error)", err is None, repr(err))
        check("the relay answer is really read", node_a.udp_ok.is_set())
        check("start() did not burn the whole timeout", took < 12, f"{took:.1f}s")
        check("the log says the relay is ready", any("UDP relay ready" in m for m in logs_a),
              " | ".join(logs_a))
        check("virtual IP handed out", node_a.vip == "10.77.0.1", str(node_a.vip))

        # --- a second player: the game traffic must travel through the relay
        j = b.req("join_room", code=room["code"], pwd="roompw1")
        check("second player joined", j.get("ok"), str(j))
        node_a.update_state(j["room"])          # like the room_state push the App forwards
        node_b, logs_b = make_node(b, j["room"])
        nodes.append(node_b)
        err = None
        try:
            node_b.start()
        except Exception as ex:
            err = ex
        check("second player enters too", err is None, repr(err))
        check("peers visible on both sides", node_a.peers.get(node_b.uid) and node_b.peers.get(node_a.uid))
        node_a.send_peer(node_b.uid, b"\x45hello through the vps")
        got = None
        for _ in range(40):
            if node_b.tun.packets:
                got = node_b.tun.packets[0]
                break
            time.sleep(0.25)
        check("game traffic is relayed to the other player", got == b"\x45hello through the vps", str(got))

        # --- a relay that never answers: loud, specific error instead of a silent stall
        jc = c.req("join_room", code=room["code"], pwd="roompw1")
        check("third player joined", jc.get("ok"), str(jc))
        node_c, _ = make_node(c, jc["room"])
        node_c._wait_relay = lambda secs: False        # pretend UDP 4242 is blocked
        try:
            node_c.start()
            msg = "no error raised"
        except OSError as ex:
            msg = str(ex)
            node_c.stop()
        check("the error names the relay", "relay" in msg and HOST in msg, msg)
        check("the error names the port", str(PORT) in msg, msg)
        check("the error points at the checker tool", "vlan42_check.py" in msg, msg)

        # --- a refused session (stale token) must not look like a blocked port
        node_d, _ = make_node(d, room)
        node_d.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        node_d.sock.settimeout(0.5)
        node_d.running = True
        threading.Thread(target=node_d.udp_loop, daemon=True).start()
        node_d.sock.sendto(b"V42BIND" + b"\x11" * 16, (HOST, PORT))
        deadline = time.time() + 5
        while time.time() < deadline and not node_d.udp_rejected:
            time.sleep(0.1)
        check("a UDP session the server refuses is recognised", node_d.udp_rejected)
        node_d.running = False
        node_d.sock.close()

        # --- _wait_relay gives up when told, it does not hang
        e_port = PORT + 700                       # a UDP port nobody listens on
        node_e = vp.VpsNode(a, room, lambda m: None, lambda e: None)
        node_e.link = type("L", (), {"host": HOST, "port": e_port, "token": "00" * 16,
                                     "alive": True, "user": {"id": 1}})()
        node_e.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        node_e.sock.settimeout(1)
        node_e.running = True
        t0 = time.time()
        ok_relay = node_e._wait_relay(3)
        node_e.running = False
        node_e.sock.close()
        check("a silent relay gives up in time", not ok_relay and time.time() - t0 < 6,
              f"{time.time() - t0:.1f}s")
    finally:
        for n in nodes:
            n.running = False
            try:
                n.stop()
            except Exception:
                pass
        for l in links:
            l.close()
        proc.terminate()
        proc.wait(10)
        shutil.rmtree(workdir, ignore_errors=True)

    print(f"\nRESULT: {sum(results)} passed, {len(results) - sum(results)} failed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
