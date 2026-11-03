# -*- coding: utf-8 -*-
"""Headless checks for the things a player should see the moment they happen.

    python _test/test_friends_pm.py

A friend request, an accept, a private message, a promotion to admin and a
removal must land on the other screen without anybody refreshing. The server
runs in its own throw-away folder, so the real database stays untouched.
"""
import json, os, shutil, socket, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
HOST, PORT = "127.0.0.1", 45244

import test_client as tc              # noqa: E402
tc.HOST, tc.PORT = HOST, PORT        # the shared test client now aims at this server
TClient, check = tc.TClient, tc.check


def boot():
    d = tempfile.mkdtemp(prefix="vlan42_pm_")
    shutil.copyfile(os.path.join(HERE, "..", "vlan42_server.py"), os.path.join(d, "vlan42_server.py"))
    with open(os.path.join(d, "vlan42_server.json"), "w", encoding="utf-8") as f:
        json.dump({"tcp_port": PORT, "udp_port": PORT}, f)
    p = subprocess.Popen([sys.executable, "vlan42_server.py"], cwd=d,
                         stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    for _ in range(50):
        try:
            socket.create_connection((HOST, PORT), timeout=0.5).close()
            return p, d
        except OSError:
            time.sleep(0.2)
    p.kill()
    raise OSError("test server did not start")


def register(name):
    c = TClient(name)
    r = c.req("register", u=name, p="pw123")
    assert r.get("ok"), r
    c.token, c.user = r["token"], r["user"]
    return c


def names(items):
    return [x["name"] for x in items or []]



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
    proc, d = boot()
    try:
        carol, dave, erin = register("carol"), register("dave"), register("erin")

        # 1. a request is on the other screen without asking for it
        r = carol.req("add_friend", user="dave")
        check("the answer carries the sender's own lists",
              r.get("ok") and "friends" in r and "requests" in r, str(r))
        rq = dave.drain_push("friend_req", timeout=6)
        check("the other side is told who asked", rq is not None and rq.get("from") == "carol", str(rq))
        up = dave.drain_push("friend_upd", timeout=6)
        check("and gets the fresh list with it",
              up is not None and "carol" in names(up.get("requests", [])), str(up))

        # 2. accepting updates both screens at once
        r = dave.req("friend_resp", user="carol", accept=True)
        check("accept answers with the accepter's list",
              r.get("ok") and "carol" in names(r.get("friends", [])) and r.get("requests") == [], str(r))
        up = carol.drain_push("friend_upd", timeout=6)
        check("the sender sees the new friend without polling",
              up is not None and "dave" in names(up.get("friends", [])), str(up))

        # 3. one to one chat between friends
        r = carol.req("pm", user="dave", text="salam, biam?")
        check("a friend can be written to", r.get("ok") and r.get("delivered") and r.get("ts"), str(r))
        p = dave.drain_push("pm", timeout=6)
        check("the line lands at once", p is not None and p.get("from") == "carol"
              and p.get("text") == "salam, biam?", str(p))
        check("writing to a friend who is away answers the sender",
              dave.req("pm", user="carol", text="are!").get("ok")
              and carol.drain_push("pm", timeout=6).get("text") == "are!")
        r = carol.req("pm", user="erin", text="hi")
        check("a stranger cannot be written to", not r.get("ok") and "friend" in str(r.get("err")), str(r))

        # 3b. the typing dots travel the same friend-only path
        check("typing to a friend is answered", carol.req("typing", user="dave").get("ok"))
        tp = dave.drain_push("typing", timeout=6)
        check("the friend sees the dots start",
              tp is not None and tp.get("from") == "carol" and not tp.get("room"), str(tp))
        r = carol.req("typing", user="erin")
        check("a stranger never sees you typing", not r.get("ok") and "friend" in str(r.get("err")), str(r))

        # 4. a friend whose connection is gone is reported as not delivered
        check("erin and dave become friends",
              dave.req("add_friend", user="erin").get("ok")
              and erin.req("friend_resp", user="dave", accept=True).get("ok"))
        erin.sock.close()
        time.sleep(0.6)
        r = dave.req("pm", user="erin", text="when you are back")
        check("writing to a closed friend says so", r.get("ok") and r.get("delivered") is False, str(r))

        # 5. one change in the room, every member informed in their own words
        room = dave.req("create_room", name="game night", pwd="roompw1")["room"]
        rid = room["id"]
        fern = register("fern")
        cj = join(carol, dave, room["code"], "roompw1")
        fj = join(fern, dave, room["code"], "roompw1")
        check("two players join by code once the host says yes",
              cj.get("ok") and fj.get("ok"), str(cj.get("err")))
        cid = next(m["id"] for m in cj["room"]["members"] if m["name"] == "carol")
        r = dave.req("set_admin", room=rid, user=cid, admin=True,
                     perms={"kick": True, "ban": True, "unban": False, "limit": False})
        check("the owner makes an admin", r.get("ok"), str(r))
        st = carol.drain_push("room_state", timeout=6)
        check("the new admin is told her own role",
              st is not None and st["room"]["my_role"] == "admin", str(st))
        check("with the permissions she was given",
              st["room"]["my_perms"].get("kick") is True
              and st["room"]["my_perms"].get("unban") is False, str(st["room"]["my_perms"]))
        sf = fern.drain_push("room_state", timeout=6)
        check("a member who never entered the room is told too",
              sf is not None and sf["room"]["id"] == rid and sf["room"]["my_role"] == "member", str(sf))
        so = dave.drain_push("room_state", timeout=6)
        check("each copy is written for its reader",
              so is not None and so["room"]["my_role"] == "owner"
              and len(so["room"]["members"]) == 3, str(so))
        check("roster of the admin copy names all three",
              sorted(names(st["room"]["members"])) == ["carol", "dave", "fern"],
              str(names(st["room"]["members"])))

        # 6. demotion is just as instant
        r = dave.req("set_admin", room=rid, user=cid, admin=False)
        check("the owner demotes again", r.get("ok"), str(r))
        st = carol.drain_push("room_state", timeout=6)
        check("the demotion reaches her at once", st is not None and st["room"]["my_role"] == "member",
              str(st))

        # 7. and room chat still reaches a member who never entered
        check("the owner activates the room", dave.req("activate", room=rid).get("ok"))
        check("the owner writes in the room chat",
              dave.req("chat", room=rid, text="game ready").get("ok"))
        rc = fern.drain_push("chat", timeout=6)
        check("a waiting member reads the room chat",
              rc is not None and rc.get("text") == "game ready" and rc.get("from") == "dave", str(rc))

        # 7b. the three dots ride the same room path
        check("the owner says he is typing", dave.req("typing").get("ok"))
        tp = fern.drain_push("typing", timeout=6)
        check("the room sees the dots start",
              tp is not None and tp.get("room") == rid and tp.get("from") == "dave", str(tp))
        check("the typist is never told about himself",
              dave.drain_push("typing", timeout=1) is None)

        # 8. breaking a friendship closes the chat on both screens
        r = dave.req("remove_friend", user="carol")
        check("removing answers with the remainer's list",
              r.get("ok") and "carol" not in names(r.get("friends", [])), str(r))
        up = carol.drain_push("friend_upd", timeout=6)
        check("the other side loses him at once",
              up is not None and "dave" not in names(up.get("friends", [])), str(up))
        r = carol.req("pm", user="dave", text="one more line")
        check("the chat is closed with the friendship", not r.get("ok"), str(r))

        print()
        print(f"RESULT: {len(tc.PASS)} passed, {len(tc.FAIL)} failed")
        if tc.FAIL:
            print("failed:", ", ".join(tc.FAIL))
            return 1
        return 0
    finally:
        proc.kill()
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
