# -*- coding: utf-8 -*-
"""The dice, the room password, and what happens to somebody who guesses.

    python _test/test_rolling.py

Half of it is pure client maths: the two fields a host would otherwise make
guessable must come from the OS entropy pool. The other half boots a
throw-away server on port 45245 and lets a script knock on one room until the
anti-cracking cooloff slams the door - while a real guest with the link still
walks in. The real database is never touched.
"""
import base64, json, os, re, shutil, socket, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
HOST, PORT = "127.0.0.1", 45245

import vplan42 as vp                # noqa: E402
import test_client as tc            # noqa: E402
tc.HOST, tc.PORT = HOST, PORT
TClient, check = tc.TClient, tc.check


def boot():
    d = tempfile.mkdtemp(prefix="vlan42_roll_")
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


def dice_uses_secrets():
    """Take the OS pool away and see which door the dice actually knock on."""
    seen = []
    real = (vp.secrets.token_urlsafe, vp.secrets.choice, vp.secrets.randbelow)
    try:
        vp.secrets.token_urlsafe = lambda n: (seen.append(("bytes", n)), "X" * 32)[1]
        vp.secrets.choice = lambda seq: (seen.append(("pick", len(seq))), seq[0])[1]
        vp.secrets.randbelow = lambda n: (seen.append(("below", n)), 7)[1]
        vp.roll_password()
        vp.roll_name()
    finally:
        vp.secrets.token_urlsafe, vp.secrets.choice, vp.secrets.randbelow = real
    return seen == [("bytes", 24), ("pick", len(vp.NAME_WORDS)),
                    ("pick", len(vp.NAME_WORDS)), ("below", 900)], str(seen)


def client_checks():
    pwds = [vp.roll_password() for _ in range(300)]
    check("the password dice gives 32 url-safe characters",
          all(re.fullmatch(r"[A-Za-z0-9_-]{32}", p) for p in pwds), pwds[0])
    raw = base64.urlsafe_b64decode(pwds[0] + "=" * (-len(pwds[0]) % 4))
    check("one throw is 24 bytes = 192 bits", len(raw) == 24, str(len(raw)))
    check("no two throws ever match", len(set(pwds)) == len(pwds))
    pool, detail = dice_uses_secrets()
    check("the dice ask the OS pool, never random()", pool is True, detail)

    names = [vp.roll_name() for _ in range(200)]
    check("the name dice reads word-word-999",
          all(re.fullmatch(r"[a-z]+-[a-z]+-\d{3}", n) for n in names), names[0])
    check("every word comes from the list",
          all(n.split("-")[0] in vp.NAME_WORDS and n.split("-")[1] in vp.NAME_WORDS for n in names))
    check("the number is always three digits",
          all(100 <= int(n.rsplit("-", 1)[1]) <= 999 for n in names))
    check("names vary too", len(set(names)) > 150, str(len(set(names))))
    check("a name is short enough for the server", all(len(n) <= 32 for n in names))


def main():
    client_checks()

    proc, d = boot()
    try:
        host = register("anna")
        r = host.req("create_room", name=vp.roll_name(), pwd=vp.roll_password())
        check("a rolled room is accepted", r.get("ok"), str(r))
        room, code, pwd = r["room"], r["room"]["code"], r["room"]["pwd"]
        check("the room code is 8 hex digits", bool(re.fullmatch(r"[0-9a-f]{8}", code)), code)
        check("the invite link round-trips to code + password",
              vp.parse_invite(r["invite"]) == (code, pwd), str(r["invite"]))

        # a lazy host who types his own guessable password is stopped at 6 chars
        g = register("greg")
        r = g.req("create_room", name="second room", pwd="abc")
        check("a room password needs six characters", not r.get("ok")
              and "min 6" in str(r.get("err")), str(r))

        # ---- the cracker
        wrong = [g.req("join_room", code=code, pwd=f"guess{i}") for i in range(5)]
        check("five guesses each get the same plain no",
              all(not x.get("ok") for x in wrong)
              and len({x.get("err") for x in wrong}) == 1, str(wrong[-1]))
        r = g.req("join_room", code="ffffffff", pwd="whatever")
        check("a code that does not exist answers the same way",
              not r.get("ok") and r.get("err") == wrong[0]["err"], str(r))
        r = g.req("join_room", code=code, pwd=pwd)
        check("six misses in a row lock the account out",
              not r.get("ok") and "Too many wrong invites" in str(r.get("err")), str(r))
        check("the lock says how long to wait",
              bool(re.search(r"wait \d+s", str(r.get("err")))), str(r))
        other = register("zoe")
        r = other.req("join_room", code=code, pwd="not it")
        check("an honest account is not punished for it",
              not r.get("ok") and r.get("err") == wrong[0]["err"], str(r))
        q = host.req("join_list", room=room["id"])
        check("the locked-out guest never reached the queue",
              q.get("ok") and len(q.get("requests", [])) == 0, str(q))

        # ---- and somebody who mistypes but stops in time
        ivan = register("ivan")
        for i in range(3):
            ivan.req("join_room", code=code, pwd=f"typo{i}")
        r = ivan.req("join_room", code=code, pwd=pwd)
        check("three typos then the real link still opens the door",
              r.get("ok") and r.get("pending"), str(r))
        q = host.req("join_list", room=room["id"])
        check("the host sees exactly one knock",
              q.get("ok") and len(q.get("requests", [])) == 1, str(q))
        check("the host lets him in",
              host.req("join_resp", room=room["id"], user=ivan.user["id"], accept=True).get("ok"))
        st = ivan.drain_push("room_state", timeout=6)
        check("ivan is inside", st and st.get("room"), str(st)[:120])
        # a fresh miss after a hit starts the count over from one
        for i in range(4):
            ivan.req("join_room", code=code, pwd=f"again{i}")
        r = ivan.req("join_room", code=code, pwd=pwd)
        check("a good invite wipes the earlier misses",
              r.get("ok") and "Too many" not in str(r), str(r))

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
