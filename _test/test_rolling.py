# -*- coding: utf-8 -*-
"""The dice, the sealed invite code, and what happens to somebody who guesses.

    python _test/test_rolling.py

Half of it is plain maths on both sides: the room password must come from the OS
entropy pool, and an invite must come out of the server's own key - a code that
is a code, not a web link, and one nobody can build without the VPS. The other
half boots a throw-away server on port 45245 and lets a script knock on one room
until the anti-cracking cooloff slams the door, while a real guest holding the
code their friend pasted still walks in. The real database is never touched.
"""
import base64, json, os, re, secrets, shutil, socket, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
HOST, PORT = "127.0.0.1", 45245
SHAPE = re.compile(r"[A-Za-z0-9_-]{4}(\.[A-Za-z0-9_-]{1,4})+")
FORGE = "Abcd.Ef01.ghij.KLMN.opqr.STuv.Wxyz.01"

import vlan42_server as vs          # noqa: E402
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
    finally:
        vp.secrets.token_urlsafe, vp.secrets.choice, vp.secrets.randbelow = real
    return seen == [("bytes", 24)], str(seen)


def invite_checks():
    key, other = secrets.token_bytes(32), secrets.token_bytes(32)
    war = {"code": "1a2b3c4d", "pwd": "super-secret-9"}
    tok = vs.make_invite(war, key)
    check("an invite is a code, not a link",
          "://" not in tok and "http" not in tok and SHAPE.fullmatch(tok) is not None, tok)
    check("the server opens its own code into code + fingerprint",
          vs.open_invite(tok, key) == ("1a2b3c4d", vs.pwd_fp("super-secret-9")),
          str(vs.open_invite(tok, key)))
    check("a code sealed by another server is nothing", vs.open_invite(tok, other) is None)
    check("the password is not sitting inside the code",
          "super" not in tok and "secret" not in tok
          and b"super-secret-9" not in base64.urlsafe_b64decode(tok.replace(".", "") + "=="), tok)
    check("one wrong character seals the door",
          vs.open_invite(tok[:-4] + (".AAAA" if not tok.endswith(".AAAA") else ".BBBB"), key) is None)
    check("a made-up code of the right shape opens nothing", vs.open_invite(FORGE, key) is None)
    two = [vs.make_invite(war, key) for _ in range(2)]
    check("two invites for one room are never the same string", two[0] != two[1])
    check("and both of them still open the same door",
          all(vs.open_invite(t, key) == ("1a2b3c4d", vs.pwd_fp("super-secret-9")) for t in two))
    rolled = vs.make_invite({"code": "1a2b3c4d", "pwd": "a-wholly-new-one"}, key)
    check("a rolled password carries a different fingerprint",
          vs.open_invite(rolled, key)[1] != vs.open_invite(tok, key)[1])

    bare = tok.replace(".", "")
    check("the client reads a dotted code", vp.parse_invite(tok) == bare, tok)
    check("spaces and a leftover deep link still parse",
          vp.parse_invite(f"  {vp.INVITE_PFX}{tok.replace('.', ' ')} ") == bare)
    check("a word is not a code", vp.parse_invite("hello my friend") is None)
    check("an old invite link is not a code any more",
          vp.parse_invite(vp.INVITE_PFX
                          + base64.urlsafe_b64encode(b'{"c":"1a2b3c4d","p":"x"}').decode()) is None)


def client_checks():
    pwds = [vp.roll_password() for _ in range(300)]
    check("the password dice gives 32 url-safe characters",
          all(re.fullmatch(r"[A-Za-z0-9_-]{32}", p) for p in pwds), pwds[0])
    raw = base64.urlsafe_b64decode(pwds[0] + "=" * (-len(pwds[0]) % 4))
    check("one throw is 24 bytes = 192 bits", len(raw) == 24, str(len(raw)))
    check("no two throws ever match", len(set(pwds)) == len(pwds))
    pool, detail = dice_uses_secrets()
    check("the dice ask the OS pool, never random()", pool is True, detail)
    check("the room name is typed, so nothing rolls it", not hasattr(vp, "roll_name"))


def main():
    client_checks()
    invite_checks()

    proc, d = boot()
    try:
        host = register("anna")
        r = host.req("create_room", name="war room", pwd=vp.roll_password())
        check("a typed room name is accepted",
              r.get("ok") and r["room"]["name"] == "war room", str(r)[:120])
        room, code, pwd, invite = r["room"], r["room"]["code"], r["room"]["pwd"], r["invite"]
        check("the room code is 8 hex digits", bool(re.fullmatch(r"[0-9a-f]{8}", code)), code)
        check("the room payload carries a sealed code too",
              SHAPE.fullmatch(room.get("invite") or "") is not None, str(room.get("invite"))[:40])
        check("the code says nothing about the password", pwd not in invite, invite)

        # ---- a host who names his room two letters, or types a password of three
        greg = register("greg")
        r = greg.req("create_room", name="ab", pwd="a-perfectly-fine-one")
        check("a room name needs three characters",
              not r.get("ok") and "min 3" in str(r.get("err")), str(r))
        r = greg.req("create_room", name="second room", pwd="abc")
        check("a room password needs six characters",
              not r.get("ok") and "min 6" in str(r.get("err")), str(r))

        # ---- the cracker: six knocks in ten minutes and the door stops answering
        wrong = [greg.req("join_room", code=code, pwd=f"guess{i}") for i in range(5)]
        check("five guesses each get the same plain no",
              all(not x.get("ok") for x in wrong)
              and len({x.get("err") for x in wrong}) == 1, str(wrong[-1]))
        r = greg.req("join_room", code="ffffffff", pwd="whatever")
        check("a room that does not exist answers the same way",
              not r.get("ok") and r.get("err") == wrong[0]["err"], str(r))
        r = greg.req("join_room", inv=FORGE)
        check("six misses in a row lock the account out",
              not r.get("ok") and "Too many wrong invites" in str(r.get("err")), str(r))
        check("the lock says how long to wait",
              bool(re.search(r"wait \d+s", str(r.get("err")))), str(r))
        r = greg.req("join_room", code=code, pwd=pwd)
        check("even the right answer is refused while locked",
              not r.get("ok") and "Too many" in str(r.get("err")), str(r))
        zoe = register("zoe")
        r = zoe.req("join_room", inv=FORGE)
        check("a forged code is as plain a no as a wrong password",
              not r.get("ok") and r.get("err") == wrong[0]["err"], str(r))
        q = host.req("join_list", room=room["id"])
        check("not one of them ever reached the queue",
              q.get("ok") and len(q.get("requests", [])) == 0, str(q))

        # ---- and somebody who mistypes but stops in time
        ivan = register("ivan")
        for i in range(3):
            ivan.req("join_room", inv=invite[:-5] + f".{i}abc")
        r = ivan.req("join_room", inv=invite)
        check("three typos then the real code still opens the door",
              r.get("ok") and r.get("pending"), str(r))
        q = host.req("join_list", room=room["id"])
        knocks = [x for x in (q.get("requests") or []) if x.get("name") == "ivan"]
        check("the host sees exactly one knock from ivan",
              q.get("ok") and len(knocks) == 1, str(q))
        check("the host lets him in",
              host.req("join_resp", room=room["id"], user=ivan.user["id"], accept=True).get("ok"))
        st = ivan.drain_push("room_state", timeout=6)
        check("ivan is inside", st and st.get("room"), str(st)[:120])
        # a fresh miss after a hit starts the count over from one
        for i in range(4):
            ivan.req("join_room", code=code, pwd=f"again{i}")
        r = ivan.req("join_room", inv=invite)
        check("a good code wipes the earlier misses",
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
