# -*- coding: utf-8 -*-
"""Headless checks for the tab bar, the branded panels and the friends chat.

    python _test/test_ui_tabs.py

The real window is built but kept invisible, so every tab, button and list row
the player uses is created and clicked for real. Only the network is faked.
"""
import base64, ctypes, os, sys, time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ctypes.windll.shcore.SetProcessDpiAwareness(2)
import customtkinter as ctk  # noqa: E402
import vplan42 as vp         # noqa: E402

PASS, FAIL = [], []
JUNK = ("vlan42.json", "vlan42.json.tmp")      # the app leaves no log file behind


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  OK  " if cond else " FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


class FakeLink:
    """Answers the control-channel calls the pages make and records what was sent."""

    def __init__(self):
        self.alive, self.sent = True, []
        self.delivered = True
        self.user = {"id": 7, "username": "042"}
        self.friends_payload = {"friends": [], "requests": []}
        self.admin_rows = []          # what the management console is shown
        self.rooms = []               # what my_rooms answers with
        self.admin_ok = True
        self.pw = None                # what the server answers to a password change

    def req(self, t, **kw):
        self.sent.append((t, kw))
        if t == "friends":
            return {"t": t, "ok": True, **self.friends_payload}
        if t == "admin":
            if not self.admin_ok:
                return {"t": t, "ok": False, "err": "This is not the management console"}
            return {"t": t, "ok": True, "rows": list(self.admin_rows)}
        if t == "change_password":
            return dict(self.pw or {"t": t, "ok": True, "token": "a-brand-new-token"})
        if t == "my_rooms":
            return {"t": t, "ok": True, "rooms": list(self.rooms)}
        if t == "search":
            return {"t": t, "ok": True, "users": [{"name": "sara"}]}
        if t == "pm":
            return {"t": t, "ok": True, "ts": time.time(), "delivered": self.delivered}
        if t == "add_friend":
            return {"t": t, "ok": True, "accepted": False, **self.friends_payload}
        if t == "create_room":
            return {"t": t, "ok": False, "err": "only here to catch what was sent"}
        if t == "join_room":
            return {"t": t, "ok": False, "err": "Wrong invite code or room password"}
        return {"t": t, "ok": True}

    def close(self):
        self.alive = False

    def notify_server(self, t, **kw):
        if self.alive:
            self.sent.append((t, kw))


class FakeNode:
    """A room engine that only remembers, so switching rooms can be watched without
    touching Wintun, UDP or the server."""

    def __init__(self, link=None, room=None, log=None, ev=None,
                 rid=5, name="war room", role="owner"):
        self.room = room or {"id": rid, "name": name, "my_role": role, "members": []}
        self.rid, self.vip, self.running = self.room.get("id"), "10.77.0.7", True
        self.tx = self.rx = 0
        self.peers = {}
        self.started = self.stopped = False

    def my_role(self):
        return self.room["my_role"]

    def update_state(self, room):
        self.room = room

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


def flush(app, times=8):
    """Let every worker answer land before the next click, the way tick() does."""
    for _ in range(times):
        time.sleep(0.03)
        app.update_idletasks()
        while not app.uq.empty():
            app.on_event(app.uq.get_nowait())


def labels(w):
    out = []
    for c in w.winfo_children():
        try:
            if isinstance(c, ctk.CTkLabel):
                out.append(str(c.cget("text")))
        except Exception:
            pass
        out += labels(c)
    return out


def images(w):
    out = []
    for c in w.winfo_children():
        try:
            if isinstance(c, ctk.CTkLabel) and c.cget("image"):
                out.append(c)
        except Exception:
            pass
        out += images(c)
    return out


def buttons(w):
    out = []
    for c in w.winfo_children():
        try:
            if isinstance(c, ctk.CTkButton):
                out.append(c)
        except Exception:
            pass
        out += buttons(c)
    return out


def drain(app, secs=3.0):
    """Feed the worker threads' answers to the UI the way tick() does."""
    end, seen = time.time() + secs, 0
    while time.time() < end:
        app.update_idletasks()
        while not app.uq.empty():
            app.on_event(app.uq.get_nowait())
            seen += 1
        if seen:
            break
        time.sleep(0.02)
    return seen


def wait_sent(app, t, secs=3.0):
    """Wait for a request the worker thread put on the wire, then flush the log queue."""
    end = time.time() + secs
    while time.time() < end:
        if any(k == t for k, _ in app.link.sent):
            break
        time.sleep(0.02)
    app.tick()


def main():
    for junk in JUNK:
        try:
            os.remove(os.path.join(vp.APP_DIR, junk))
        except OSError:
            pass

    app = vp.App()
    app.update_idletasks()

    # 1. the app is called V LAN 42 and every visible string follows
    check("window title is the app name", app.title() == vp.APP_NAME == "V LAN 42", app.title())
    check("the logo is loaded in three sizes",
          app.logo_img is not None and app.nav_logo is not None and app.card_logo is not None)
    check("logo on the login card and the tab bar",
          images(app.pg_login) and images(app.nav))
    check("a page carries its own title, not a second copy of the mark",
          not images(app.pg_friends) and not images(app.pg_logs)
          and "reymit.ir/42level" in labels(app.pg_friends)
          and "reymit.ir/42level" in labels(app.pg_logs),
          str(labels(app.pg_friends)[:3]))
    check("the tab bar writes VLAN and lets the picture be the 42",
          "VLAN" in labels(app.nav) and "42" not in labels(app.nav) and images(app.nav),
          str(labels(app.nav)[:4]))
    check("the landing menu shows its mark once, with no second 42",
          "VLAN" in labels(app.pg_start) and "42" not in labels(app.pg_start),
          str(labels(app.pg_start)[:6]))
    twice = [n for n, page in (("rooms", app.pg_start), ("login", app.pg_login),
                               ("friends", app.pg_friends), ("logs", app.pg_logs),
                               ("room", app.pg_room), ("settings", app.pg_settings))
             if "42" in labels(page)]
    check("no page writes a 42 of its own next to the picture", not twice, str(twice))
    old = [t for w in (app.pg_start, app.pg_login, app.pg_friends, app.pg_logs, app.pg_room)
           for t in labels(w) if "V.Lan.42" in t]
    check("no panel still says V.Lan.42", not old, str(old))
    dead = [t for t in labels(app.pg_start)
            if "All traffic" in t or "Low, stable ping" in t or "Rooms, friends, roles" in t]
    check("the three bullets are gone", not dead, str(dead))

    # 2. login is a full page with the tab bar hidden, not a floating panel
    check("login page fills the window", app.pg_login.winfo_manager() == "pack"
          and app.body.winfo_manager() == "pack")
    check("tab bar hidden before login", app.nav.winfo_manager() == "")

    # 3. the bar carries the tabs, and Room only exists while inside a room
    check("tabs in order", [b.cget("text") for (_, b, _) in app.tabs.values()]
          == ["Rooms", "Friends", "Room", "Logs", "Settings"],
          str([b.cget("text") for (_, b, _) in app.tabs.values()]))
    sep = [t for t in labels(app.nav) if t == "|"]
    check("tabs split by green bars, never painted green", len(sep) == 4
          and app.tabs["start"][1].cget("fg_color") == "transparent", str(sep))
    check("no red circle sits on a tab before anything arrives",
          all(b.winfo_manager() == "" and str(b.cget("text")) == "" for (_, _, b) in app.tabs.values()),
          str([(k, b.winfo_manager(), b.cget("text")) for k, (_, _, b) in app.tabs.items()]))
    check("no Logs/Friends/Logout buttons left on the page",
          not [b for b in buttons(app.pg_start)
               if b.cget("text") in ("Logs", "Friends", "Logout")])

    # 4. signing in shows the bar and lands on Rooms
    app.on_auth_ok({"link": FakeLink(), "remember": False, "server": "127.0.0.1:4242", "user": "042"})
    drain(app)
    check("tab bar shown after login", app.nav.winfo_manager() == "pack" and app.page == "start")
    check("account name on the bar", app.lbl_nav_acct.cget("text") == "042")
    check("Room tab hidden outside a room", app.tabs["room"][0].winfo_manager() == "")

    # 4b. the host writes the room name; only the password comes from the dice
    check("the room name is an empty field you type yourself", app.h_room.value() == "",
          repr(app.h_room.value()))
    check("the password is already rolled when the page opens",
          len(app.h_pwd.get()) == 32 and app.h_room.value() == "", repr(app.h_pwd.get()))
    app.roll()
    check("the dice throws a 32-character password", len(app.h_pwd.get()) == 32,
          str(len(app.h_pwd.get())))
    check("the dice never names the room", app.h_room.value() == "")
    app.h_room.set("war room")
    first = app.h_pwd.get()
    app.roll()
    check("rolling again keeps your name and changes only the secret",
          app.h_room.value() == "war room" and app.h_pwd.get() != first, app.h_room.value())
    app.h_pwd.delete(0, "end")
    app.create_room()
    app.tick()
    check("a room without a password is stopped before the wire",
          not [kw for t, kw in app.link.sent if t == "create_room"], str(app.link.sent[-3:]))
    check("and it is said out loud", "Room name and password are required" in app.logbox.get("1.0", "end"),
          app.logbox.get("1.0", "end")[-90:])
    app.roll()
    app.create_room()
    wait_sent(app, "create_room")
    sent = [(t, kw) for t, kw in app.link.sent if t == "create_room"]
    check("creating sends the name exactly as typed",
          len(sent) == 1 and sent[0][1]["name"] == "war room", str(sent))
    check("with the rolled password beside it", sent and sent[0][1]["pwd"] == app.h_pwd.get(),
          str(sent[0][1] if sent else ""))

    # 4c. joining takes a sealed code, never a link the client can read
    app.g_link.delete(0, "end")
    app.g_link.insert("end", "vlan42://join/" + "abcd." * 15)
    app.join_link()
    wait_sent(app, "join_room")
    joined = [kw for t, kw in app.link.sent if t == "join_room"]
    check("an invite is sent as one sealed token, with no address or password in it",
          len(joined) == 1 and set(joined[0]) == {"inv"}, str(joined))
    check("the dots are stripped, the code itself is handed over unread",
          joined and joined[0]["inv"] == "abcd" * 15, str(joined[0]["inv"]) if joined else "")
    app.g_link.delete(0, "end")
    app.g_link.insert("end", "https://v42.ir/join/myroom")
    app.join_link()
    time.sleep(0.2)
    check("a web address is not an invite code",
          len([1 for t, kw in app.link.sent if t == "join_room"]) == 1, str(app.link.sent[-2:]))
    app.tick()
    check("and the join field says what belongs there",
          str(app.g_link.cget("placeholder_text")) == "xxxx.xxxx.xxxx...",
          str(app.g_link.cget("placeholder_text")))

    # 5. a friend request arrives as a notification on the Friends & Chat tab
    sara = {"name": "sara", "online": False}
    app.link.friends_payload = {"friends": [], "requests": [sara]}
    app.on_event({"t": "friend_req", "from": "sara"})
    check("a request makes the client re-read its list", ("friends", {}) in app.link.sent)
    app.on_event({"t": "friend_upd", "friends": [], "requests": [sara]})
    drain(app)
    app.tick()
    check("request counted on the tab badge", app.tabs["friends"][2].cget("text") == "1"
          and app.tabs["friends"][2].winfo_manager() == "pack")
    check("request written to the log", "sara sent you a friend request" in app.logbox.get("1.0", "end"))

    # 6. opening the tab lists it with Accept and Ignore
    app.select_tab("friends")
    check("tab click switches the page", app.page == "friends"
          and app.pg_friends.winfo_manager() == "pack" and app.pg_start.winfo_manager() == "")
    got = [b.cget("text") for b in buttons(app.fr_body)]
    check("request offers Accept and Ignore", "Accept" in got and "✕" in got, str(got))
    check("only the open tab looks selected",
          app.tabs["friends"][1].cget("fg_color") == vp.CARD2
          and app.tabs["friends"][1].cget("border_color") != vp.ACC
          and app.tabs["start"][1].cget("fg_color") == "transparent")

    # 7. accepting updates this side at once, from the answer alone
    app.friend_apply({"ok": True, "friends": [dict(sara, online=True)], "requests": []})
    app.link.friends_payload = {"friends": [dict(sara, online=True)], "requests": []}
    check("accept rebuilds the list without a poll", "sara  (online)" in " ".join(labels(app.fr_body)),
          " ".join(labels(app.fr_body)))
    check("badge cleared once nothing waits", app.tabs["friends"][2].winfo_manager() == "")

    # 8. chat: a line while looking away is counted, then read
    app.on_event({"t": "pm", "from": "sara", "text": "salam", "ts": time.time()})
    check("unread counted on the tab", app.pm_unread.get("sara") == 1
          and app.tabs["friends"][2].cget("text") == "1")
    dots = [c for c in app.fr_body.winfo_children() if isinstance(c, ctk.CTkFrame)]
    circ = [c for w in dots for c in w.winfo_children()
            if isinstance(c, ctk.CTkLabel) and c.cget("text") == "1" and c.cget("fg_color") == vp.RED]
    check("unread is a red circle with the number inside", bool(circ), str(dots))
    [b for b in buttons(app.fr_body) if b.cget("text") == "Chat"][0].invoke()
    check("opening the chat reads it and clears the badge",
          "salam" in app.pm_box.get("1.0", "end") and app.tabs["friends"][2].winfo_manager() == "")
    check("chat header names the friend", app.pm_title.cget("text") == "sara"
          and app.pm_state.cget("text") == "online")

    # 9. sending is confirmed by the server before the line appears
    app.pm_in.set(" سلام ")
    app.send_pm()
    drain(app)
    body = app.pm_box.get("1.0", "end")
    check("own answer rendered", "You" in body and "سلام" in body, repr(body[-90:]))
    check("own line kept in the thread", app.pms.get("sara") and app.pms["sara"][-1][0] == "You")
    app.link.delivered = False
    app.pm_in.set("you are away")
    app.send_pm()
    drain(app)
    app.tick()
    check("undelivered is said out loud", "not delivered" in app.logbox.get("1.0", "end"),
          app.logbox.get("1.0", "end")[-120:])
    app.link.delivered = True

    # 10. search adds friends through the same instant path
    app.do_search()
    drain(app)
    check("search results offer Add", "Add" in [b.cget("text") for b in buttons(app.fr_results)])
    buttons(app.fr_results)[0].invoke()
    drain(app)
    check("add friend sent with the name", ("add_friend", {"user": "sara"}) in app.link.sent,
          str(app.link.sent[-3:]))

    # 11. the room tab appears with a live node and carries its name
    app.node, app.room_name = FakeNode(), "war room"
    app.update_tabs()
    check("Room tab appears in its place", app.tabs["room"][0].winfo_manager() == "pack"
          and app.tabs["room"][1].cget("text") == "Room · war room")
    app.select_tab("room")
    check("room page shows the role", app.page == "room"
          and app.lbl_role.cget("text") == vp.ROLE_BADGE["owner"][0], str(app.lbl_role.cget("text")))

    # 11c. Players: one solid card per person, their ping on it, the line copies their IP
    n = app.node
    n.room["members"] = [{"id": 7, "name": "042", "role": "owner", "online": True, "vip": "10.77.0.1"},
                         {"id": 8, "name": "milad", "role": "member", "online": True, "vip": "10.77.0.2"},
                         {"id": 9, "name": "sara", "role": "member", "online": False, "vip": "10.77.0.3"}]
    n.peers = {8: {"id": 8, "name": "milad", "vip": "10.77.0.2", "online": True, "rtt": 34,
                   "timed_out": False, "last": time.time()},
               9: {"id": 9, "name": "sara", "vip": "10.77.0.3", "online": False, "rtt": None,
                   "timed_out": False, "last": time.time()}}
    n.srv_rtt = 21
    app.role_key = None
    app.update_room(n)
    app.update_idletasks()
    cards = [w for w in app.plist.winfo_children() if isinstance(w, ctk.CTkFrame)]
    check("every player gets a card of their own", len(cards) == 3, str(len(cards)))
    check("a card is one line tall, not a box",
          all(6 < c.winfo_reqheight() < 45 for c in cards),
          str([c.winfo_reqheight() for c in cards]))
    r7, nm7, info7, ping7, dot7 = app.rows[7]
    check("my own line says the round trip to the VPS", ping7.cget("text") == "21 ms",
          ping7.cget("text"))
    check("names are written plain, not bold", "bold" not in str(nm7.cget("font")),
          str(nm7.cget("font")))
    check("a friend's line carries his own ping", app.rows[8][3].cget("text") == "34 ms",
          app.rows[8][3].cget("text"))
    check("whoever is away is grey and says offline",
          app.rows[9][4].cget("text_color") == vp.GRAY and app.rows[9][3].cget("text") == "offline",
          f"{app.rows[9][4].cget('text_color')} {app.rows[9][3].cget('text')}")
    check("the header counts everyone present", app.lbl_count.cget("text") == "2 online",
          app.lbl_count.cget("text"))
    app.copy_peer_ip(7)
    check("clicking my own line copies my IP", app.clipboard_get() == "10.77.0.1",
          repr(app.clipboard_get()))
    app.copy_peer_ip(8)
    check("clicking a player copies his virtual IP", app.clipboard_get() == "10.77.0.2",
          repr(app.clipboard_get()))
    check("the copied line marks itself", str(app.rows[8][2].cget("text")) == "Copied ✓",
          repr(str(app.rows[8][2].cget("text"))))
    drain(app)
    app.tick()
    check("the copy is said out loud", "10.77.0.2 copied" in app.logbox.get("1.0", "end"),
          app.logbox.get("1.0", "end")[-90:])
    n.room["members"] = list(n.room["members"])       # same roster, so no row is rebuilt
    app.update_room(n)
    check("and the mark hands the IP back on the next word",
          str(app.rows[8][2].cget("text")) == "10.77.0.2", repr(str(app.rows[8][2].cget("text"))))

    # 11d. one person standing inside is still a room attached to the server
    members, peers = list(n.room["members"]), dict(n.peers)
    n.room["members"] = [m for m in members if m["id"] == 7]
    n.peers = {}
    app.role_key = None
    app.update_room(n)
    app.update_idletasks()
    check("a room of one says connected, not waiting",
          app.lbl_status.cget("text") == "● Connected", app.lbl_status.cget("text"))
    check("and counts the one who is inside", app.lbl_count.cget("text") == "1 online",
          app.lbl_count.cget("text"))
    check("the lonely card still shows the virtual IP", app.rows[7][2].cget("text") == "10.77.0.1",
          app.rows[7][2].cget("text"))
    n.room["members"], n.peers = members, peers
    app.role_key = None
    app.update_room(n)

    # 11b. "X is typing ..." on both the room chat and a private thread
    app.on_event({"t": "typing", "room": app.node.rid, "from": "sara"})
    app.on_event({"t": "typing", "room": app.node.rid, "from": "milad"})
    app.tick()
    check("two names become one typing line",
          app.lbl_typing.cget("text") == "milad and sara are typing ...",
          app.lbl_typing.cget("text"))
    app.on_event({"t": "typing", "room": 999, "from": "stranger"})
    app.tick()
    check("a typing note about another room is ignored",
          app.lbl_typing.cget("text") == "milad and sara are typing ...")
    app.typing_room["milad"] = time.time() - 1
    app.tick()
    check("the dots expire on their own", app.lbl_typing.cget("text") == "sara is typing ...",
          app.lbl_typing.cget("text"))
    app.sel_friend = "sara"
    app.on_event({"t": "typing", "from": "sara"})
    app.tick()
    check("the private thread has its own typing line",
          app.pm_typing.cget("text") == "sara is typing ...", app.pm_typing.cget("text"))
    app.sel_friend = None
    app.tick()
    check("closing the thread drops her typing line", app.pm_typing.cget("text") == "")
    app.note_typing("sara")
    app.note_typing("sara")
    check("typing is said on the wire, but never twice in a row",
          app.link.sent.count(("typing", {"user": "sara"})) == 1, str(app.link.sent[-3:]))
    app.note_typing()
    check("room typing goes out while inside a room", ("typing", {}) in app.link.sent,
          str(app.link.sent[-3:]))

    # ---- the sound a friend's message makes, and how big a notice may be
    heard = []
    real_play, real_ws, real_focus, real_sound = vp.play_file, vp.winsound, app.focused, vp.SOUND[0]
    vp.play_file = lambda p: (heard.append(p), True)[1]
    vp.winsound = type("W", (), {"SND_ALIAS": 1, "SND_ASYNC": 1,
                                 "PlaySound": lambda *a: heard.append("ding")})
    app.focused = lambda: True
    vp.SOUND[0] = True
    app.sel_friend = None
    app.pm_add("sara", "sara", "are you in?", ts=time.time())
    check("a friend's message plays the message sound",
          bool(heard) and str(heard[-1]).endswith(vp.SND_FILE), str(heard))
    heard.clear()
    app.pm_add("sara", "You", "yes", ts=time.time(), mine=True)
    check("your own words do not ring back at you", heard == [], str(heard))
    heard.clear()
    app.notify("Join request", "Waiting for the host of home")
    app.update_idletasks()
    check("any other notice keeps the plain ding", heard == ["ding"], str(heard))
    check("and a notice is one thin line, not a panel",
          app.hint.winfo_manager() == "pack" and app.hint.winfo_height() <= 44,
          str(app.hint.winfo_height()))
    check("it sits above the page instead of over it",
          app.nav.winfo_y() < app.hint.winfo_y() < app.body.winfo_y(),
          f"{app.nav.winfo_y()} / {app.hint.winfo_y()} / {app.body.winfo_y()}")
    check("the line says what it is, then the news",
          labels(app.hint)[:2] == ["Join request", "Waiting for the host of home"],
          str(labels(app.hint)[:3]))
    heard.clear()
    vp.SOUND[0] = False
    app.pm_add("milad", "milad", "hello?", ts=time.time())
    check("Message sound Off means silence", heard == [], str(heard))
    vp.play_file, vp.winsound, app.focused, vp.SOUND[0] = real_play, real_ws, real_focus, real_sound
    app.hide_hint()
    sent_room = app.link.sent.count(("typing", {}))
    app.node = None
    app.tick()
    check("leaving the room clears the room typing line", app.lbl_typing.cget("text") == "")
    app.note_typing()
    check("no room typing is sent without a room",
          app.link.sent.count(("typing", {})) == sent_room)
    app.tick()
    app.update_tabs()
    check("Room tab goes away with the room", app.tabs["room"][0].winfo_manager() == "")
    app.select_tab("room")
    check("clicking a stale Room tab falls back to Rooms", (app.tab, app.page) == ("start", "start"))

    # 12. Logs is a page too, titled once and thanking the supporters
    app.select_tab("logs")
    check("logs page with its own title and no second mark", app.page == "logs"
          and "Logs" in labels(app.pg_logs) and "VLAN" not in labels(app.pg_logs)
          and "42" not in labels(app.pg_logs), str(labels(app.pg_logs)[:4]))
    app.q_put("a line for the log")
    app.tick()
    check("log lines land in the page", "a line for the log" in app.logbox.get("1.0", "end"))

    # 12b. switching rooms, and the notice line that waits for a host
    room5 = {"id": 5, "name": "war room", "members": [], "my_role": "owner", "key": "00",
             "code": "AAA", "pwd": "p", "invite": "x", "limit": 16}
    room9 = {"id": 9, "name": "my room", "members": [], "my_role": "member", "key": "00",
             "code": "BBB", "pwd": "p", "invite": "y", "limit": 16}
    real_node, vp.VpsNode = vp.VpsNode, FakeNode
    try:
        app.on_my_rooms([room5, room9])
        app.link.rooms = [room5, room9]
        first = FakeNode(app.link, room5, lambda s: None, lambda e: None)
        first.started = True
        app.node, app.busy, app.tab, app.room_name = first, False, "room", "war room"
        app.link.sent.clear()
        app.enter_room(room9)
        flush(app)
        check("entering another room leaves the first one by itself", first.stopped, str(first.stopped))
        check("and takes the new room without a second click",
              bool(app.node) and app.node.rid == 9 and app.node.started,
              str(app.node and (app.node.rid, app.node.started)))
        app.tab = "start"
        app.show_page("start")
        app.update_start()
        check("the row of the room you are in says Open, not Enter",
              [str(r["enter"].cget("text")) for r in app.room_rows.values()] == ["Enter", "Open"],
              str([str(r["enter"].cget("text")) for r in app.room_rows.values()]))
        app.link.sent.clear()
        for where in ("friends", "start", "logs", "friends"):
            app.select_tab(where)
        check("visiting other tabs never asks the server to drop the room",
              app.node is not None and not any(t in ("deactivate", "logout")
                                               for t, _ in app.link.sent), str(app.link.sent[-3:]))
    finally:
        app.node, app.busy = None, False
        app.link.rooms = []
        vp.VpsNode = real_node
        app.show_page("start")

    app.on_event({"t": "join_pending", "name": "home", "msg": ""})
    check("the waiting line is shown while a host decides",
          app.hint.winfo_manager() == "pack" and app.hint_kind == "join", str(app.hint_kind))
    app.on_event({"t": "join_ok", "room": 9, "by": "sara", "name": "home"})
    check("and it goes away the moment the host lets you in",
          app.hint.winfo_manager() == "" and app.await_enter == 9, str(app.await_enter))
    app.on_event({"t": "join_pending", "name": "home", "msg": ""})
    app.on_event({"t": "join_no", "by": "sara"})
    check("a refusal takes the line away too", app.hint.winfo_manager() == "")
    app.await_enter = None

    # 12c. the columns: a chat that waits to be opened, and lines that can be dragged
    app.sel_friend = None
    app.select_tab("friends")
    check("no chat box before a friend is picked",
          app.fr_right.winfo_manager() == "" and app.fr_split.winfo_manager() == "",
          f"{app.fr_right.winfo_manager()} / {app.fr_split.winfo_manager()}")
    app.open_pm("sara")
    app.update_idletasks()
    check("picking a friend opens the chat and the line beside it",
          app.fr_right.winfo_manager() == "grid" and app.fr_split.winfo_manager() == "grid",
          str(app.fr_right.winfo_manager()))
    app.fr_split.apply(520)
    check("the drag line widens the list, so a long name is read whole",
          app.fr_w == 520 and app.fr_cols.grid_columnconfigure(0)["minsize"] == 520,
          str(app.fr_cols.grid_columnconfigure(0)["minsize"]))
    app.close_pm()
    check("closing the chat gives the whole page back to the list",
          app.fr_right.winfo_manager() == "" and app.fr_cols.grid_columnconfigure(0)["weight"] == 1,
          str(app.fr_cols.grid_columnconfigure(0)))

    app.set_room_w(460)
    check("the room page has the same drag line for its players column",
          app.room_left.cget("width") == 460 and app.room_split.winfo_manager() == "pack",
          str(app.room_left.cget("width")))
    slaves = app.room_left.pack_slaves()
    check("and its buttons are put down before the list can squeeze them out of sight",
          app.room_act.pack_info()["side"] == "bottom"
          and slaves.index(app.room_act) < slaves.index(app.room_pc),
          str([type(s).__name__ for s in slaves]))
    check("the room chat takes Ctrl+C and Ctrl+V like any other box",
          "<Control-Key>" in str(app.chatbox._textbox.bind("")),
          str(app.chatbox._textbox.bind())[:70])
    check("the friends chat does too",
          "<Control-Key>" in str(app.pm_box._textbox.bind("")))
    check("so does a friend's message line",
          "<Control-Key>" in str(app.pm_in._textbox.bind("")))
    check("and so does the room's own message line",
          "<Control-Key>" in str(app.chat_in._textbox.bind("")))

    # 13. every floating panel is branded
    top = ctk.CTkToplevel(app)
    top.withdraw()
    app.brand(top, "Admin panel")
    app.panel_head(top, "Roles and permissions")
    check("panel title uses the app name", top.title() == "V LAN 42 - Admin panel", top.title())
    check("panel header carries the wordmark once",
          {"VLAN", "Roles and permissions"} <= set(labels(top))
          and "42" not in labels(top), str(labels(top)))
    check("panel header carries the logo picture", bool(images(top)), str(labels(top)))
    top.destroy()

    # 14. logging out hides the bar and forgets the chats
    app.tab = "friends"
    app.logout()
    check("logout returns to the login page", app.page == "login" and app.nav.winfo_manager() == "")
    check("logout clears threads and unread", app.pms == {} and app.pm_unread == {}
          and app.sel_friend is None)
    check("logout clears the badge", app.tabs["friends"][2].winfo_manager() == "")

    # 15. lists read top to bottom by name, and nothing a player can read repeats
    #     the address of the network itself
    app.link = FakeLink()
    names = ["zed", "042", "milad", "aria"]
    roles = ["member", "member", "admin", "owner"]
    n2 = FakeNode()
    n2.srv_rtt = 21
    n2.room["members"] = [{"id": i + 10, "name": nm, "role": rl, "online": True,
                           "vip": f"10.77.0.{i + 10}"}
                          for i, (nm, rl) in enumerate(zip(names, roles))]
    n2.room["invite"] = ""
    app.node, app.room_name = n2, "war room"
    app.role_key = None
    app.update_room(n2)
    seen = [str(row[1].cget("text")) for row in app.rows.values()]   # built in list order
    check("players lead with the ranks: owner, admin, member", seen == ["aria", "milad", "042", "zed"],
          str(seen))
    # a rank that changes reorders the column on the next word from the server
    n2.room["members"][0]["role"] = "owner"      # zed takes the room over
    n2.room["members"][3]["role"] = "member"     # and aria steps down
    app.update_room(n2)
    seen = [str(row[1].cget("text")) for row in app.rows.values()]
    check("and the column follows a role that changed", seen == ["zed", "milad", "042", "aria"],
          str(seen))
    # inside one rank the names still read top to bottom, A to Z
    n2.room["members"] = [{"id": 20 + i, "name": nm, "role": "member", "online": True,
                           "vip": f"10.77.0.{20 + i}"} for i, nm in enumerate(names)]
    app.update_room(n2)
    seen = [str(row[1].cget("text")) for row in app.rows.values()]
    check("inside a rank the names line up", seen == sorted(names, key=str.lower), str(seen))
    app.link.friends_payload = {"friends": [{"name": nm, "online": True} for nm in names],
                                "requests": []}
    app.friends = {"friends": app.link.friends_payload["friends"], "requests": []}
    app.rebuild_friends()
    check("friends line up by name too",
          [t.split()[0] for t in labels(app.fr_body) if t.split()[0] in names]
          == sorted(names, key=str.lower), str(labels(app.fr_body)))

    # the invite code: the button copies, says so, and the live room state supplies it
    n2.room["invite"] = "QQQQ.WWWW.EEEE.RRRR"
    app.invite_text = ""
    app.update_room(n2)
    check("the room state hands the invite code to the button", app.invite_text == "QQQQ.WWWW.EEEE.RRRR",
          repr(app.invite_text))
    app.b_inv.invoke()
    check("and pressing it copies the code", app.clipboard_get() == "QQQQ.WWWW.EEEE.RRRR",
          repr(app.clipboard_get()))
    check("and the button says copied", str(app.b_inv.cget("text")) == "Copied ✓",
          repr(str(app.b_inv.cget("text"))))

    # the VPS address is the team's: no log line, error or report carries it
    vp.learn_net()
    addr = vp.VpsLink("203.0.113.10", 4242, lambda s: None)
    app.q_put(f"Connecting to {addr.host}:{addr.port} timed out")
    app.q_put("UDP relay ready (203.0.113.10)")
    app.err = vp.mask_net("Could not start: Connecting to v42.ir:4242 timed out after 12s")
    drain(app)
    app.tick()
    log = app.logbox.get("1.0", "end")
    check("no log line carries the server address",
          "203.0.113.10" not in log and "v42.ir" not in log and "4242" not in log, log[-140:])
    check("and the masked line still says what happened",
          "timed out" in log and "the network" in log, log[-140:])
    check("an error line is scrubbed too",
          "v42.ir" not in app.err and "4242" not in app.err, repr(app.err))
    check("a room IP is not scrubbed - the players need it",
          "10.77.0.12" in vp.mask_net("Your virtual IP: 10.77.0.12"),
          vp.mask_net("Your virtual IP: 10.77.0.12"))

    # ------------------------------------------------- a player's own password
    def pset(app, old="", new="", again=""):
        for e, v in ((app.p_old, old), (app.p_new, new), (app.p_again, again)):
            e.delete(0, "end")
            if v:
                e.insert(0, v)

    app.select_tab("settings")
    check("a signed-in account is offered the password card",
          app.pwd_card.winfo_manager() == "pack", app.pwd_card.winfo_manager())
    sent_before = len(app.link.sent)
    pset(app)
    app.b_pwd.invoke()
    check("an empty form asks for the words instead of sending them",
          len(app.link.sent) == sent_before and "Fill" in str(app.p_err.cget("text")),
          str(app.p_err.cget("text")))
    pset(app, "old-password", "new-password", "something else")
    app.b_pwd.invoke()
    check("two different new passwords are caught before the send",
          len(app.link.sent) == sent_before and "not match" in str(app.p_err.cget("text")),
          str(app.p_err.cget("text")))
    cfg = vp.load_cfg()
    cfg["token"] = "the old remember-me token"
    vp.save_cfg(cfg)
    app.link.pw = {"t": "change_password", "ok": False, "err": "Current password is wrong"}
    pset(app, "bad", "goodpassword", "goodpassword")
    app.b_pwd.invoke()
    drain(app)
    check("the server's no is shown in the card",
          "Current password is wrong" in str(app.p_err.cget("text")), str(app.p_err.cget("text")))
    check("and the saved session is left alone",
          vp.load_cfg().get("token") == "the old remember-me token")
    app.link.pw = {"t": "change_password", "ok": True, "token": "a-brand-new-token"}
    pset(app, "my-old-password", "goodpassword", "goodpassword")
    app.b_pwd.invoke()
    drain(app)
    check("the change is answered inside the card",
          "changed" in str(app.p_err.cget("text")).lower() or "✓" in str(app.p_err.cget("text")),
          str(app.p_err.cget("text")))
    check("the three boxes are emptied",
          not (app.p_old.get() or app.p_new.get() or app.p_again.get()))
    check("the button is clickable again", str(app.b_pwd.cget("state")) == "normal")
    check("remember-me carries on with the new password",
          vp.load_cfg().get("token") == "a-brand-new-token", str(vp.load_cfg()))

    # ------------------------------------------------- the team saying yes, live
    app.staff = False
    app.select_tab("settings")
    check("the settings page scrolls, so no card is ever out of reach",
          isinstance(app.set_body, ctk.CTkScrollableFrame)
          and app.team_card.master is app.set_body and app.pwd_card.master is app.set_body,
          str(app.team_card.master))
    check("and it thanks the people who pay for the servers",
          "reymit.ir/42level" in labels(app.pg_settings)
          and vp.REYMIT_URL == "https://reymit.ir/42level",
          str(labels(app.pg_settings)[:4]))
    check("a player sees no way into the panel", app.team_card.winfo_manager() == "",
          app.team_card.winfo_manager())
    app.on_event({"t": "staff", "on": True})
    app.update_idletasks()
    check("the card appears the moment the team vouches, without signing out",
          app.staff and app.team_card.winfo_manager() == "pack", app.team_card.winfo_manager())
    lines = []
    while not app.q.empty():
        lines.append(app.q.get_nowait())
    check("and the log says what changed",
          any("Management access" in l for l in lines), str(lines[-2:]))
    app.on_event({"t": "staff", "on": False})
    check("and it is taken away the same way",
          not app.staff and app.team_card.winfo_manager() == "")
    app.staff = True

    # ------------------------------------------------- the team's own console
    def find(w, cls, text=None, out=None):
        out = [] if out is None else out
        for c in w.winfo_children():
            if isinstance(c, cls) and (text is None or str(c.cget("text")) == text):
                out.append(c)
            find(c, cls, text, out)
        return out

    def order(app, names):
        return [t for t in labels(app.con_body) if t in names]

    def rows(app):
        return [c for c in app.con_body.winfo_children() if isinstance(c, ctk.CTkFrame)]

    NAMES3 = {"sara", "milad", "negar"}
    USERS = [{"id": 11, "name": "sara", "created": 1700000000.0, "last": 1700000600.0,
              "machine": "0123456789ab", "rooms": 2, "online": True, "bytes": 4096,
              "staff": False, "today": 1024, "room_ids": [5, 9]},
             {"id": 12, "name": "milad", "created": 1700000100.0, "last": 1700000900.0,
              "machine": "1020304050607", "rooms": 1, "online": False, "bytes": 512,
              "staff": True, "today": 512, "room_ids": [5]},
             {"id": 13, "name": "negar", "created": 1700000200.0, "last": 1700000000.0,
              "machine": "fedcba098765", "rooms": 0, "online": True, "bytes": 12288,
              "staff": False, "today": 0, "room_ids": []}]
    ROOMS = [{"id": 5, "name": "war room", "owner": "sara", "members": 2, "online": 1,
              "limit": 16, "created": 1700000000.0},
             {"id": 9, "name": "my room", "owner": "milad", "members": 1, "online": 1,
              "limit": 4, "created": 1700000050.0}]
    TRAFFIC = [{"id": 11, "name": "sara", "day": "2026-11-04", "bytes": 1024},
               {"id": 12, "name": "milad", "day": "2026-11-03", "bytes": 512}]
    app.link.admin_rows = USERS
    app.staff = True
    app.show_page("settings")
    check("the console card appears only for an account the team vouched for",
          app.team_card.winfo_manager() == "pack", app.team_card.winfo_manager())
    app.staff = False
    app.show_page("settings")
    check("and a plain player never sees the way in", app.team_card.winfo_manager() == "")
    app.staff = True
    app.show_page("settings")
    app.b_console.invoke()
    flush(app)
    check("the console opens on the user list",
          app.cwin.winfo_exists() and app.con_view == "Users", str(app.con_view))
    check("it asks the server, and carries a stamp with the ask",
          any(t == "admin" and kw.get("cmd") == "users" and "stamp" in kw
              for t, kw in app.link.sent), str(app.link.sent[-1]))
    check("the rows are on the table", order(app, NAMES3) == ["milad", "negar", "sara"],
          str(order(app, NAMES3)))
    head = [c for c in app.con_head.winfo_children() if isinstance(c, vp.Btn)]
    check("the header words sit over the columns they name",
          [app.con_head.grid_columnconfigure(i)["minsize"] for i in range(len(head))]
          == [rows(app)[0].grid_columnconfigure(i)["minsize"] for i in range(len(head))],
          str([app.con_head.grid_columnconfigure(i)["minsize"] for i in range(len(head))]))
    check("and the header is packed above the rows, not after them",
          app.con_head in app.cwin.pack_slaves()
          and app.cwin.pack_slaves().index(app.con_head)
          < app.cwin.pack_slaves().index(app.con_body._parent_frame),
          str([type(k).__name__ for k in app.cwin.pack_slaves()]))
    check("a team row is marked as team", "★" in labels(app.con_body))
    check("and an online one as online", "●" in labels(app.con_body))
    check("the volume is readable, not a byte count", "4.0KB" in labels(app.con_body),
          str(labels(app.con_body)))
    check("and a user line names the rooms they hold", "5, 9" in labels(app.con_body),
          str(labels(app.con_body)))
    check("every account can be moved into the team",
          len(find(app.con_body, ctk.CTkButton, "Make team")) == 2
          and len(find(app.con_body, ctk.CTkButton, "Remove from team")) == 1)
    sara = next(f for f in rows(app) if "sara" in labels(f))
    find(sara, ctk.CTkButton, "Make team")[0].invoke()
    flush(app)
    check("and clicking it says so to the server",
          any(t == "admin" and kw.get("cmd") == "set admin sara" for t, kw in app.link.sent),
          str(app.link.sent[-2:]))
    app.console_sort("bytes")
    check("a column header sorts the table", order(app, NAMES3) == ["milad", "sara", "negar"],
          str(order(app, NAMES3)))
    app.console_sort("bytes")
    check("clicking it again turns the order around",
          order(app, NAMES3) == ["negar", "sara", "milad"], str(order(app, NAMES3)))
    app.con_find.delete(0, "end")
    app.con_find.insert(0, "MIL")
    app.console_draw()
    check("and the search box narrows it", order(app, NAMES3) == ["milad"],
          str(order(app, NAMES3)))
    app.con_find.delete(0, "end")

    app.link.admin_rows = ROOMS
    app.set_admin_view("Rooms")
    flush(app)
    app.console_sort("id")
    def boxes(row):
        """The two typed cells of a room line: its name and how many players it may hold."""
        return find(row, ctk.CTkEntry)

    check("the room list is on the same table",
          app.con_view == "Rooms" and boxes(rows(app)[0])[0].get() == "war room",
          str(labels(app.con_body)))
    check("a room line carries a name box and a ceiling box",
          len(find(app.con_body, ctk.CTkEntry)) == 2 * len(ROOMS),
          str(len(find(app.con_body, ctk.CTkEntry))))
    nm0, lim0 = boxes(rows(app)[0])
    check("and both are typed in the row itself", (nm0.get(), lim0.get()) == ("war room", "16"),
          str((nm0.get(), lim0.get())))
    sent_before = len(app.link.sent)
    lim0.delete(0, "end")
    lim0.insert(0, "7")
    nm0.delete(0, "end")
    nm0.insert(0, "home team")
    find(rows(app)[0], ctk.CTkButton, "Save")[0].invoke()
    flush(app)
    cmds = [kw.get("cmd") for t, kw in app.link.sent[sent_before:] if t == "admin"]
    check("saving renames the room and retunes its ceiling in one go",
          "set room 5 home team" in cmds and "set limit 5 7" in cmds, str(cmds))
    sent_before = len(app.link.sent)
    boxes(rows(app)[0])[1].delete(0, "end")
    boxes(rows(app)[0])[1].insert(0, "nope")
    find(rows(app)[0], ctk.CTkButton, "Save")[0].invoke()
    flush(app)
    check("a number that is not one is stopped at the door",
          len(app.link.sent) == sent_before and app.hint.winfo_manager() == "pack"
          and "2 to 64" in " ".join(labels(app.hint)), str(labels(app.hint)))
    app.hide_hint()
    sent_before = len(app.link.sent)
    d = find(rows(app)[0], ctk.CTkButton, "Delete")[0]
    d.invoke()
    check("deleting a room asks first instead of just doing it",
          str(d.cget("text")) == "Sure?" and len(app.link.sent) == sent_before,
          str(d.cget("text")))
    d.invoke()
    flush(app)
    check("and only the second click says so to the server",
          any(t == "admin" and kw.get("cmd") == "remove room 5" for t, kw in app.link.sent),
          str(app.link.sent[-2:]))

    app.link.admin_rows = TRAFFIC
    app.set_admin_view("Traffic")
    flush(app)
    check("the traffic view lists the days players moved data",
          "2026-11-03" in labels(app.con_body) and "512B" in labels(app.con_body),
          str(labels(app.con_body)))
    app.link.admin_ok = False
    app.set_admin_view("Users")
    flush(app)
    check("and a server that says no is answered in plain words",
          "management console" in str(app.con_note.cget("text")), str(app.con_note.cget("text")))
    app.link.admin_ok = True
    app.cwin.destroy()
    app.cwin = None

    # the stamp is the whole identity of the console, so a player's copy must not make one
    real_res = vp.res_path
    key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp_team.key")
    try:
        with open(key_file, "w", encoding="utf-8") as f:
            f.write("0" * 64)
        vp.res_path = lambda name: key_file if name == vp.STAFF_FILE else real_res(name)
        got = vp.staff_stamp()
        raw = base64.urlsafe_b64decode(got + "=" * (-len(got) % 4))
        win = int(AESGCM(bytes.fromhex("0" * 64)).decrypt(raw[:12], raw[12:], vp.STAFF_AAD))
        check("a PC with the team's key makes a stamp", bool(got) and abs(
            win - int(time.time() // vp.STAFF_WINDOW)) <= 1, str(win))
        vp.res_path = lambda name: None if name == vp.STAFF_FILE else real_res(name)
        check("and a player's copy, which has no such file, makes nothing at all",
              vp.staff_stamp() == "", repr(vp.staff_stamp()))
    finally:
        vp.res_path = real_res
        try:
            os.remove(key_file)
        except OSError:
            pass

    app.closing = True
    if app.hangf:
        app.hangf.close()
    app.destroy()
    for junk in JUNK:
        try:
            os.remove(os.path.join(vp.APP_DIR, junk))
        except OSError:
            pass
    try:
        os.remove(vp.HANG_FILE)
    except OSError:
        pass
    check("a run leaves no log file next to the app",
          not os.path.exists(os.path.join(vp.APP_DIR, "vlan42.log"))
          and not os.path.exists(os.path.join(vp.APP_DIR, "vlan42_server.log")))
    print(f"\nRESULT: {len(PASS)} passed, {len(FAIL)} failed")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
