# -*- coding: utf-8 -*-
"""Headless checks for the tab bar, the branded panels and the friends chat.

    python _test/test_ui_tabs.py

The real window is built but kept invisible, so every tab, button and list row
the player uses is created and clicked for real. Only the network is faked.
"""
import ctypes, os, sys, time

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

    def req(self, t, **kw):
        self.sent.append((t, kw))
        if t == "friends":
            return {"t": t, "ok": True, **self.friends_payload}
        if t == "my_rooms":
            return {"t": t, "ok": True, "rooms": []}
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
    def __init__(self, rid=5, name="war room", role="owner"):
        self.rid, self.vip, self.running = rid, "10.77.0.7", True
        self.tx = self.rx = 0
        self.room = {"id": rid, "name": name, "my_role": role, "members": []}
        self.peers = {}

    def my_role(self):
        return self.room["my_role"]

    def update_state(self, room):
        self.room = room

    def stop(self):
        pass


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
    check("logo on the friends and logs headers",
          images(app.pg_friends) and images(app.pg_logs))
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

    # 12. Logs is a page too and carries the same header
    app.select_tab("logs")
    check("logs page with the brand header", app.page == "logs"
          and {"VLAN", "Logs"} <= set(labels(app.pg_logs))
          and "42" not in labels(app.pg_logs), str(labels(app.pg_logs)[:4]))
    app.q_put("a line for the log")
    app.tick()
    check("log lines land in the page", "a line for the log" in app.logbox.get("1.0", "end"))

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
    n2 = FakeNode()
    n2.srv_rtt = 21
    n2.room["members"] = [{"id": i + 10, "name": nm, "role": "member", "online": True,
                           "vip": f"10.77.0.{i + 10}"} for i, nm in enumerate(names)]
    n2.room["invite"] = ""
    app.node, app.room_name = n2, "war room"
    app.role_key = None
    app.update_room(n2)
    seen = [str(row[1].cget("text")) for row in app.rows.values()]   # built in list order
    check("players line up by name, top to bottom",
          seen == sorted(names, key=str.lower), str(seen))
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
