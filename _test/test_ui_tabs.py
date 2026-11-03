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
JUNK = ("vlan42.json", "vlan42.log", "vlan42_hang.txt", "vlan42.json.tmp")


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  OK  " if cond else " FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


class FakeLink:
    """Answers the control-channel calls the pages make and records what was sent."""

    def __init__(self):
        self.alive, self.sent = True, []
        self.delivered = True
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
        return {"t": t, "ok": True}

    def close(self):
        self.alive = False


class FakeNode:
    def __init__(self, rid=5, name="war room", role="owner"):
        self.rid, self.vip, self.running = rid, "10.77.0.7", True
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
    check("wordmark split in two colours", "V LAN" in labels(app.pg_start) and "42" in labels(app.pg_start))
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
          == ["Rooms", "Friends & Chat", "Room", "Logs"])
    check("no Logs/Friends/Logout buttons left on the page",
          not [b for b in buttons(app.pg_start)
               if b.cget("text") in ("Logs", "Friends", "Logout")])

    # 4. signing in shows the bar and lands on Rooms
    app.on_auth_ok({"link": FakeLink(), "remember": False, "server": "127.0.0.1:4242", "user": "042"})
    drain(app)
    check("tab bar shown after login", app.nav.winfo_manager() == "pack" and app.page == "start")
    check("account name on the bar", app.lbl_nav_acct.cget("text") == "042")
    check("Room tab hidden outside a room", app.tabs["room"][0].winfo_manager() == "")

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
    check("only the open tab looks selected", app.tabs["friends"][1].cget("border_color") == vp.ACC
          and app.tabs["start"][1].cget("border_color") == vp.CARD)

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
    check("unread shown on the friend row", "Chat (1)" in [b.cget("text") for b in buttons(app.fr_body)])
    [b for b in buttons(app.fr_body) if b.cget("text") == "Chat (1)"][0].invoke()
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
    app.node = None
    app.update_tabs()
    check("Room tab goes away with the room", app.tabs["room"][0].winfo_manager() == "")
    app.select_tab("room")
    check("clicking a stale Room tab falls back to Rooms", (app.tab, app.page) == ("start", "start"))

    # 12. Logs is a page too and carries the same header
    app.select_tab("logs")
    check("logs page with the brand header", app.page == "logs"
          and {"V LAN", "42", "Logs"} <= set(labels(app.pg_logs)))
    app.q_put("a line for the log")
    app.tick()
    check("log lines land in the page", "a line for the log" in app.logbox.get("1.0", "end"))

    # 13. every floating panel is branded
    top = ctk.CTkToplevel(app)
    top.withdraw()
    app.brand(top, "Admin panel")
    app.panel_head(top, "Roles and permissions")
    check("panel title uses the app name", top.title() == "V LAN 42 - Admin panel", top.title())
    check("panel header carries the wordmark",
          {"V LAN", "42", "Roles and permissions"} <= set(labels(top)), str(labels(top)))
    check("panel header carries the logo picture", bool(images(top)), str(labels(top)))
    top.destroy()

    # 14. logging out hides the bar and forgets the chats
    app.tab = "friends"
    app.logout()
    check("logout returns to the login page", app.page == "login" and app.nav.winfo_manager() == "")
    check("logout clears threads and unread", app.pms == {} and app.pm_unread == {}
          and app.sel_friend is None)
    check("logout clears the badge", app.tabs["friends"][2].winfo_manager() == "")

    app.closing = True
    for f in (app.logf, app.hangf):
        try:
            if f:
                f.close()
        except OSError:
            pass
    app.destroy()
    for junk in JUNK:
        try:
            os.remove(os.path.join(vp.APP_DIR, junk))
        except OSError:
            pass
    print(f"\nRESULT: {len(PASS)} passed, {len(FAIL)} failed")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
