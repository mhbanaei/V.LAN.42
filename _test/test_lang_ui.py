# -*- coding: utf-8 -*-
"""English <-> Persian: every word and every edge has to turn around.

    python _test/test_lang_ui.py

The real window is built, signed in with a fake link and switched to Persian
for real. A string that only got translated half way, or a panel that stayed on
the wrong side of the screen, fails here.
"""
import ctypes, os, re, sys, time
import tkinter.font as tkfont

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
ctypes.windll.shcore.SetProcessDpiAwareness(2)
import vplan42 as vp          # noqa: E402
import test_ui_tabs as tu     # noqa: E402

PASS, FAIL = [], []
JUNK = tu.JUNK
TABS = ["Rooms", "Friends", "Room", "Logs", "Settings"]


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  OK  " if cond else " FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def tab_texts(app):
    return [str(b.cget("text")) for (_, b, _) in app.tabs.values()]


def halves(parent):
    """The two pieces of the wordmark - the word and the picture that is the 42 -
    however deep they are nested."""
    out = {}
    for c in parent.winfo_children():
        t = str(c.cget("text")) if isinstance(c, vp.Label) else ""
        if t == "VLAN":
            out["VLAN"] = c
        elif isinstance(c, vp.Label) and not t and c.cget("image"):
            out["42"] = c
        else:
            out.update(halves(c))
    return out


def friend_rows(app):
    return [c for c in app.fr_body.winfo_children() if isinstance(c, vp.ctk.CTkFrame)]


def friend_dot(app):
    """The online dot of the last friend row, wherever that row was rebuilt to now."""
    for c in reversed(friend_rows(app)):
        for k in c.winfo_children():
            if isinstance(k, vp.Label) and str(k.cget("text")) == "●":
                return k
    return None


def vorder(w):
    """The vertical order a column packs its children in, read off their positions - the
    mirror has to keep it, because pack puts anything it re-packs at the end of the stack."""
    out = []
    for c in w.winfo_children():
        if c.winfo_manager() == "pack":
            out.append((c.winfo_y(), id(c)))
    return [i for _, i in sorted(out)]


def settle(app, times=4):
    """Let Tk actually place everything, so a position read is a position and not a stale one."""
    for _ in range(times):
        app.update_idletasks()
        app.update()
        time.sleep(0.02)


def placed(card):
    info = card.place_info()
    return float(info["relx"]), info["anchor"]


def pen(w):
    """The font family one widget was actually handed."""
    try:
        f = w.cget("font")
    except Exception:
        return ""
    if isinstance(f, vp.ctk.CTkFont):
        return str(f.cget("family"))
    if isinstance(f, (tuple, list)) and f:
        return str(f[0])
    return ""


def pens(parent):
    out = set()
    for c in parent.winfo_children():
        p = pen(c)
        if p:
            out.add(p)
        out |= pens(c)
    return out


def managed(app):
    """Every widget on screen by its Tk path, with the manager that holds it. A language
    switch must never take that away: a widget without a manager is drawn nowhere, which is
    how a Persian word used to simply disappear."""
    out = {}

    def walk(w, path):
        for c in w.winfo_children():
            p = path + "/" + c._w
            out[p] = c.winfo_manager()
            walk(c, p)
    walk(app, "main")
    return out


def lost(before, after):
    return [p for p, m in before.items() if m and after.get(p, m) == ""]


def main():
    for junk in JUNK:
        try:
            os.remove(os.path.join(vp.APP_DIR, junk))
        except OSError:
            pass

    app = vp.App()
    app.geometry("1100x720+30+30")
    app.update_idletasks()

    # signed in, so the landing page and its side menu are really on screen
    app.link = tu.FakeLink()
    app.link.friends_payload = {"friends": [{"name": "sara", "online": True}], "requests": []}
    app.on_auth_ok({"link": app.link, "remember": False, "server": "v42.ir:4242", "user": "042"})
    tu.drain(app)
    app.update_idletasks()
    side = app.pg_start.winfo_children()[0]
    word = halves(app.nav)

    # 1. the app is built in English and everything hangs on the left
    check("signed in and reading English", vp.LANG[0] == "en" and app.page == "start")
    check("the side menu hugs the left edge", side.pack_info()["side"] == "left")
    check("tabs read English", tab_texts(app) == TABS, str(tab_texts(app)))
    check("the wordmark is VLAN then the 42 picture, left to right",
          set(word) == {"VLAN", "42"} and word["42"].pack_info()["side"] == "left"
          and word["42"].pack_info()["padx"] == (6, 0), str(word["42"].pack_info()))
    check("the big mark in the menu is not followed by a second 42",
          "42" not in tu.labels(side) and "VLAN" in tu.labels(side), str(tu.labels(side)[:6]))
    note = app.notify("Test", "hello")
    app.layout_notes()
    check("a notice lands bottom-right in English", placed(note) == (1.0, "se"), str(placed(note)))

    # 2. the language control is a real setting, not a decoration
    app.select_tab("settings")
    check("the settings page exists with a language switch",
          app.page == "settings" and app.seg_lang.cget("values") == ["English", "فارسی"])
    check("the language button sits on the left in English",
          app.seg_lang.pack_info()["side"] == "left")
    app.select_tab("start")

    settle(app)
    held = managed(app)          # English arrangement, before anything turns around
    stood = vorder(side)         # and the order the landing menu packs its column in
    app.seg_lang.set("فارسی")
    app.set_lang(app.seg_lang.get())
    app.update_idletasks()

    # 3. Persian: the words
    check("the app is in Persian now", vp.LANG[0] == "fa")
    fa = tab_texts(app)
    check("every tab carries its Persian name",
          fa == [vp.T(x) for x in TABS] and all(vp.has_rtl(t) for t in fa), str(fa))
    check("the tagline is Persian", any("شبکه" in t for t in tu.labels(app.pg_start)),
          str(tu.labels(app.pg_start)[:6]))
    check("a hidden page is translated too",
          any("فارسی" in t for t in tu.labels(app.pg_settings)), str(tu.labels(app.pg_settings)[:6]))
    check("the language button stayed on the choice you clicked", app.seg_lang.get() == "فارسی")
    check("the choice is remembered in the config file", vp.load_cfg().get("lang") == "fa")

    # 3b. Persian: the pen - a font that exists here and can draw Arabic letters
    have = {n.lower() for n in tkfont.families(app)}
    tag = [c for c in side.winfo_children()
           if isinstance(c, vp.Label) and "شبکه" in str(c.cget("text"))][0]
    check("the Persian pen is picked from the installed list, in order",
          app.fa_font.lower() == next((f for f in vp.FA_FONTS if f.lower() in have), "").lower(),
          str(app.fa_font))
    check("the pen the app writes with is on this machine", vp.FONT.lower() in have, str(vp.FONT))
    check("every word on the landing page switched pen", pens(app.pg_start) == {vp.FONT},
          str(pens(app.pg_start)))
    check("the tagline is drawn in the Persian font", pen(tag) == vp.FONT, pen(tag))

    # 4. Persian: the geometry, mirrored for real
    check("the side menu moved to the right edge", side.pack_info()["side"] == "right")
    settle(app)
    check("the menu keeps its column order in Persian", vorder(side) == stood,
          f"{len(vorder(side))} vs {len(stood)}")
    check("the wordmark now reads the 42 picture then VLAN",
          word["42"].pack_info()["side"] == "right" and word["42"].pack_info()["padx"] == (0, 6),
          str(word["42"].pack_info()))
    anchors = [c.pack_info().get("anchor") for c in side.winfo_children()
               if isinstance(c, vp.Label) and c.pack_info().get("anchor")]
    check("anchor w became anchor e", anchors and set(anchors) == {"e"}, str(anchors))
    check("the space that followed a word now precedes it",
          app.lbl_acct_name.pack_info()["padx"] == (0, 7), str(app.lbl_acct_name.pack_info()["padx"]))
    check("Persian text is right-justified", tag.cget("justify") == "right", tag.cget("justify"))
    app.layout_notes()
    check("a notice lands bottom-left in Persian", placed(note) == (0.0, "sw"), str(placed(note)))
    app.select_tab("settings")
    check("a page that was hidden turns around when it appears",
          app.seg_lang.pack_info()["side"] == "right")
    app.select_tab("start")

    # 4c. the mirror must move words, never erase them
    gone = lost(held, managed(app))
    check("turning to Persian leaves every widget held by a manager", not gone, str(gone[:4]))
    check("the mirror only ever names options the manager takes",
          all(set(vp.mirror_of({"side": "left", "anchor": "w", "sticky": "ew",
                               "column": 0, "padx": (4, 0)}, m, True, 2)) <= vp._OPTS[m]
              for m in ("pack", "grid", "place")))
    check("a scroll list keeps its own glass where customtkinter put it",
          app.plist._parent_canvas.winfo_manager() == "grid"
          and int(app.plist._parent_canvas.grid_info()["column"]) == 0,
          str(app.plist._parent_canvas.grid_info()))

    # 4d. a room row is built on a grid, so its columns and its slack both cross over
    app.on_my_rooms([{"id": 7, "name": "my room", "my_role": "owner", "limit": 8,
                      "members": [{"id": 7, "name": "042", "role": "owner",
                                   "online": True, "vip": "10.77.0.1"}]}])
    app.mirror_t = 0
    app.tick()
    for _ in range(4):
        app.update_idletasks()
        app.update()
    rr, seen = app.room_rows[7], {}
    for key in ("mark", "name", "info", "host", "enter"):
        if key in rr and hasattr(rr[key], "grid_info"):
            seen[key] = int(rr[key].grid_info()["column"])
    check("the room row keeps its words on the grid",
          rr["name"].winfo_manager() == "grid" and rr["enter"].winfo_manager() == "grid",
          str((rr["name"].winfo_manager(), rr["enter"].winfo_manager())))
    check("the room row's mark leads from the far side",
          seen["mark"] == max(seen.values()) and seen["enter"] == min(seen.values()), str(seen))
    check("the column that stretches crosses over with its words",
          int(rr["frame"].grid_columnconfigure(seen["name"])["weight"]) == 1
          and int(rr["frame"].grid_columnconfigure(seen["mark"])["weight"]) == 0,
          str({c: rr["frame"].grid_columnconfigure(c)["weight"] for c in range(4)}))
    check("the room row is still on screen in Persian",
          rr["frame"].winfo_manager() == "pack" and rr["name"].winfo_ismapped(),
          str((rr["frame"].winfo_manager(), rr["name"].winfo_ismapped())))

    # 5. rows built after the switch are mirrored too, without closing anything.
    #    Friends live on their own tab only - the landing menu keeps no list of them.
    check("the landing menu carries no friend list",
          not hasattr(app, "fr_rail") and not hasattr(app, "rail_rows"))
    app.link.friends_payload = {"friends": [{"name": "sara", "online": True},
                                            {"name": "milad", "online": False}], "requests": []}
    app.friends = {"friends": app.link.friends_payload["friends"], "requests": []}
    app.select_tab("friends")
    app.rebuild_friends()
    app.mirror_t = 0
    app.tick()
    dot = friend_dot(app)
    check("two friend rows stand on the Friends page", len(friend_rows(app)) == 2,
          str(friend_rows(app)))
    check("a friend row built after the switch is mirrored by the next tick",
          dot is not None and dot.pack_info()["side"] == "right",
          str(dot.pack_info()) if dot else "no row")
    check("the tabs are still Persian after a rebuild",
          all(vp.has_rtl(t) for t in tab_texts(app) if t != "Room"), str(tab_texts(app)))

    # 5b. the Players cards stand in a Persian line too
    n = tu.FakeNode()
    n.room["members"] = [{"id": 7, "name": "042", "role": "owner", "online": True, "vip": "10.77.0.1"},
                         {"id": 8, "name": "milad", "role": "member", "online": True, "vip": "10.77.0.2"}]
    n.peers = {8: {"id": 8, "name": "milad", "vip": "10.77.0.2", "online": True, "rtt": 34,
                   "timed_out": False, "last": time.time()}}
    n.srv_rtt = 21
    app.node, app.room_name = n, "war room"
    app.select_tab("room")
    app.update_room(n)
    app.mirror_t = 0
    app.tick()
    card, _, _, ping, dot = app.rows[8]
    check("a Persian player card is still one line tall", card.winfo_reqheight() < 45,
          str(card.winfo_reqheight()))
    check("the status dot leads the line from the right", dot.pack_info()["side"] == "right",
          str(dot.pack_info()))
    check("the ping waits at the far left", ping.pack_info()["side"] == "left",
          str(ping.pack_info()))

    # 5c. the log and the chat are plain text boxes - their lines are translated as they land
    app.q_put("Left the room")
    app.chat_add("system", "Not connected", "sys")
    app.chat_add("milad", "Left the room", "them")     # what a player typed stays as typed
    app.tick()
    log = app.logbox.get("1.0", "end")
    chat = app.chatbox.get("1.0", "end")
    check("the log answers in Persian", "از اتاق خارج شدید" in log, log[-60:])
    check("a system line in the chat is Persian", "متصل نیستید" in chat, chat[-60:])
    check("another player's own words are never rewritten", "Left the room" in chat, chat[-60:])

    # 5d. Persian sentences put the thing before its count, or Tk drops the count off the end
    lead = re.compile(r"^\s*(?:[۰-۹0-9]|\{(?:n|m|o|on|total|limit|count)\})")
    opens = [k for k, v in vp.TR.items() if v and lead.match(v)]
    check("no Persian line opens with a number", not opens, str(opens[:3]))

    # 5e. and nothing on a Persian screen stayed English. "English" itself is the name the
    # language switch offers, in its own tongue; the notice is a message somebody typed.
    NAMES = {"VLAN", "English", "Test", "hello", "sara", "milad", "negar", "042",
             "war room", "my room", "friend room"}

    def shown(w, out):
        for c in w.winfo_children():
            try:
                t = str(c.cget("text")).strip()
            except Exception:
                t = ""
            if t and not isinstance(c, vp.ctk.CTkEntry):
                out.add(t)
            shown(c, out)
        return out

    def is_english(t):
        if t in NAMES or vp.has_rtl(t):
            return False
        if re.search(r"^[0-9.,: /\-↑↓]+(ms|KB/s|MB/s)[0-9.,: /\-↑↓msKB]*$", t):
            return False                      # a number with its unit is not a word
        return bool(re.search(r"[A-Za-z]{3,}", t))

    app.select_tab("room")
    app.show_admin()
    app.update_idletasks()
    on_screen = sorted(t for t in shown(app, set()) if is_english(t))
    if app.awin and app.awin.winfo_exists():
        on_screen += [t for t in sorted(shown(app.awin, set())) if is_english(t)]
        app.set_admin_tab("Role defaults")
        settle(app)
        on_screen += [t for t in sorted(shown(app.awin, set())) if is_english(t)]
    check("a Persian screen holds no English word", not on_screen, str(on_screen[:4]))
    if app.awin and app.awin.winfo_exists():
        app.awin.destroy()
        app.awin = None

    # 5f. the team's own pages: the password card in Settings and the console table
    app.staff = True
    app.select_tab("settings")
    settle(app)
    leak = [t for t in shown(app.pg_settings, set()) if is_english(t)]
    check("the password card and the console card speak Persian", not leak, str(leak[:4]))
    rows_in = [{"id": 11, "name": "sara", "created": 1700000000.0, "last": 1700000600.0,
                "machine": "0123456789ab", "rooms": 1, "online": True, "bytes": 4096,
                "staff": False, "today": 4096},
               {"id": 12, "name": "milad", "created": 1700000100.0, "last": 1700000900.0,
                "machine": "1020304050607", "rooms": 0, "online": False, "bytes": 512,
                "staff": True, "today": 512}]
    app.link.admin_rows = rows_in
    app.show_console()
    tu.drain(app)                 # the table is only worth mirroring once its rows landed
    settle(app)
    app.mirror_t = 0
    app.tick()                    # the tick that moves fresh rows to the Persian side
    app.update_idletasks()
    leak = [t for t in shown(app.cwin, set()) if is_english(t)]
    check("the management console speaks Persian too", not leak, str(leak[:4]))
    first = [c for c in app.con_body.winfo_children() if isinstance(c, vp.ctk.CTkFrame)][0]
    xs = [c.winfo_x() for c in first.winfo_children() if isinstance(c, vp.Label)]
    check("the Persian table reads from the right", xs and xs == sorted(xs, reverse=True), str(xs))
    check("and mirroring left both rows standing",
          len([c for c in app.con_body.winfo_children() if isinstance(c, vp.ctk.CTkFrame)]) == 2,
          str(len(app.con_body.winfo_children())))
    first = [c for c in app.con_body.winfo_children() if isinstance(c, vp.ctk.CTkFrame)][0]
    slaves = app.cwin.pack_slaves()
    check("the header stays above the rows after the turn",
          slaves.index(app.con_head) < slaves.index(app.con_body._parent_frame),
          str([type(k).__name__ for k in slaves]))
    hd = [c for c in app.con_head.winfo_children() if isinstance(c, vp.Btn)]
    cells = [c for c in first.winfo_children() if isinstance(c, vp.Label)]
    hx = [c.winfo_x() for c in hd]
    cx = [c.winfo_x() for c in cells]
    check("the Persian header keeps the table's own columns",
          hx == sorted(hx, reverse=True) and cx == sorted(cx, reverse=True)
          and all(vp.has_rtl(str(b.cget("text"))) for b in hd),
          f"{hx} / {cx}")
    check("and its own count is said in Persian too",
          vp.has_rtl(str(app.con_note.cget("text"))), str(app.con_note.cget("text")))
    check("the console's note line reads from the right",
          app.con_note.cget("anchor") == "e", str(app.con_note.cget("anchor")))

    app.cwin.destroy()
    app.cwin = None

    # 6. back to English: nothing is left behind
    fa_seen = managed(app)
    app.set_lang("English")
    app.update_idletasks()
    check("turning back to English leaves every widget held too",
          not lost(fa_seen, managed(app)), str(lost(fa_seen, managed(app))[:4]))
    check("English comes back complete",
          [t.split(" · ")[0] for t in tab_texts(app)] == TABS, str(tab_texts(app)))
    check("the side menu is on the left again", side.pack_info()["side"] == "left")
    check("the wordmark reads left to right again",
          word["42"].pack_info()["side"] == "left" and word["42"].pack_info()["padx"] == (6, 0))
    check("the late friend rows turn back too",
          friend_dot(app) is not None and friend_dot(app).pack_info()["side"] == "left",
          str(friend_dot(app).pack_info()) if friend_dot(app) else "no row")
    check("the player cards lead from the left again",
          app.rows[8][4].pack_info()["side"] == "left", str(app.rows[8][4].pack_info()))
    check("justify follows back", tag.cget("justify") == "left")
    check("English takes its own pen back",
          vp.FONT == vp.FONT_EN and pen(tag) == vp.FONT_EN, f"{vp.FONT} / {pen(tag)}")
    check("no widget is left in the Persian font", pens(app.pg_start) == {vp.FONT_EN},
          str(pens(app.pg_start)))
    app.layout_notes()
    check("the notice returns to the right corner", placed(note) == (1.0, "se"), str(placed(note)))
    settle(app)
    check("the menu keeps its column order in English too", vorder(side) == stood,
          f"{len(vorder(side))} vs {len(stood)}")
    check("the config file says English", vp.load_cfg().get("lang") == "en")

    app.drop_note(note)
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
    print(f"\nRESULT: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
