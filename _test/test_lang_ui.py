# -*- coding: utf-8 -*-
"""English <-> Persian: every word and every edge has to turn around.

    python _test/test_lang_ui.py

The real window is built, signed in with a fake link and switched to Persian
for real. A string that only got translated half way, or a panel that stayed on
the wrong side of the screen, fails here.
"""
import ctypes, os, sys, time
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


def rail_rows(app):
    return app.fr_rail.winfo_children()


def rail_dot(app):
    """The online dot of the last friend row, wherever that row was rebuilt to now."""
    for c in reversed(rail_rows(app)):
        for k in c.winfo_children():
            if isinstance(k, vp.Label) and str(k.cget("text")) == "●":
                return k
    return None


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


def main():
    for junk in JUNK:
        try:
            os.remove(os.path.join(vp.APP_DIR, junk))
        except OSError:
            pass

    app = vp.App()
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

    # 5. rows built after the switch are mirrored too, without closing anything
    app.link.friends_payload = {"friends": [{"name": "sara", "online": True},
                                            {"name": "milad", "online": False}], "requests": []}
    app.friends = {"friends": app.link.friends_payload["friends"], "requests": []}
    app.rebuild_friends()
    app.mirror_t = 0
    app.tick()
    dot = rail_dot(app)
    check("two friend rows stand in the side menu", len(rail_rows(app)) == 2, str(rail_rows(app)))
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

    # 6. back to English: nothing is left behind
    app.set_lang("English")
    app.update_idletasks()
    check("English comes back complete",
          [t.split(" · ")[0] for t in tab_texts(app)] == TABS, str(tab_texts(app)))
    check("the side menu is on the left again", side.pack_info()["side"] == "left")
    check("the wordmark reads left to right again",
          word["42"].pack_info()["side"] == "left" and word["42"].pack_info()["padx"] == (6, 0))
    check("the late friend rows turn back too",
          rail_dot(app) is not None and rail_dot(app).pack_info()["side"] == "left",
          str(rail_dot(app).pack_info()) if rail_dot(app) else "no row")
    check("the player cards lead from the left again",
          app.rows[8][4].pack_info()["side"] == "left", str(app.rows[8][4].pack_info()))
    check("justify follows back", tag.cget("justify") == "left")
    check("English takes its own pen back",
          vp.FONT == vp.FONT_EN and pen(tag) == vp.FONT_EN, f"{vp.FONT} / {pen(tag)}")
    check("no widget is left in the Persian font", pens(app.pg_start) == {vp.FONT_EN},
          str(pens(app.pg_start)))
    app.layout_notes()
    check("the notice returns to the right corner", placed(note) == (1.0, "se"), str(placed(note)))
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
