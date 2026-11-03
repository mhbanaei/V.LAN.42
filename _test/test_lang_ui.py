# -*- coding: utf-8 -*-
"""English <-> Persian: every word and every edge has to turn around.

    python _test/test_lang_ui.py

The real window is built, signed in with a fake link and switched to Persian
for real. A string that only got translated half way, or a panel that stayed on
the wrong side of the screen, fails here.
"""
import ctypes, os, sys

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
    """The two words of the wordmark, however deep they are nested."""
    out = {}
    for c in parent.winfo_children():
        t = str(c.cget("text")) if isinstance(c, vp.Label) else ""
        if t in ("VLAN", "42"):
            out[t] = c
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
    word = halves(side)

    # 1. the app is built in English and everything hangs on the left
    check("signed in and reading English", vp.LANG[0] == "en" and app.page == "start")
    check("the side menu hugs the left edge", side.pack_info()["side"] == "left")
    check("tabs read English", tab_texts(app) == TABS, str(tab_texts(app)))
    check("the wordmark is VLAN then 42, left to right",
          set(word) == {"VLAN", "42"} and word["42"].pack_info()["side"] == "left"
          and word["42"].pack_info()["padx"] == (5, 0), str(word["42"].pack_info()))
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

    # 4. Persian: the geometry, mirrored for real
    check("the side menu moved to the right edge", side.pack_info()["side"] == "right")
    check("the wordmark now reads 42 then VLAN",
          word["42"].pack_info()["side"] == "right" and word["42"].pack_info()["padx"] == (0, 5),
          str(word["42"].pack_info()))
    anchors = [c.pack_info().get("anchor") for c in side.winfo_children()
               if isinstance(c, vp.Label) and c.pack_info().get("anchor")]
    check("anchor w became anchor e", anchors and set(anchors) == {"e"}, str(anchors))
    check("the space that followed a word now precedes it",
          app.lbl_acct_name.pack_info()["padx"] == (0, 7), str(app.lbl_acct_name.pack_info()["padx"]))
    tag = [c for c in side.winfo_children()
           if isinstance(c, vp.Label) and "شبکه" in str(c.cget("text"))][0]
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

    # 6. back to English: nothing is left behind
    app.set_lang("English")
    app.update_idletasks()
    check("English comes back complete", tab_texts(app) == TABS, str(tab_texts(app)))
    check("the side menu is on the left again", side.pack_info()["side"] == "left")
    check("the wordmark reads left to right again",
          word["42"].pack_info()["side"] == "left" and word["42"].pack_info()["padx"] == (5, 0))
    check("the late friend rows turn back too",
          rail_dot(app) is not None and rail_dot(app).pack_info()["side"] == "left",
          str(rail_dot(app).pack_info()) if rail_dot(app) else "no row")
    check("justify follows back", tag.cget("justify") == "left")
    app.layout_notes()
    check("the notice returns to the right corner", placed(note) == (1.0, "se"), str(placed(note)))
    check("the config file says English", vp.load_cfg().get("lang") == "en")

    app.drop_note(note)
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
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
