# -*- coding: utf-8 -*-
"""Headless checks for the landing-page room list (no window, no server)."""
import ctypes, os, sys, types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ctypes.windll.shcore.SetProcessDpiAwareness(2)
import customtkinter as ctk  # noqa: E402
import vplan42 as vp         # noqa: E402

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  OK  " if cond else " FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def room(rid, name, role, members, limit=16):
    return {"id": rid, "name": name, "code": "c%d" % rid, "pwd": "p", "limit": limit,
            "my_role": role, "my_perms": {}, "members": members}


def m(i, name=None, online=True):
    return {"id": i, "name": name or f"u{i}", "role": "member", "vip": f"10.77.0.{i}", "online": online}


class Fake:
    """Only the attributes the landing code touches."""


def make_app():
    root = ctk.CTk()
    root.withdraw()
    f = Fake()
    f.root = root
    f.rooms_list = ctk.CTkScrollableFrame(root, fg_color="transparent")
    f.rooms_list.pack(fill="both", expand=True)
    f.lbl_rooms_count = ctk.CTkLabel(root, text="")
    f.rows, f.room_rows, f.my_rooms = {}, {}, []
    f.rooms_empty, f.entering_rid, f.busy, f.node, f.link = None, None, False, None, None
    f.entered, f.removed, f.await_enter = [], [], None
    f.enter_room = lambda r: f.entered.append(r)
    f.remove_room = lambda r: f.removed.append(r)
    for nm in ("btn", "room_sig", "find_room", "clear_rooms", "show_rooms_empty",
               "add_room_row", "set_room_row", "on_my_rooms", "inside"):
        setattr(f, nm, types.MethodType(getattr(vp.App, nm), f))
    return f


def kids(f):
    return [w for w in f.rooms_list.winfo_children() if w.winfo_exists()]


def main():
    f = make_app()

    # 1. empty state must be exactly one widget, however many refreshes arrive
    f.on_my_rooms([])
    n1 = len(kids(f))
    for _ in range(5):
        f.on_my_rooms([])
    check("empty note never stacks", len(kids(f)) == n1 == 1, str(len(kids(f))))
    check("empty note text", "No rooms yet" in f.rooms_empty.cget("text"))

    # 2. a hosted room: one row, Enter button present, rows are reused (never rebuilt)
    rooms = [room(7, "my room", "owner", [m(1), m(2)])]
    f.on_my_rooms(rooms)
    check("placeholder gone when a room exists", f.rooms_empty is None and len(kids(f)) == 1)
    row = f.room_rows[7]
    enter = [w for w in row["frame"].winfo_children() if isinstance(w, ctk.CTkButton)
             and w.cget("text") == "Enter"]
    check("Enter button exists", len(enter) == 1)
    f.on_my_rooms(rooms)
    f.on_my_rooms(rooms)
    check("unchanged rooms are not re-rendered", f.room_rows[7] is row and len(kids(f)) == 1)

    # 3. member rooms used to crash the row build (ROLE_BADGE['member'] has no space)
    try:
        f.on_my_rooms([room(7, "my room", "owner", [m(1), m(2)]),
                       room(9, "friend room", "member", [m(1), m(3), m(2)])])
        crashed = ""
    except Exception as ex:
        crashed = str(ex)
    check("joined room row builds without error", not crashed, crashed)
    if not crashed:
        btns = [w.cget("text") for w in f.room_rows[9]["frame"].winfo_children()
                if isinstance(w, ctk.CTkButton)]
        check("joined room has its own Enter", "Enter" in btns, str(btns))
        check("member role text", "you are member" in f.room_rows[9]["info"].cget("text"),
              f.room_rows[9]["info"].cget("text"))
        check("host line only for the owner",
              f.room_rows[7]["host"].cget("text") == "you host this room"
              and f.room_rows[9]["host"].cget("text") == "")

    # 4. live counters update in place (no new widgets, no scroll growth)
    before = len(kids(f))
    f.on_my_rooms([room(7, "my room", "owner", [m(1), m(2), m(5), m(6)]),
                   room(9, "friend room", "member", [m(1), m(3), m(2)])])
    check("member count text updates", "4 members" in f.room_rows[7]["info"].cget("text"),
          f.room_rows[7]["info"].cget("text"))
    check("rows are not rebuilt on change", len(kids(f)) == before and f.room_rows[7] is row)

    # 5. a removed room destroys exactly its own row
    f.on_my_rooms([room(7, "my room", "owner", [m(1), m(2), m(5), m(6)])])
    check("removed room row is gone", 9 not in f.room_rows and len(kids(f)) == 1)

    # 6. Enter clicks hand over the freshest room dict
    f.entered.clear()
    f.room_rows[7]["enter"].invoke()
    check("Enter passes the current room", f.entered and f.entered[0]["id"] == 7
          and f.entered[0]["my_role"] == "owner")

    # 7. logout clears every tracked widget, including the placeholder
    f.on_my_rooms([])
    f.clear_rooms()
    check("clear_rooms leaves nothing behind", kids(f) == [] and f.rooms_empty is None
          and f.my_rooms == [] and f.room_rows == {})

    # 8. signing back in rebuilds from scratch
    f.on_my_rooms([room(11, "again", "admin", [m(1), m(2)])])
    check("list rebuilds after logout", len(kids(f)) == 1 and "🛡" == f.room_rows[11]["mark"].cget("text"))

    f.root.destroy()
    print(f"\nRESULT: {len(PASS)} passed, {len(FAIL)} failed")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
