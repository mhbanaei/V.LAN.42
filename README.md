# V.Lan.42

Play together over a virtual local network.

V.Lan.42 gives a small group of players one shared **virtual LAN** (`10.77.0.0/16`) even
though everybody sits at home. Every packet travels through your own VPS, so a game that
only broadcasts on the local network finds the other players, and the room lives as long
as the server does - not as long as one person's laptop stays open.

* ** coded by Hossein & Erfan **
* https://github.com/mhbanaei

---

## Who runs what

| | who | what |
|---|---|---|
| `vlan42_server.py` | the management team, on the VPS | started with `start_server.bat`, kept running |
| `V.Lan.42.exe` / `vplan42.py` | the players | sign in with a username and a password, that is all |

**Players never type a server address.** The address comes only from the team's
`vlan42_servers.txt` (default `v42.ir`) and is bundled into the client build. The login
and register forms ask for a username and a password and nothing else. If a player is
handed an address, it is a bug - report it.

---

## Running the server (the team)

1. Put `vlan42_server.py`, `start_server.bat` and (optional) `vlan42_check.py` in one
   folder on the VPS.
2. Run **`start_server.bat` as Administrator** once, so it can add the firewall rules.
3. Keep the window open - that window *is* the server.

The script installs `cryptography`, opens TCP/UDP 4242 in the Windows firewall, writes
`vlan42_servers.txt` if it is missing, detects the public IP of the VPS and adds it to
that file as a fallback, then starts the server and runs a self-check.

To use another address: `start_server.bat your-domain-or-ip`.

### Ports

Both directions must be open **twice** - inside Windows *and* in the security panel of
the hosting company:

| port | protocol | used for |
|---|---|---|
| 4242 | TCP | login, rooms, friends, chat (encrypted control channel) |
| 4242 | UDP | the game traffic relay |

UDP is the one people forget. Without it players can log in and see the rooms, but
entering a room fails.

### Files the server creates

| file | what it is |
|---|---|
| `vlan42_server.json` | ports, `udp_timeout` and the `invite_key` that mints invite codes |
| `vlan42_data/db.sqlite` | accounts, rooms, friends, messages |
| `vlan42_servers.txt` | the addresses clients try, in order - the team's file, not the players' |

`vlan42_server.json` and `vlan42_data/` hold live data and the invite key. **Do not
commit them.**

---

## Running the client (the players)

Double-click `V.Lan.42.exe`. First launch asks for a username and a password; tick
*remember me* and the next launch goes straight in.

Inside the app:

* **Rooms** - the rooms you host or belong to, with a crown on the one you own. Up to
  **3 rooms per account**. Create a room by typing its name and pressing the dice for the
  password; the password is 32 characters from the operating system's entropy pool.
* **Friends** - search by username, send a request, accept or ignore, open a private
  thread. A request or a message updates both sides the moment it lands.
* **Room** - appears in the tab bar only while you are inside one. One clean card per
  player: status dot, name, their ping, and clicking the card copies their virtual IP.
  The room stays attached to the server even when you are the only one inside.
* **Logs** - everything the app has to say. Nothing is written to a `.log` file.
* **Settings** - English / فارسی.

A room does not die with its host. When the owner leaves, ownership moves to the
longest-serving admin and, if there is none, to any other member - so the room and its
chat survive however few players are left. Only an empty room is deleted.

### Roles

`Owner` → `Admin` (with chosen permissions) → `Member`. Per-admin permissions are
`kick`, `ban`, `unban`, `limit`, `approve`. Kicked players can be let back in; banned
players cannot join until unbanned. New members wait for the host (or an admin with
`approve`) before they are inside.

### Invites

An invite is a **sealed code**, not a link: `xxxx.xxxx.xxxx.xxxx...`

The VPS builds it from the room code and a fingerprint of the room password, encrypts it
with AES-256-GCM under the `invite_key` in `vlan42_server.json`, and hands out the
base64url result in dot groups. Nobody - including the player holding the code - can read
it or guess another one. Only the server opens it. Re-rolling the room password retires
every code already in circulation. Six wrong tries in ten minutes cool an account off for
two minutes, and every rejection says the same thing, so nothing leaks which part was
wrong.

`vlan42://join/<code>` is accepted too, for when somebody forwards a click - but the code
inside it is the same sealed token.

---

## Languages

The Settings tab switches the whole interface between English and Persian: the words are
translated, the layout mirrors (left becomes right), notices move to the other corner,
and Persian text is drawn in **Vazir** (falling back through `Vazirmatn`, `Vazir FD`,
`Noto Sans Arabic`, `Tahoma` - whatever is installed). The choice is remembered.

---

## Building the exe

```
build_exe.bat
```

Installs `pyinstaller customtkinter cryptography pillow`, bundles `V.Lan.42.ico`
(and `wintun.dll` if present) and produces a single **`dist\V.Lan.42.exe`**. Ship that
file next to your `vlan42_servers.txt` if you change the addresses.

## Before you push

`.gitignore` keeps the live state out of the repository: the database, both config files
(`vlan42_server.json` holds the invite key) and anything ending in `.log`. Look at
`vlan42_servers.txt` before you commit it - it lists your real VPS addresses, and a public
repository publishes them to the world. `v42.ir` alone is usually enough.

## Tests

Everything runs headless against the real server or the real window - no mocks for the
protocol:

```
python _test/test_rolling.py      # invite sealing, dice, join cooloff
python _test/test_client.py       # full protocol against a throw-away server (port 45242)
python _test/test_enter_room.py   # joining, approval, roster
python _test/test_timeouts.py     # UDP silence and the reason a peer dropped
python _test/test_rooms_ui.py     # the landing room list
python _test/test_friends_pm.py   # requests, private messages, instant updates
python _test/test_ui_tabs.py      # the real window: tabs, cards, invites, panels
python _test/test_lang_ui.py      # English <-> Persian: words, geometry, font
```

Run them one at a time - they share the config file and the test ports.

## Requirements

* Windows 10/11 (the virtual adapter uses WinTUN)
* Python 3.10+ with `cryptography`, `customtkinter`, `pillow`
* Server: nothing else - it is one file and one SQLite database

## Security notes

* The control channel is X25519 → HKDF-SHA256 → AES-256-GCM. There is no TLS anywhere.
* Room passwords and account passwords are never stored in the clear.
* `vlan42_server.json` holds the invite key - treat it like a secret.
