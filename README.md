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
3. Keep the window open - that window *is* the server, and it answers the team's commands.

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
| `vlan42_server.json` | ports, `udp_timeout`, the `invite_key` that mints invite codes and the `staff` list |
| `vlan42_data/db.sqlite` | accounts, rooms, friends, messages, per-day traffic |
| `vlan42_servers.txt` | the addresses clients try, in order - the team's file, not the players' |
| `vlan42_staff.key` | 32 random bytes written the first time the server runs - the management door |

`vlan42_server.json`, `vlan42_staff.key` and `vlan42_data/` hold live data, the invite key
and the way into the management console. **Do not commit them, and do not copy the key file
to a player's machine** - it is what makes the team the team.

### The management console

**Type them into the window that is running the server** - the one `start_server.bat`
opened. `python vlan42_server.py <words>` next to it works too, from any other window on
that machine.

```
status                  what is running right now
users                   every account: made, last seen, its PC, its rooms, its data
rooms                   every room: owner, members, who is in it now
traffic                 bytes the relay moved, per player per day
set admin <name>        let that account open the panel inside the app
remove admin <name>     take that right back
set limit <room> <n>    how many players a room may hold (2-64)
help                    this list
```

Typed in the server's own window there is no password: whoever can type there owns the
machine. Over the network the same commands answer either to a stamp made from
`vlan42_staff.key` - that file lives on this server alone, and a stamp is worth one minute -
or to a connection already signed in as an account the team vouched for.

The same facts as a table inside the app: **Settings → Open the console**, which appears
only for an account the team vouched for. *Users / Rooms / Traffic*, a click on a column
header to sort, a box to search, the rooms each account holds listed in its line,
`Make team` / `Remove from team` on a user row, and each
room's player ceiling typed in its own row. `set admin` opens that panel on the
account's screen the moment you type it - no signing out and back in for them, and
`remove admin` closes it the same way.

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
* **Settings** - English / فارسی, the message sound, and a card to change your own
  password. The current one is asked for, so a seat left unlocked is not a way in; the
  new one has to be at least 6 characters, every other session of the account is dropped,
  and *remember me* carries on with the new password. For the team, one more card:
  *Open the console*. The page scrolls, so no card is ever out of reach on a short window.

The name of the app is drawn once, in the top bar; a page header only says where you are
and thanks the people whose support pays for the servers - `reymit.ir/42level`, clickable.

A room does not die with its host. When the owner leaves, ownership moves to the
longest-serving admin and, if there is none, to any other member - so the room and its
chat survive however few players are left. Only an empty room is deleted.

### Roles and permissions

`Owner` → `Admin` → `Member`. Permissions are `kick`, `ban`, `unban`, `limit`, `approve`
and `invite`, and **every one of them belongs to one room only** - nothing is global and
no room borrows another room's rules.

* The owner sets the room's own **defaults per role** (admin panel → *Role defaults* →
  tick → *Save*). Out of the box a member may do nothing but play, and an admin may
  `kick`, `ban`, `unban` and `invite`. Inviting a friend into a room is therefore not
  something a plain member can do, and the owner can turn it on for members - or off for
  admins - for this room alone.
* The owner can also tick permissions **for one person** (admin panel → *Members* → the
  ticks under each name → *Apply*). A tick on a person outranks that role's default, in
  both directions: putting it on grants it, taking it off refuses it even when the room
  default says yes.
* A person with no ticks of their own always follows the room's current default, so
  changing the default afterwards still reaches everybody who was never ticked. Promoting
  somebody writes no ticks at all, for exactly that reason.
* Kicked players can be let back in; banned players cannot join until unbanned. New
  members wait for the host (or an admin with `approve`) before they are inside.
* The **Players** column leads with the ranks - owner at the top, then the admins, then
  the members, each group in name order. The roster key that decides whether the column
  is rebuilt carries every member's role, so the moment somebody is promoted or demoted
  the column reorders itself on the next state the server sends.

### Invites

An invite is a **sealed code**, not a link: `xxxx.xxxx.xxxx.xxxx...`

The VPS builds it from the room code and a fingerprint of the room password, encrypts it
with AES-256-GCM under the `invite_key` in `vlan42_server.json`, and hands out the
base64url result in dot groups. Nobody - including the player holding the code - can read
it or guess another one. Only the server opens it. Inside a room, **Copy invite code**
puts that code on the clipboard and answers with a green `Copied ✓` on the button itself,
the same way a player line does when it hands over an IP. Re-rolling the room password retires
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

What the mirror covers, because a word that is not moved is a word that disappears:

* every page (including the Settings password card), every floating panel (admin, invite,
  the management console) and every notice card;
* rows built *after* the switch - room rows, player cards, friend rows, a console table
  redrawn while it is open - caught by the slow pass in `tick()`;
* the inside of scroll lists (Rooms, Players, Friends, Admin panel, the console's tables):
  customtkinter builds them as a canvas holding a frame, and the frame's rows are mirrored
  while the canvas, the scrollbar and the caption are left exactly where customtkinter put
  them;
* grid columns *and* the column that stretches, so a mirrored row keeps its shape instead
  of opening a gap in the middle;
* the **order** inside a packed column: `pack` puts anything it re-packs at the end of its
  stack, so the mirror re-packs the whole group in the order the code used (`after=`
  chaining) instead of moving one widget at a time;
* log lines and system chat lines, which are plain text and are translated as they land -
  a player's own message is never rewritten;
* Persian lines name the thing before its count (`عضو: ۲`, not `۲ عضو`), because Tk sends
  a number that opens a right-to-left line to the far end of it.

A language switch rebuilds the lists it can (rooms, players, friends) *before* mirroring,
never after: mirroring a widget that is about to be destroyed leaves customtkinter
redrawing a canvas that is gone.

Only the geometry managers this app uses itself are touched (`_box`/`_glass` in
`vplan42.py`): a button's own label, an entry's own box, a segmented switch's own buttons
and a scroll list's own canvas and scrollbar belong to customtkinter and are never moved.

---

## Building the exe

```
build_exe.bat
```

Installs `pyinstaller customtkinter cryptography pillow`, bundles `V.Lan.42.ico`
(and `wintun.dll` if present) and produces a single **`dist\V.Lan.42.exe`**. Ship that
file next to your `vlan42_servers.txt` if you change the addresses.

## Before you push

`.gitignore` keeps the live state out of the repository: the database, the configs
(`vlan42_server.json` holds the invite key, `vlan42_staff.key` the management door) and
anything ending in `.log`. Look at
`vlan42_servers.txt` before you commit it - it lists your real VPS addresses, and a public
repository publishes them to the world. `v42.ir` alone is usually enough.

## Tests

Everything runs headless against the real server or the real window - no mocks for the
protocol:

```
python _test/test_rolling.py      # invite sealing, dice, join cooloff
python _test/test_client.py       # protocol, throw-away server on 45242: rooms, invites, the
                                  # machine cap, changing a password, the management console
python _test/test_enter_room.py   # joining, approval, roster
python _test/test_timeouts.py     # UDP silence and the reason a peer dropped
python _test/test_rooms_ui.py     # the landing room list
python _test/test_friends_pm.py   # requests, private messages, instant updates
python _test/test_ui_tabs.py      # the real window: tabs, cards, invites, panels, the tables
python _test/test_lang_ui.py      # English <-> Persian: words, geometry, font, mirrored tables
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
* **The VPS address never reaches a player.** `mask_net()` scrubs every host, IP and port
  the client knows (`learn_net()` collects them from `vlan42_servers.txt` and the built-in
  list) out of every log line, error card and diagnostics report, replacing it with
  "the network". Virtual room IPs (`10.77.0/16`) are left alone - those are the numbers
  players put into their game, and a click on a player line copies one to the clipboard
  and marks the line `Copied ✓`.
* **The management door has two keys, and a player holds neither.** A connection that is
  signed in as an account the team vouched for is let in - which is how the panel inside the
  app works, with no key file on that PC. Any other connection needs a stamp made by a
  process able to read `vlan42_staff.key` (AES-256-GCM over the minute it was minted, AAD
  `vlan42-staff`), and that file lives on the VPS alone; typing into the server's own window
  needs nothing at all, because whoever is at that keyboard owns the machine. So a player
  with the whole source code still cannot make themselves management: the `staff` list lives
  in the server's *own* `vlan42_server.json`, which no client writes, `set admin` only runs
  behind those two doors, a stamp copied off the wire is worthless a minute later, and every
  refusal says the same flat "this is not the management console". Vouching or un-vouching
  reaches the account on their screen the moment it is typed - no signing out and in.
* **Three accounts to a PC, no more.** The app hashes what Windows and the BIOS say about
  the box (`machine_id()`: install GUID, board maker/product/serial, and WMI's UUID and CPU
  signature only if the registry had nothing) and sends only that hash. The server keeps it
  per account and refuses a fourth registration from the same machine; an account made
  before the rule is adopted by the first PC it signs in from, so it cannot dodge the count.
  A box that gives no hash at all is not punished - it registers uncounted and the server
  log says so.
