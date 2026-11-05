# -*- coding: utf-8 -*-
"""
V.Lan.42 - virtual LAN for games over your own VPS (Windows, run as Admin)

How it works:
  * Server        : your VPS runs vlan42_server.py (start it with start_server.bat)
                    Players never enter an address - the app defaults to v42.ir and a
                    vlan42_servers.txt shipped with the app can override that for the team.
  * Signaling     : TCP control channel, X25519 handshake + AES-GCM session encryption
                    (login/register, rooms, friends, kick/ban, roles, chat)
  * Data          : every game packet goes through the VPS UDP relay - one hop, low stable ping
  * Virtual net   : Wintun adapter, each member gets 10.77.x.y assigned by the server
  * Firewall      : one-time rules (the program + game ports from 10.77.0.0/16 only)

coded by Hossein & Erfan  -  https://github.com/mhbanaei
"""
import os, sys, json, time, socket, threading, hashlib, ctypes, subprocess, zipfile, queue, struct
import traceback, platform, base64, secrets, glob, shutil, webbrowser, re, tempfile, faulthandler
import tkinter as tk
import tkinter.font as tkfont
from collections import deque
import urllib.request
from ctypes import c_void_p, c_uint32, c_wchar_p, POINTER, byref

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import customtkinter as ctk
try:
    import winsound
except ImportError:
    winsound = None
try:
    winmm = ctypes.windll.winmm      # mci plays an mp3 with nothing extra installed
except Exception:
    winmm = None

APP_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
CFG_FILE = os.path.join(APP_DIR, "vlan42.json")
IFACE = "V-Lan-42"
APP_NAME = "V LAN 42"
LOGO_FILE = "V.Lan.42.ico"
SND_FILE = "text.mp3"                # the sound a friend's message makes
GITHUB_URL = "https://github.com/mhbanaei"
REYMIT_URL = "https://reymit.ir/42level"     # the team's support page: it pays for the servers
DEFAULT_PORT = 4242
MAX_ROOMS = 3
# Users only ever sign in with a username and password - the app never asks for an address.
# v42.ir is the domain the team points at their VPS. start_server.bat keeps a
# vlan42_servers.txt (next to V.Lan.42.exe / in the build folder) as the override for the
# team, with one "ip", "domain" or "ip:port" per line - it is tried before the default.
SERVER_HOSTS = ["v42.ir"]
SERVER_HOSTS_FILE = "vlan42_servers.txt"
STAFF_FILE = "vlan42_staff.key"      # only on the VPS: what makes a console the team's
STAFF_AAD = b"vlan42-staff"
STAFF_WINDOW = 60
# The app writes no logs next to itself. Only a freeze report exists, in the system temp
# dir, read back on the next start and deleted: the Logs page is the place to read anything.
HANG_FILE = os.path.join(tempfile.gettempdir(), "vlan42_hang.txt")
PERM_LABELS = {"kick": "Kick", "ban": "Ban", "unban": "Unban", "limit": "Member limit",
               "approve": "Approve", "invite": "Invite"}


def sh(cmd, timeout=25):
    try:
        return subprocess.run(cmd, shell=False, capture_output=True, stdin=subprocess.DEVNULL,
                              creationflags=0x08000000 | 0x00004000, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 1, b"", b"timeout")
    except OSError as ex:
        return subprocess.CompletedProcess(cmd, 1, b"", str(ex).encode())


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def res_path(name):
    for base in (getattr(sys, "_MEIPASS", None), APP_DIR, os.path.dirname(os.path.abspath(__file__))):
        if base:
            p = os.path.join(base, name)
            if os.path.isfile(p):
                return p
    return None


def play_file(path):
    """One short sound through the media player Windows already has. The alias is closed
    first so a second message does not fail on a stream still held open."""
    if not (path and winmm):
        return False
    try:
        winmm.mciSendStringW("close v42snd", None, 0, None)
        if winmm.mciSendStringW(f'open "{path}" alias v42snd', None, 0, None):
            return False
        winmm.mciSendStringW("play v42snd", None, 0, None)
        return True
    except Exception:
        return False


def load_cfg():
    try:
        with open(CFG_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cfg(cfg):
    try:
        tmp = CFG_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=1)
        os.replace(tmp, CFG_FILE)
    except Exception:
        pass


def bigbuf(sock, size=2 << 20):
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, size)
        except OSError:
            pass


# ---------------- wintun trust (unchanged machinery from the previous version)
_REG_KEY = r"SOFTWARE\P2PLAN"


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def trust_cache_get():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _REG_KEY) as k:
            v = winreg.QueryValueEx(k, "wintun_ok")[0]
            return set(v) if isinstance(v, list) else set()
    except Exception:
        return set()


def trust_cache_add(digest):
    try:
        import winreg
        cur = [d for d in trust_cache_get() if d != digest][-7:] + [digest]
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, _REG_KEY) as k:
            winreg.SetValueEx(k, "wintun_ok", 0, winreg.REG_MULTI_SZ, cur)
    except Exception:
        pass


class WintunMissing(Exception):
    pass


WINTUN_URLS = ["https://www.wintun.net/builds/wintun-0.14.1.zip"]


def want_machine():
    if struct.calcsize("P") == 8:
        return 0xAA64 if platform.machine().upper() == "ARM64" else 0x8664
    return 0x14C


def pe_machine(path):
    with open(path, "rb") as f:
        f.seek(0x3C)
        off = struct.unpack("<I", f.read(4))[0]
        f.seek(off)
        if f.read(4) != b"PE\0\0":
            raise ValueError("no PE header")
        return struct.unpack("<H", f.read(2))[0]


def oem_decode(b):
    try:
        return b.decode(f"cp{ctypes.windll.kernel32.GetOEMCP()}", errors="replace")
    except Exception:
        return b.decode("utf-8", errors="replace")


def wintun_trusted(path):
    try:
        mach = pe_machine(path)
    except Exception as ex:
        return False, f"not a valid DLL ({ex})"
    if mach != want_machine():
        return False, f"wrong CPU type (0x{mach:x}, need 0x{want_machine():x})"
    try:
        digest = file_sha256(path)
    except OSError as ex:
        return False, f"cannot read file ({ex})"
    if digest in trust_cache_get():
        return True, "ok (cached)"
    ps = "$s=Get-AuthenticodeSignature -LiteralPath '" + path.replace("'", "''") + "'; $s.Status; $s.SignerCertificate.Subject"
    out = oem_decode(sh(f'powershell -NoProfile -NonInteractive -Command "{ps}"', timeout=60).stdout).strip().splitlines()
    status = out[0].strip() if out else "no output"
    if status == "Valid" and "WireGuard" in " ".join(out[1:]):
        trust_cache_add(digest)
        return True, "ok"
    if status == "Valid":
        return False, "signed by a different publisher (not WireGuard LLC)"
    return False, f"signature check failed ({status})"


def _arch_dir():
    return {0x8664: "amd64", 0xAA64: "arm64", 0x14C: "x86"}[want_machine()]


def install_wintun_from(src, log=print):
    dst = os.path.join(APP_DIR, "wintun.dll")
    tmp = os.path.join(APP_DIR, "wintun_new.dll")
    try:
        if src.lower().endswith(".zip"):
            with zipfile.ZipFile(src) as z:
                open(tmp, "wb").write(z.read(f"wintun/bin/{_arch_dir()}/wintun.dll"))
        elif os.path.abspath(src) == os.path.abspath(dst):
            tmp = dst
        else:
            shutil.copyfile(src, tmp)
        ok, why = wintun_trusted(tmp)
        if not ok:
            raise WintunMissing(f"{src}: {why}")
        if tmp != dst:
            os.replace(tmp, dst)
        log(f"wintun.dll ready (from {src})")
        return dst
    finally:
        if tmp != dst and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


_SKIP_DIRS = {"temp", "cache", "caches", "packages", "steamapps", "node_modules", ".git", "windowsapps",
              "windows", "$recycle.bin", "code cache", "gpucache", "crashpad", "logs"}


def _scan_for_wintun(base, depth, deadline):
    level = [base]
    for d in range(depth + 1):
        nxt = []
        for folder in level:
            if time.time() > deadline:
                return
            try:
                with os.scandir(folder) as it:
                    for e in it:
                        try:
                            if e.is_file(follow_symlinks=False):
                                if e.name.lower() == "wintun.dll":
                                    yield e.path
                            elif d < depth and e.is_dir(follow_symlinks=False) and e.name.lower() not in _SKIP_DIRS:
                                nxt.append(e.path)
                        except OSError:
                            pass
            except OSError:
                continue
        level = nxt


def _wintun_sources():
    seen = set()

    def fresh(p):
        k = os.path.normcase(os.path.abspath(p))
        if k in seen or not os.path.isfile(p):
            return False
        seen.add(k)
        return True

    first = [os.path.join(APP_DIR, "wintun.dll"), os.path.join(os.getcwd(), "wintun.dll")]
    if getattr(sys, "_MEIPASS", None):
        first.insert(0, os.path.join(sys._MEIPASS, "wintun.dll"))
    for p in first:
        if fresh(p):
            yield p
    home = os.path.expanduser("~")
    for d in (APP_DIR, os.path.join(home, "Downloads"), os.path.join(home, "Desktop")):
        for z in glob.glob(os.path.join(d, "wintun*.zip")):
            if fresh(z):
                yield z
    pf = [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")]
    for rel in ("Tailscale", "WireGuard", "v2rayN", "Clash Verge", "Hiddify", "NekoRay"):
        for base in filter(None, pf):
            p = os.path.join(base, rel, "wintun.dll")
            if fresh(p):
                yield p
    deadline = time.time() + 6
    for base, depth in [(b, 3) for b in pf] + [(os.environ.get("LOCALAPPDATA"), 2), (os.environ.get("APPDATA"), 2),
                                               (home, 2)]:
        if base and os.path.isdir(base):
            for p in _scan_for_wintun(base, depth, deadline):
                if fresh(p):
                    yield p


def ensure_wintun(log=print):
    dst = os.path.join(APP_DIR, "wintun.dll")
    cfg = load_cfg()
    if cfg.get("wintun_path"):
        try:
            return install_wintun_from(cfg["wintun_path"], log)
        except Exception as ex:
            log(f"wintun_path ignored: {ex}")
    if os.path.isfile(dst) and wintun_trusted(dst)[0]:
        return dst
    log("Looking for wintun.dll on this PC (other apps like Tailscale/v2rayN ship it)...")
    for src in _wintun_sources():
        try:
            return install_wintun_from(src, log)
        except Exception as ex:
            log(f"  skipped {src}: {ex}")
    errors = []
    for url in ([cfg["wintun_url"]] if cfg.get("wintun_url") else []) + WINTUN_URLS:
        try:
            log(f"Downloading wintun from {url} ...")
            data = urllib.request.urlopen(url, timeout=25).read()
            zp = os.path.join(APP_DIR, "wintun_download.zip")
            open(zp, "wb").write(data)
            try:
                return install_wintun_from(zp, log)
            finally:
                os.remove(zp)
        except Exception as ex:
            errors.append(f"{url}: {ex}")
            log(f"  download failed: {ex}")
    raise WintunMissing(
        "wintun.dll was not found and could not be downloaded.\n"
        "Fix (pick one):\n"
        "  1) Download wintun-0.14.1.zip from https://www.wintun.net and select the zip when asked.\n"
        "  2) Copy wintun.dll from an app that has it (Tailscale, v2rayN, Hiddify, Clash...) next to the app.\n"
        "  3) Put a direct link in vlan42.json:  \"wintun_url\": \"https://.../wintun-0.14.1.zip\"\n"
        "A file selection window will open now.")


def net_hint(ex):
    if "10013" in str(ex):
        return ("\n  HINT: Windows blocked this connection (WinError 10013). Allow it in "
                "Windows Firewall / your antivirus, then retry.")
    if "10061" in str(ex) or "refused" in str(ex).lower():
        return f"\n  HINT: the {APP_NAME} network is offline right now - please try again later."
    if "getaddrinfo" in str(ex).lower() or "11001" in str(ex) or "10065" in str(ex):
        return "\n  HINT: check your internet connection - the network could not be resolved."
    if "timed out" in str(ex).lower() or "timeout" in str(ex).lower():
        return f"\n  HINT: no answer from the {APP_NAME} network - check your internet connection."
    return ""


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


# ----------------------------------------------------------------- Wintun adapter
class Tun:
    def __init__(self, dll, name):
        self.name = name
        w = self.w = ctypes.WinDLL(dll, use_last_error=True)
        k = self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k.WaitForSingleObject.argtypes = [c_void_p, c_uint32]
        k.WaitForSingleObject.restype = c_uint32
        w.WintunOpenAdapter.argtypes = [c_wchar_p]
        w.WintunOpenAdapter.restype = c_void_p
        w.WintunCreateAdapter.argtypes = [c_wchar_p, c_wchar_p, c_void_p]
        w.WintunCreateAdapter.restype = c_void_p
        w.WintunStartSession.argtypes = [c_void_p, c_uint32]
        w.WintunStartSession.restype = c_void_p
        w.WintunGetReadWaitEvent.argtypes = [c_void_p]
        w.WintunGetReadWaitEvent.restype = c_void_p
        w.WintunReceivePacket.argtypes = [c_void_p, POINTER(c_uint32)]
        w.WintunReceivePacket.restype = c_void_p
        w.WintunReleaseReceivePacket.argtypes = [c_void_p, c_void_p]
        w.WintunAllocateSendPacket.argtypes = [c_void_p, c_uint32]
        w.WintunAllocateSendPacket.restype = c_void_p
        w.WintunSendPacket.argtypes = [c_void_p, c_void_p]
        w.WintunEndSession.argtypes = [c_void_p]
        w.WintunCloseAdapter.argtypes = [c_void_p]
        self.ad = w.WintunOpenAdapter(name) or w.WintunCreateAdapter(name, "VLan42", None)
        if not self.ad:
            raise OSError("Cannot create Wintun adapter (run as Administrator)")
        self.ses = w.WintunStartSession(self.ad, 0x400000)
        self.ev = w.WintunGetReadWaitEvent(self.ses)
        self.lock = threading.Lock()
        self.alive = True
        self.last_loop = time.time()

    def configure(self, ip):
        n = self.name
        for i in range(12):
            r = sh(f'netsh interface ip set address name="{n}" static {ip} 255.255.0.0')
            if r.returncode == 0:
                break
            time.sleep(0.4 + 0.2 * i)
        sh(f'netsh interface ipv4 set subinterface "{n}" mtu=1280 store=active')
        sh(f'netsh interface ipv4 set interface "{n}" metric=5')

    def read_loop(self, cb):
        size = c_uint32()
        while self.alive:
            self.last_loop = time.time()
            p = self.w.WintunReceivePacket(self.ses, byref(size))
            if p:
                data = ctypes.string_at(p, size.value)
                self.w.WintunReleaseReceivePacket(self.ses, p)
                cb(data)
            elif ctypes.get_last_error() == 259:
                self.k32.WaitForSingleObject(self.ev, 500)
            else:
                time.sleep(0.05)

    def write(self, data):
        if not self.alive:
            return
        with self.lock:
            p = self.w.WintunAllocateSendPacket(self.ses, len(data))
            if p:
                ctypes.memmove(p, data, len(data))
                self.w.WintunSendPacket(self.ses, p)

    def close(self):
        self.alive = False
        time.sleep(0.6)
        try:
            self.w.WintunEndSession(self.ses)
            self.w.WintunCloseAdapter(self.ad)
        except Exception:
            pass


# ----------------------------------------------------------------- VPS control link
NET_HIDDEN = set()          # every form the network's own address reaches the app in
NET_PORT = [""]             # and its port, so a message can be scrubbed of both


def mask_net(text):
    """The VPS address belongs to the team, not to a player's screen: no log line, notice,
    error or saved report ever repeats it. Virtual room IPs (10.77.0/16) stay - those are
    the numbers the players put into their game."""
    s = str(text)
    for bad in sorted(NET_HIDDEN, key=len, reverse=True):   # "host:port" before "host"
        if bad and bad in s:
            s = s.replace(bad, "the network")
    if NET_PORT[0]:
        # a port standing on its own, with no address next to it, is the server's too
        s = re.sub(r"(?<!\d)" + re.escape(NET_PORT[0]) + r"(?!\d)", "the network", s)
    return re.sub(r"(?<!\d)(?!10\.77\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?",
                  "the network", s)


class VpsLink:
    """Encrypted TCP control channel to the V.Lan.42 server."""

    def __init__(self, host, port, log):
        self.host, self.port, self.log = host, port, log
        NET_HIDDEN.update({host, f"{host}:{port}", f"{host}:"})
        NET_PORT[0] = str(port)
        self.sock, self.aead = None, None
        self.user, self.token = None, None
        self.alive = False
        self.send_lock = threading.Lock()
        self.waiters = {}
        self.push_cb = None
        self.down_cb = None

    # ---- transport
    def _send_plain(self, obj):
        self.sock.sendall(json.dumps(obj, separators=(",", ":")).encode() + b"\n")

    def send(self, obj):
        raw = json.dumps(obj, separators=(",", ":")).encode()
        n = os.urandom(12)
        with self.send_lock:
            self.sock.sendall(base64.b64encode(n + self.aead.encrypt(n, raw, b"vlan42-ctl")) + b"\n")

    def notify_server(self, t, **kw):
        """Fire and forget - used for the typing dots, where an answer is not worth a wait."""
        if self.alive:
            try:
                self.send({"t": t, **kw})
            except OSError:
                pass

    def req(self, t, timeout=15, **kw):
        """Send a request and wait for the reply with the same type."""
        if not self.alive:
            return {"t": t, "ok": False, "err": "Not connected to the server"}
        q = queue.Queue()
        with self.send_lock:
            self.waiters.setdefault(t, []).append(q)
        try:
            self.send({"t": t, **kw})
        except OSError:
            with self.send_lock:
                self.waiters.get(t, []).remove(q)
            return {"t": t, "ok": False, "err": "Connection to the server lost"}
        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            return {"t": t, "ok": False, "err": "The server did not answer (timeout)"}

    # ---- lifecycle
    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=12)
        self.sock.settimeout(12)
        buf = b""
        while b"\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise OSError("server closed the connection")
            buf += chunk
        hello = json.loads(buf.split(b"\n", 1)[0].decode())
        if hello.get("t") != "hello":
            raise OSError(f"this is not a {APP_NAME} server")
        eph = X25519PrivateKey.generate()
        pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared = eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(hello["pub"])))
        key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=bytes.fromhex(hello["nonce"]), info=b"vlan42-ctl").derive(shared)
        self.aead = AESGCM(key)
        self._send_plain({"t": "auth1", "pub": pub.hex()})
        self.sock.settimeout(None)
        self.alive = True
        self._rest = buf.split(b"\n", 1)[1]
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._keepalive, daemon=True).start()

    def _reader(self):
        buf = getattr(self, "_rest", b"")
        while self.alive:
            try:
                while b"\n" not in buf:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        raise OSError("disconnected")
                    buf += chunk
                line, _, buf = buf.partition(b"\n")
                d = base64.b64decode(line.strip())
                obj = json.loads(self.aead.decrypt(d[:12], d[12:], b"vlan42-ctl"))
                if obj.get("t") == "push":
                    if self.push_cb:
                        self.push_cb(obj.get("p") or {})
                else:
                    qs = self.waiters.get(obj.get("t"))
                    if qs:
                        try:
                            qs.pop(0).put(obj)
                        except (IndexError, AttributeError):
                            pass
            except Exception as ex:
                if self.alive:
                    self.alive = False
                    if self.down_cb:
                        self.down_cb(str(ex))
                return

    def _keepalive(self):
        while self.alive:
            time.sleep(20)
            if not self.alive:
                return
            try:
                self.send({"t": "ping"})
            except OSError:
                return

    def close(self):
        self.alive = False
        try:
            if self.user:
                self.send({"t": "logout"})
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


# ------------------------------------------------- managed VPS discovery (never typed by users)
def parse_addr(s):
    s = str(s or "").strip()
    if not s or s in ("0.0.0.0", "::"):
        # 0.0.0.0 is what a listen socket uses, never an address to connect to:
        # on Windows it quietly means "this machine" and confuses everyone.
        return None
    host, sep, port = s.rpartition(":")
    if sep and port.isdigit():
        return host, int(port)
    return s, DEFAULT_PORT


def server_targets():
    """Addresses of the VPSes run by the team - a file wins over the built-in list."""
    cands = []
    for base in (APP_DIR, getattr(sys, "_MEIPASS", None)):
        if not base:
            continue
        try:
            with open(os.path.join(base, SERVER_HOSTS_FILE), "r", encoding="utf-8") as f:
                cands += [ln for ln in (line.strip() for line in f) if ln and not ln.startswith("#")]
        except OSError:
            pass
    cands += list(SERVER_HOSTS)
    out = []
    for cand in cands:
        addr = parse_addr(cand)
        if addr and addr not in out:
            out.append(addr)
    return out


def learn_net():
    """Every address the team runs is remembered as something a player must never be shown,
    so an error that quotes it can be scrubbed before it reaches a screen."""
    for host, port in server_targets():
        NET_HIDDEN.update({host, f"{host}:{port}", f"{host}: {port}", f"{host} port {port}"})
        NET_PORT[0] = str(port)


def open_link(log):
    """Return a control link to the first VPS that answers."""
    learn_net()
    errs = []
    for host, port in server_targets():
        link = VpsLink(host, port, log)
        try:
            link.connect()
            return link
        except Exception as ex:
            log(f"{APP_NAME} network {host}:{port} unavailable: {ex}")
            errs.append(str(ex))
            link.close()
    raise OSError("\n".join(errs) or f"the {APP_NAME} network is not configured yet")


# ----------------------------------------------------------------- active room session
class VpsNode:
    """One active room: UDP relay through the VPS + the Wintun adapter."""

    def __init__(self, link, room, log, ev):
        self.link, self.log, self.ev = link, log, ev
        self.room = room
        self.rid = room["id"]
        self.uid = link.user["id"]
        self.key = bytes.fromhex(room["key"])
        self.aead = AESGCM(self.key)
        self.vip = None
        self.peers = {}          # uid(int) -> state dict
        self.byip = {}
        self.tx = self.rx = 0
        self.chat_cb = None
        self.running = False
        self.srv_rtt = None
        self.sock = None
        self.tun = None
        self.udp_ok = threading.Event()
        self.udp_rejected = False
        self.hb = {}

    # ---- helpers
    def dgram(self, mode, target, payload):
        h = b"V42D" + struct.pack("!I", self.rid) + bytes([mode])
        if mode:
            h += struct.pack("!I", target)
        return h + payload

    def usend(self, data):
        try:
            self.sock.sendto(data, (self.link.host, self.link.port))
        except OSError:
            pass

    # ---- lifecycle
    def start(self):
        self.running = True
        self.log(f"{APP_NAME} | Python {sys.version.split()[0]} | {platform.platform()}")
        self.log(fmt("Connecting to room '{room}'...", room=self.room["name"]))
        r = self.link.req("activate", room=self.rid)
        if not r.get("ok"):
            raise OSError(r.get("err") or "could not activate the room")
        self.firewall_rules()          # the allow rules must exist before the first packet
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bigbuf(self.sock)
        self.sock.settimeout(1)
        try:
            self.sock.ioctl(socket.SIO_UDP_CONNRESET, False)
        except Exception:
            pass
        # somebody has to read the socket, otherwise the V42OK answer of the server is dropped
        threading.Thread(target=self.watch, args=("udp", self.udp_loop), daemon=True).start()
        threading.Thread(target=self.bind_loop, daemon=True).start()
        if not self._wait_relay(15):
            if self.udp_rejected:
                raise OSError("The server rejected this session on UDP - sign out and sign in again.")
            raise OSError("No answer from the relay. The team has to open inbound UDP "
                          "on the server - both its own firewall and the panel of the hosting "
                          "company. Ask them to run vlan42_check.py on the VPS.")
        self.log("Preparing virtual adapter...")
        self.tun = Tun(ensure_wintun(self.log), IFACE)
        self.tun.configure(self.vip)
        self.log(f"Your virtual IP: {self.vip}")
        for name, fn in (("maint", self.maint_loop),
                         ("tun", lambda: self.tun.read_loop(self.on_tun_packet))):
            threading.Thread(target=self.watch, args=(name, fn), daemon=True).start()
        self.log("Room ready - waiting for the other players")

    def watch(self, name, fn):
        while self.running:
            try:
                fn()
                if not self.running:
                    return
                self.log(f"[watchdog] {name} exited, restarting in 2s")
            except Exception:
                self.log(f"[watchdog] {name} crashed:\n{traceback.format_exc()}")
            time.sleep(2)

    FW_VER = 4

    def firewall_rules(self):
        exe = sys.executable
        cfg = load_cfg()
        sig = f"{self.FW_VER}|{exe}"
        if cfg.get("fw_sig") == sig and sh('netsh advfirewall firewall show rule name="V-Lan-42-LAN-UDP"').returncode == 0:
            return
        self.log("Setting up Windows Firewall rules (one time)...")
        add = "netsh advfirewall firewall add rule"
        for prefix in ("P2PLAN", "Esh-VLan", "V-Lan-42"):
            for sfx in ("", "-out", "-LAN-TCP", "-LAN-UDP", "-LAN-PING"):
                sh(f'netsh advfirewall firewall delete rule name="{prefix}{sfx}"')
        rules = [
            f'{add} name="V-Lan-42" dir=in action=allow program="{exe}" protocol=UDP',
            f'{add} name="V-Lan-42-out" dir=out action=allow program="{exe}"',
            f'{add} name="V-Lan-42-LAN-TCP" dir=in action=allow protocol=TCP localport=1024-65535 remoteip=10.77.0.0/16 profile=any',
            f'{add} name="V-Lan-42-LAN-UDP" dir=in action=allow protocol=UDP localport=1024-65535 remoteip=10.77.0.0/16 profile=any',
            f'{add} name="V-Lan-42-LAN-PING" dir=in action=allow protocol=icmpv4:8,any remoteip=10.77.0.0/16 profile=any',
        ]
        if all(sh(r).returncode == 0 for r in rules):
            cfg = load_cfg()
            cfg["fw_sig"] = sig
            save_cfg(cfg)
        else:
            self.log("Firewall: some rules could not be added - games may be blocked")

    def _wait_relay(self, secs):
        end = time.time() + secs
        while time.time() < end and not self.udp_ok.is_set() and not self.udp_rejected:
            time.sleep(0.1)
        return self.udp_ok.is_set()

    def bind_loop(self):
        token = bytes.fromhex(self.link.token)
        while self.running:
            if not self.udp_ok.is_set() or time.time() - self.last_udp > 8:
                try:
                    self.sock.sendto(b"V42BIND" + token, (self.link.host, self.link.port))
                except OSError:
                    pass
            time.sleep(1.0 if not self.udp_ok.is_set() else 4.0)

    def stop(self):
        self.running = False
        try:
            if self.link.alive:
                self.link.req("deactivate", timeout=3)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        try:
            self.tun.close()
        except Exception:
            pass
        for p in self.peers.values():
            p.clear()
        self.peers, self.byip = {}, {}

    last_udp = 0.0
    _ping_t = 0.0

    # ---- room state (from server pushes through the App)
    def update_state(self, room):
        if room.get("my_role") is None:      # broadcast states carry no personal fields
            room["my_role"] = self.room.get("my_role")
            room["my_perms"] = self.room.get("my_perms")
        self.room = room
        cur = {}
        for m in room.get("members", []):
            if m["id"] == self.uid:
                self.vip = m.get("vip") or self.vip
                continue
            p = self.peers.get(m["id"], {"rtt": None, "last": time.time(), "sent": 0, "acks": 0, "loss": 0.0,
                                         "timed_out": False, "online": False})
            was_online = p.get("online")
            p.update(name=m["name"], role=m["role"], vip=m.get("vip"), online=bool(m.get("online")))
            if p["online"] and not was_online:
                # a peer that just came online has not had the chance to answer yet
                p["rtt"], p["timed_out"], p["last"] = None, False, time.time()
            cur[m["id"]] = p
        self.peers = cur
        self.byip = {p["vip"]: uid for uid, p in self.peers.items() if p.get("vip")}
        if self.vip is None:  # first state: find myself
            for m in room.get("members", []):
                if m["id"] == self.uid:
                    self.vip = m.get("vip")

    # ---- UDP channel
    def udp_loop(self):
        while self.running:
            self.hb["udp"] = time.time()
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    time.sleep(0.5)
                continue
            if data == b"V42OK":
                if not self.udp_ok.is_set():
                    self.udp_ok.set()
                    self.log("UDP relay ready")
                self.last_udp = time.time()
                continue
            if data == b"V42PONG" and self._ping_t:
                self.srv_rtt = (time.time() - self._ping_t) * 1000
                self._ping_t = 0.0
                continue
            if data == b"V42BAD":
                self.udp_rejected = True
                self.log("ERROR: the server rejected the UDP session - relogin needed")
                continue
            if len(data) < 13:
                continue
            kind = data[0:1]
            if kind not in (b"D", b"P", b"R"):
                continue
            sender = struct.unpack("!I", data[1:5])[0]
            p = self.peers.get(sender)
            if p:
                p["last"] = time.time()
                if p.get("timed_out"):
                    p["timed_out"] = False
                    self.log(f"{p.get('name', '?')} is back (connection restored)")
            if kind == b"P":  # ping: echo it straight back through the server
                self.usend(self.dgram(1, sender, b"R" + struct.pack("!I", self.uid) + data[5:13]))
                continue
            if kind == b"R":
                ts = struct.unpack("!d", data[5:13])[0]
                rtt = (time.time() - ts) * 1000
                if p and 0 <= rtt < 5000:
                    prev = p.get("rtt")
                    p["rtt"] = rtt if prev is None else prev * 0.7 + rtt * 0.3
                    p["acks"] += 1
                continue
            # data packet: room-key AES-GCM over kind(1) + sender(4) + nonce(12) + ciphertext
            if len(data) < 33:
                continue
            try:
                pkt = self.aead.decrypt(data[5:17], data[17:], b"vd")
            except Exception:
                continue
            self.rx += len(pkt)
            self.tun.write(pkt)

    def maint_loop(self):
        last_ping = 0.0
        while self.running:
            now = time.time()
            self.hb["maint"] = now
            alone = not any(p.get("online") for p in self.peers.values())
            interval = 10.0 if alone else 2.0   # dormant room: far fewer keepalives
            if now - last_ping >= interval:
                last_ping = now
                self._ping_t = time.time()      # my own latency, shown in the players list
                self.usend(b"V42PING")
                for uid, p in list(self.peers.items()):
                    if not p.get("online"):
                        continue
                    self.usend(self.dgram(1, uid, b"P" + struct.pack("!I", self.uid) +
                                          struct.pack("!d", time.time())))
                    p["sent"] += 1
                    if p["sent"] >= 15:
                        loss = max(0.0, 100.0 * (1 - p["acks"] / p["sent"]))
                        p["loss"] = p["loss"] * 0.5 + loss * 0.5
                        p["sent"] = p["acks"] = 0
            for uid, p in list(self.peers.items()):
                if p.get("online") and now - p.get("last", 0) > 12 and not p.get("timed_out"):
                    p["timed_out"] = True
                    p["rtt"] = None
                    why = f"timeout: no answer from {p.get('name', '?')} for {now - p.get('last', 0):.0f}s"
                    self.log(f"{p.get('name', '?')}: {why}")
                    self.ev({"t": "peer_timeout", "user": uid, "name": p.get("name"), "reason": why})
            time.sleep(0.25)

    def send_peer(self, uid, pkt):
        if uid not in self.peers:
            return
        n = os.urandom(12)
        payload = b"D" + struct.pack("!I", self.uid) + n + self.aead.encrypt(n, pkt, b"vd")
        self.usend(self.dgram(1, uid, payload))
        self.tx += len(pkt)

    def on_tun_packet(self, pkt):
        if len(pkt) < 20 or pkt[0] >> 4 != 4:
            return
        dst = socket.inet_ntoa(pkt[16:20])
        uid = self.byip.get(dst)
        if uid and uid in self.peers:
            self.send_peer(uid, pkt)
        elif dst == "255.255.255.255" or pkt[16] >= 224 or dst.endswith(".255.255"):
            n = os.urandom(12)
            payload = b"D" + struct.pack("!I", self.uid) + n + self.aead.encrypt(n, pkt, b"vd")
            self.usend(self.dgram(0, 0, payload))
            self.tx += len(pkt)

    def send_chat(self, text):
        if not self.link.alive:
            return False
        r = self.link.req("chat", text=text)
        return bool(r.get("ok"))

    def diag(self):
        now = time.time()
        lines = [f"--- DIAGNOSTICS --- {time.strftime('%H:%M:%S')}",
                 f"Python {sys.version.split()[0]} | {platform.platform()}",
                 f"Link {'up' if self.link.alive else 'DOWN'}"
                 f" | round trip {f'{self.srv_rtt:.0f}ms' if self.srv_rtt else '?'}",
                 f"Room {self.room.get('name')} #{self.rid} | virtual IP {self.vip}",
                 "Thread heartbeat (seconds ago): " + ", ".join(f"{k}={now - v:.0f}" for k, v in self.hb.items())
                 + f", tun={now - getattr(self.tun, 'last_loop', now):.0f}"]
        for uid, p in list(self.peers.items()):
            lines.append(f"  peer {p.get('name')} {p.get('vip')} online={p.get('online')} "
                         f"rtt={p.get('rtt', -1) if p.get('rtt') is not None else -1:.0f}ms "
                         f"loss={p.get('loss', 0):.0f}% timed_out={p.get('timed_out')}")
        return "\n".join(lines)


# ----------------------------------------------------------------- invite codes
INVITE_PFX = "vlan42://join/"      # the browser hand-off, when somebody forwards a click


def staff_stamp():
    """The stamp that says this app is the team's console. It is made from the server's own
    key file - the one that never travels to a player - so a copy of the source code, or of
    this very app, carries nothing that opens the management door."""
    try:
        raw = open(res_path(STAFF_FILE), encoding="utf-8").read().strip()
        key = bytes.fromhex(raw)
    except Exception:
        return ""
    if len(key) != 32:
        return ""
    win = int(time.time() // STAFF_WINDOW)
    nonce = struct.pack(">QI", win, 0)
    return base64.urlsafe_b64encode(nonce + AESGCM(key).encrypt(
        nonce, str(win).encode(), STAFF_AAD)).decode().rstrip("=")


def parse_invite(text):
    """A friend's code in whatever shape it arrives - dotted, spaced, or inside a whole
    deep link - reduced to the bare sealed token the server opens. None if it is no code.
    The client never reads a token: only the VPS holds the key that seals them."""
    s = str(text or "").strip()
    if INVITE_PFX in s:
        s = s.split(INVITE_PFX, 1)[1]
    s = "".join(ch for ch in s if ch not in " \t\r\n.:|,")
    return s if 48 <= len(s) <= 200 and re.fullmatch(r"[A-Za-z0-9_-]+", s) else None


def _reg_str(path, name):
    r"""One string out of HKLM, read from the 64-bit view so a 32-bit build of the app
    still sees the real machine rather than the redirected copy of the registry."""
    try:
        import winreg
        flag = getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                            winreg.KEY_READ | flag) as k:
            return str(winreg.QueryValueEx(k, name)[0]).strip()
    except Exception:
        return ""


def _run_out(cmd):
    """One short command's stdout, or "" when it is not there to be had."""
    try:
        r = subprocess.run(cmd, shell=False, capture_output=True, stdin=subprocess.DEVNULL,
                           creationflags=0x08000000 | 0x00004000, timeout=10)
        return oem_decode(r.stdout)
    except Exception:
        return ""


_MACHINE_ID = None


def machine_id():
    r"""One hash for this box, the way its owner cannot pick one: the install GUID Windows
    gave this machine plus the board's maker, product and serial, and - only when the
    registry had nothing to say - the BIOS UUID and the CPU signature from WMI. Missing
    pieces are left out rather than guessed, so the same PC keeps answering the same, and
    the answer is remembered for the run: no login waits on a slow disk again.
    The parts never leave this PC - the network only ever sees the hash."""
    global _MACHINE_ID
    if _MACHINE_ID is not None:
        return _MACHINE_ID
    parts = [_reg_str(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid"),
             _reg_str(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer"),
             _reg_str(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName"),
             _reg_str(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemSerialNumber")]
    if not any(p for p in parts if p):
        for cmd in (["wmic", "csproduct", "get", "uuid"], ["wmic", "cpu", "get", "ProcessorId"]):
            out = _run_out(cmd)
            parts += [ln.strip() for ln in out.splitlines()[1:] if ln.strip()][:1]
    keep = [p for p in parts if p and p.upper() not in ("TO BE FILLED BY OEM", "NONE", "DEFAULT")]
    _MACHINE_ID = (hashlib.sha256(b"v42-machine|" + "|".join(keep).encode("utf-8", "ignore")).hexdigest()
                   if keep else "")
    return _MACHINE_ID


def register_protocol():
    try:
        import winreg
        if getattr(sys, "frozen", False):
            cmd = f'"{sys.executable}" "%1"'
        else:
            pyw = sys.executable.replace("python.exe", "pythonw.exe")
            cmd = f'"{pyw if os.path.exists(pyw) else sys.executable}" "{os.path.abspath(sys.argv[0])}" "%1"'
        base = r"Software\Classes\vlan42"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "URL:V.Lan.42")
            winreg.SetValueEx(k, "URL Protocol", 0, winreg.REG_SZ, "")
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\shell\open\command") as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, cmd)
    except Exception:
        pass


_mutex = None


def already_running():
    global _mutex
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    _mutex = k.CreateMutexW(None, False, "VLAN42_SINGLE_INSTANCE")
    return ctypes.get_last_error() == 183


# --------------------------------------------------------------------- UI
BG, CARD, CARD2, LINE = "#0e1218", "#161c25", "#1d2531", "#2a3442"
# a warm grass green: the dark ink on it keeps Persian button labels readable
ACC, ACC_H, ACC_TXT = "#8bc34a", "#76ad3c", "#12200f"
BLUE = "#3498db"
TXT, MUTED = "#e8edf3", "#8896a8"
GREEN, YELLOW, RED, GRAY = "#4ecb6a", "#f1c40f", "#e74c3c", "#6b7686"
NAME_RED = "#ff4d4d"          # the signed-in name
NAME_DIM = "#6e2323"          # the dark half of its pulse
GOLD = "#f5c542"
FONT_EN = "Segoe UI"
FONT = FONT_EN
# Persian in Segoe UI is a row of disconnected letters, so the language switch swaps the
# drawing family. Vazir comes first, and it is the plain one on purpose: the FD and WOL
# variants drop either the Latin or the Persian half, and a family this PC has not got is
# never picked - that is how a language switch ends up showing nothing at all.
FA_FONTS = ("Vazir", "Vazirmatn", "Vazir FD", "Noto Sans Arabic", "Tahoma")
_PENS = {FONT_EN} | set(FA_FONTS)   # families that follow the language, not the widget


def human_size(n):
    """Bytes the way a person reads them."""
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024


def when(t):
    """A moment from the server, in the shape a table column wants."""
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(t)))
    except (TypeError, ValueError):
        return "-"


def con_clip(text, px):
    """Shorten a value that is too long for its column. Each frame sizes its own columns, so
    one long word in one row would move that row's columns out of line with the header."""
    pen = tkfont.Font(font=(FONT, 12))
    if px <= 0 or not text or pen.measure(text) <= px:
        return text
    while text and pen.measure(text + "…") > px:
        text = text[:-1]
    return text.rstrip() + "…"


def has_rtl(text):
    return any("\u0590" <= c <= "\u08ff" or "\ufb1d" <= c <= "\ufdff" or "\ufe70" <= c <= "\ufeff" for c in text)


RLM = "\u200f"     # invisible, and here only a stamp that says "this line is already written
                   # the way Tk wants its pieces" - reversing a second time would undo it


def _run_kind(c):
    """What piece of a line this character belongs to: r for Persian, l for anything Latin -
    letters and every digit, Persian ones included, because Tk lays a number down as its own
    little left-to-right island - and None for the spaces and marks in between."""
    if "\u0590" <= c <= "\u08ff" or "\ufb1d" <= c <= "\ufdff" or "\ufe70" <= c <= "\ufeff":
        return "r"
    if c.isalnum():
        return "l"
    return None


def rtl_runs(text):
    """Split a line into the pieces Tk will lay down one after another: a stretch of Persian,
    a stretch of Latin, and the marks between them. A gap only ends a piece when the word
    after it is of the other kind - the space between two Persian words belongs to the phrase,
    the space between a Persian word and a number is the border."""
    runs, i, n = [], 0, len(text)
    while i < n:
        k = _run_kind(text[i])
        j = i
        while j < n:
            kk = _run_kind(text[j])
            if kk == k:
                j += 1
                continue
            if kk is None:
                p = j
                while p < n and _run_kind(text[p]) is None:
                    p += 1
                if p < n and _run_kind(text[p]) == k:
                    j = p
                    continue
            break
        runs.append(text[i:j])
        i = j
    return runs


def bidi(text):
    """Write a mixed Persian line back to front, so a right-to-left reader meets its words in
    the order they were meant to be read. Tk has no bidirectional reordering at all: it lays a
    line's pieces down left to right in the order they are written and only turns the letters
    inside each piece round - which is why "sara · 10.77.0.7 · نقش: عضو" puts the name at the
    left, where a Persian reader finishes the line instead of starting it. A mark like
    RIGHT-TO-LEFT MARK changes nothing about that; the only thing Tk obeys is the order it is
    given, so the order is what gets changed. A line of a single piece - every plain Persian
    phrase - is already right and is left completely alone."""
    if LANG[0] != "fa" or not text or not has_rtl(text) or text.startswith(RLM):
        return text
    runs = rtl_runs(text)
    if all(_run_kind(c) in (None, "r") for r in runs for c in r):
        return text
    return RLM + "".join(reversed(runs))


def pick_fa_font(master):
    """The first Persian face this machine really has, or "" to stay with the UI font.
    Only tkinter knows which families are installed, so this waits for the window."""
    import tkinter.font as tkfont
    try:
        have = {n.lower(): n for n in tkfont.families(master)}
    except Exception:
        return ""
    for name in FA_FONTS:
        if name.lower() in have:
            return have[name.lower()]
    return ""


def refamily(w, family):
    """Every widget under w, told which family to draw in. The words they hold are left
    alone - only the pen changes. customtkinter hands back the font it was given, either a
    CTkFont object or a plain (family, size, style) tuple, and both ways are updated."""
    try:
        f = w.cget("font")
    except Exception:
        f = None
    if isinstance(f, ctk.CTkFont):
        if f.cget("family") != family:
            f.configure(family=family)
    elif isinstance(f, (tuple, list)) and f:
        base = str(f[0])
        if "_fam0" not in w.__dict__:
            # the pen this widget was written with. A family that is neither language's -
            # the log's Consolas - is its own; anything else follows the language.
            w.__dict__["_fam0"] = base if base not in _PENS else FONT_EN
        want = w.__dict__["_fam0"] if family == FONT_EN else family
        if base != want:
            try:
                w.configure(font=(want,) + tuple(f[1:]))
            except Exception:
                pass
    try:
        kids = list(w.winfo_children())
    except Exception:
        kids = []
    for k in kids:
        refamily(k, family)


# the host names the room themselves; the secret of a room is its password,
# and that is 32 characters of OS randomness nobody can guess
def roll_password():
    return secrets.token_urlsafe(24)      # 32 characters, no guessable pattern


_CLIP_KEYS = {65: "sel", 67: "<<Copy>>", 86: "<<Paste>>", 88: "<<Cut>>"}


def _clip_do(w, act):
    try:
        if act == "sel":
            if w.winfo_class() == "Text":
                w.tag_add("sel", "1.0", "end-1c")
                w.mark_set("insert", "end-1c")
            else:
                w.select_range(0, "end")
                w.icursor("end")
        else:
            w.event_generate(act)
    except Exception:
        pass


def _clip_key(e):
    if e.state & 0x20000:
        return None
    act = _CLIP_KEYS.get(e.keycode)
    if not act:
        return None
    _clip_do(e.widget, act)
    return "break"


def fix_clipboard(widget):
    inner = getattr(widget, "_textbox", None) or getattr(widget, "_entry", None) or widget
    inner.bind("<Control-KeyPress>", _clip_key)

    def popup(e):
        m = tk.Menu(inner, tearoff=0)
        for label, act in (("Cut", "<<Cut>>"), ("Copy", "<<Copy>>"), ("Paste", "<<Paste>>"), ("Select all", "sel")):
            m.add_command(label=label, command=lambda a=act: _clip_do(inner, a))
        inner.focus_set()
        try:
            m.tk_popup(e.x_root, e.y_root)
        finally:
            m.grab_release()
    inner.bind("<Button-3>", popup)


def setw(w, **kw):
    if "text" in kw:
        w.__dict__["_src"] = kw["text"]
        w.__dict__.pop("_src_fmt", None)     # a line said outright outranks a remembered shape
        kw["text"] = T(kw["text"])
    cache = w.__dict__.setdefault("_last", {})
    ch = {k: v for k, v in kw.items() if cache.get(k) != v}
    if ch:
        cache.update(ch)
        w.configure(**ch)
        if "text" in ch and isinstance(w, Btn):
            w.refit()          # the new word may need more room than the old one


def setf(w, template, pieces=None, **kw):
    """A line made from a template. setw alone cannot serve here: by the time it is handed the
    text, the sentence is already assembled and the switch to the other language would only
    say it again in the words it happens to be in. So the shape and its pieces are kept, and
    the line is built anew every time the language changes. `pieces` are what fills the shape;
    anything else goes to the widget as style."""
    setw(w, text=fmt(template, **(pieces or {})), **kw)
    w.__dict__["_src_fmt"] = (template, dict(pieces or {}))


# ------------------------------------------------------------------ two languages
LANG = ["en"]        # "en" or "fa", the language the interface is drawn in
SOUND = [True]       # the little ding that answers a message

# English is what the code is written with; Persian is what the screen shows when
# the player asks for it. Names, numbers and the wordmark are never translated.
# Write the Persian the way it is said: bidi() puts the pieces of a mixed line in the order
# Tk has to be given them, so a name or a count never lands on the wrong side of its words.
TR = {
    # ------------------------------------------------- navigation and credits
    "Rooms": "اتاق‌ها",
    "Friends": "دوستان",
    "Friends & Chat": "دوستان و گفتگو",
    "Room": "اتاق",
    "Logs": "گزارش‌ها",
    "Settings": "تنظیمات",
    "Logout": "خروج",
    "DEVELOPED BY : Hossein42\nUI / UX DESIGN : Erfan.Sh":
        "برنامه: Hossein42\nطراحی: Erfan.Sh",
    "coded by Hossein & Erfan": "کدنویسی: Hossein و Erfan",
    "Room · {n}": "اتاق · {n}",
    # ------------------------------------------------- sign in
    "Username": "نام کاربری",
    "Password": "رمز عبور",
    "Login": "ورود",
    "Register": "ثبت‌نام",
    "Sign in": "ورود",
    "Enter your username and password.": "نام کاربری و رمزت را وارد کن.",
    "Signing in...": "در حال ورود...",
    "Signing in with the saved session...": "دارم با اطلاعات ذخیره‌شده وارد می‌شم...",
    "Please wait...": "لطفاً صبر کن...",
    "Remember me on this PC": "توی این سیستم خاطرم داشته باش",
    "● Connected": "● وصل",
    "● Connecting": "● در حال وصل شدن",
    "● Waiting": "● منتظر",
    "signed in as": "وارد شده با",
    "{app} network online": "شبکه‌ی {app} بالاست",
    # ------------------------------------------------- rooms page
    "Play together over a\nvirtual local network.": "با هم روی یک شبکه‌ی محلی مجازی بازی کن.",
    "Play together over a virtual local network.": "با هم روی یک شبکه‌ی محلی مجازی بازی کن.",
    "My rooms": "اتاق‌های من",
    "Create a room": "ساخت اتاق",
    "Join a room": "ورود به اتاق",
    "{n} / {m} rooms": "اتاق {n} از {m}",
    "No rooms yet - create one or join with an invite code.":
        "هنوز اتاقی نداری - یکی بساز یا با کد دعوت وارد شو.",
    "Waiting for your friends...\nSend them the invite code.":
        "در انتظار دوستانت...\nکد دعوت رو براشون بفرست.",
    "No friends yet.": "هنوز دوستی نداری.",
    "Create room": "ساخت اتاق",
    "Room name": "نام اتاق",
    "Room password": "رمز اتاق",
    "Join room": "ورود به اتاق",
    "Join": "پیوستن",
    "Enter": "ورود",
    "Invite": "دعوت",
    "Invite code": "کد دعوت",
    "Invite code from your friend": "کد دعوتی که دوستت فرستاده",
    "xxxx.xxxx.xxxx...": "xxxx.xxxx.xxxx...",
    "Copy invite code": "کپی کد دعوت",
    "This is not a valid invite code. Ask your friend to send it again.":
        "این کد دعوت درست نیست. از دوستت بخواه دوباره برات بفرسته.",
    "There is no invite code yet - enter a room first.":
        "هنوز کد دعوتی نیست - اول وارد یک اتاق شو.",
    "Invite code (already copied to your clipboard):":
        "کد دعوت (از قبل توی حافظه کپی شده):",
    "Copy code": "کپی کد",
    "The QR picture needs:  pip install qrcode[pil]":
        "برای تصویر QR این لازم‌ه:  pip install qrcode[pil]",
    # ------------------------------------------------- friends
    "Search": "جستجو",
    "Search username...": "جستجوی نام کاربری...",
    "Add": "افزودن",
    "Chat": "گفتگو",
    "Open": "باز کردن",
    "Accept": "قبول",
    "No users found.": "کاربری پیدا نشد.",
    "No friends yet - search a username above.":
        "هنوز دوستی نداری - بالا یک نام کاربری رو جستجو کن.",
    "No chat open": "گفتگویی باز نیست",
    "pick a friend on the left": "از سمت راست یک دوست را انتخاب کن",
    "Friends ({n})": "دوستان ({n})",
    "Friend requests ({n})": "درخواست‌های دوستی ({n})",
    "Make admin": "مدیر کردن",
    "Rank, permissions and the member limit": "نقش، اجازه‌ها و سقف اعضا",
    "{name}  (online)": "{name}  (آنلاین)",
    "Send": "ارسال",
    "Type a message...": "پیام بنویس...",
    "{n} online": "آنلاین: {n}",
    "{on} / {total} online": "آنلاین {on} از {total}",
    "0 online": "آنلاین: ۰",
    "{name} is typing ...": "{name} داره می‌نویسه...",
    "{a} and {b} are typing ...": "{a} و {b} دارن می‌نویسن...",
    "{n} people are typing ...": "در حال نوشتن: {n} نفر...",
    # ------------------------------------------------- inside a room
    "Players": "بازیکن‌ها",
    "Member limit:": "سقف اعضا:",
    "Leave room": "خروج از اتاق",
    "Admin panel": "پنل مدیر",
    "Room control": "کنترل اتاق",
    "Members": "اعضا",
    "Members - tap a rank or a permission to change it":
        "اعضا - برای تغییر نقش یا اجازه رویش بزن",
    "Ban list": "لیست مسدودها",
    "Ban": "مسدود",
    "Unban": "رفع مسدودی",
    "Approve": "قبول",
    "Member limit": "سقف اعضا",
    "Role defaults": "پیش‌فرض نقش‌ها",
    "{role} - by default": "{role} - پیش‌فرض",
    "What a member and an admin may do in this room by default":
        "توی این اتاق یک عضو و یک مدیر به‌طور پیش‌فرض چه کارهایی می‌تونن بکنن",
    "Room defaults saved": "پیش‌فرض‌های اتاق ذخیره شد",
    "Saving the defaults failed": "ذخیره کردن پیش‌فرض‌ها نشد",
    "Permission failed: {err}": "تغییر اجازه انجام نشد: {err}",
    "Invite code copied - send it to a friend": "کد دعوت کپی شد - بفرستیش برای دوستت",
    "The room has no invite code yet - the server may need updating. Ask the team to run their start_server.bat again.":
        "این اتاق هنوز کد دعوتی نداره؛ شاید سرور باید به‌روز بشه. از تیم بخواه start_server.bat رو دوباره اجرا کنه.",
    "You may not invite people into this room": "توی این اتاق نمی‌تونی کسی رو دعوت کنی",
    "Kick": "اخراج",
    "Remove admin": "برداشتن مدیر",
    "Apply": "اعمال",
    "Save": "ذخیره",
    "Set": "تنظیم",
    "Close": "بستن",
    "Paste": "چسباندن",
    "No banned users in this room.": "توی این اتاق کاربر مسدودی نیست.",
    "online": "آنلاین",
    "offline": "آفلاین",
    "timeout": "بی‌پاسخ",
    "role: {r}": "نقش: {r}",
    "(owner)": "(صاحب)",
    "(admin)": "(مدیر)",
    "owner": "صاحب",
    "admin": "مدیر",
    "member": "عضو",
    "member ": "عضو ",
    "👑 Owner": "👑 صاحب",
    "🛡 Admin": "🛡 مدیر",
    "Member": "عضو",
    "no reason": "بی‌دلیل",
    "Owner": "صاحب",
    "Admin": "مدیر",
    "{m} members · {o} online · you are {role} · limit {limit}":
        "عضو: {m} · آنلاین: {o} · نقش تو: {role} · سقف: {limit}",
    "you host this room": "میزبان این اتاق تو هستی",
    "inside this room": "توی این اتاق",
    "{who}   ·   {vip}   ·   role: {r}": "{who}   ·   {vip}   ·   نقش: {r}",
    "{who}   (you)": "{who}   (خودت)",
    "{vip}  ·  no answer since {t}": "{vip}  ·  از {t} بی‌پاسخ",
    "{vip} copied - paste it into the game": "{vip} کپی شد - توی بازی بچسبون",
    "Copied ✓": "کپی شد ✓",
    # ------------------------------------------------- logs
    "Copy log": "کپی گزارش",
    "Save log": "ذخیره‌ی گزارش",
    "Diagnostics": "عیب‌یابی",
    "Diag ZIP": "فایل عیب‌یابی",
    # ------------------------------------------------- settings
    "Language": "زبان",
    "Persian turns the whole app right-to-left.": "با فارسی کل برنامه راست‌به‌چپ می‌شه.",
    "Your support keeps our servers running - thank you.":
        "حمایت شما باعث می‌شه سرورهای ما روشن بمونه — سپاسگزاریم.",
    "Message sound": "صدای پیام",
    "On": "روشن",
    "Off": "خاموش",
    "Test sound": "تست صدا",
    "inside '{room}' - the room stays connected":
        "توی «{room}» هستی - اتصال اتاق برقراره",
    "Leaving {old} for {new}": "از {old} می‌رم بیرون تا {new} باز بشه",
    "Language: {which}": "زبان: {which}",
    # ------------------------------------------------- in-app notices
    "Friend request": "درخواست دوستی",
    "{name} wants to be your friend.": "{name} می‌خواد دوستت باشه.",
    "New message": "پیام تازه",
    "Join request": "درخواست ورود",
    "wants to join the room": "می‌خواد وارد اتاق بشه",
    "Decline": "رد کردن",
    "Requests": "درخواست‌ها",
    "{name} wants to join the room.": "{name} می‌خواد وارد اتاق بشه.",
    "{name} is {what}": "{name} {what}",
    "let in": "پذیرفته شد",
    "turned away": "رد شد",
    "Waiting to be let in ({n})": "منتظر پذیرش ({n})",
    "Nobody is waiting.": "کسی منتظر نیست.",
    "Waiting for the host of {room}": "در انتظار میزبانِ {room}",
    "{who} let you into {room}": "{who} تو رو به اتاق {room} راه داد",
    "{who} did not let you in": "{who} تو رو راه نداد",
    # ------------------------------------------------- the log, the chat, the panels
    "system": "سیستم",
    "Room name and password are required.": "نام و رمز اتاق لازم‌ه.",
    "Still finishing the previous room - one moment.":
        "اتاق قبلی هنوز بسته نشده - یک لحظه صبر کن.",
    "Left the room": "از اتاق خارج شدی",
    "Not connected": "به سرور وصل نیستی",
    "Could not send - check the connection to the server":
        "فرستاده نشد - اتصال به سرور رو بررسی کن",
    "Log copied to clipboard": "گزارش کپی شد",
    "Collecting diagnostics (a few seconds)...": "دارم اطلاعات عیب‌یابی رو جمع می‌کنم (چند ثانیه)...",
    "Invite loaded - log in to join the room.":
        "دعوت آماده‌ست - برای ورود به اتاق وارد شو.",
    "This PC already has 3 accounts - sign in to one of them instead":
        "توی این سیستم از قبل ۳ حساب هست - وارد یکی از همونا شو",
    "This account was used to sign in on another device.":
        "این حساب توی دستگاه دیگه‌ای وارد شده.",
    "Connection to the server lost. Please log in again.":
        "اتصال به سرور قطع شد. دوباره وارد شو.",
    "wintun.dll is required. Press the button again after you have it.":
        "فایل wintun.dll لازم‌ه. وقتی آماده شد دوباره دکمه رو بزن.",
    "Entering…": "در حال ورود…",
    "Kick failed: {err}": "اخراج انجام نشد: {err}",
    "Ban failed: {err}": "مسدود نشد: {err}",
    "Unban failed: {err}": "رفع مسدودی نشد: {err}",
    "Ban list failed: {err}": "لیست مسدودها نیامد: {err}",
    "Limit failed: {err}": "سقف تنظیم نشد: {err}",
    "Admin update failed: {err}": "تغییر مدیر انجام نشد: {err}",
    "User {name} unbanned": "مسدودی {name} برداشته شد",
    "by {who}  ·  {why}": "توسط {who}  ·  {why}",
    "Diagnostics ZIP saved: {path}": "فایل عیب‌یابی ذخیره شد: {path}",
    # ------------------------------------------------- what the log and notices say
    "Could not answer the request: {err}": "نتونستم جواب درخواست رو بدم: {err}",
    "Layout: {e}": "چیدمان: {e}",
    "Logged in as {name}": "وارد شدی: {name}",
    "Connecting to room '{room}'...": "در حال ورود به اتاق '{room}'...",
    "Create room failed: {err}": "اتاق ساخته نشد: {err}",
    "Join failed: {err}": "ورود به اتاق انجام نشد: {err}",
    "Removed '{room}' from your rooms": "اتاق '{room}' از اتاق‌هایت برداشته شد",
    "Remove failed: {err}": "برداشته نشد: {err}",
    "{cmd} failed: {err}": "{cmd} انجام نشد: {err}",
    "{name} is now your friend": "{name} الان دوستته",
    "Invite sent to {name}": "دعوت برای {name} فرستاده شد",
    "Invite failed: {err}": "دعوت فرستاده نشد: {err}",
    "You were kicked from the room by {by}": "{by} تو رو از اتاق اخراج کرد",
    "You were banned from the room by {by} ({reason})": "{by} تو رو از اتاق مسدود کرد ({reason})",
    "You were kicked by {by}.": "{by} تو رو اخراج کرد.",
    "You were banned by {by} ({reason}).": "{by} تو رو مسدود کرد ({reason}).",
    "{name} went offline: {why}": "{name} آفلاین شد: {why}",
    "{who} sent you a friend request": "{who} برایت درخواست دوستی فرستاد",
    "{who} is not online - your message was not delivered": "{who} آنلاین نیست - پیامت نرسید",
    "Chat failed: {err}": "گفتگو انجام نشد: {err}",
    "{who} invited you to the room '{room}'": "{who} تو رو به اتاق '{room}' دعوت کرد",
    "Connection to the server lost: {why}": "اتصال به سرور قطع شد: {why}",
    "entering '{room}' - preparing the virtual adapter...":
        "وارد '{room}' می‌شم - دارم کارت شبکه‌ی مجازی رو آماده می‌کنم...",
    # ------------------------------------------------- the password card
    "Current password": "رمز فعلی",
    "New password": "رمز جدید",
    "New password again": "تکرار رمز جدید",
    "Change password": "تغییر رمز",
    "Fill in the current and the new password.": "رمز فعلی و رمز جدید را بنویس.",
    "The two new passwords do not match.": "دو رمز جدید یکی نیستن.",
    "You are not signed in.": "وارد نشده‌ای.",
    "Password changed OK": "رمز تغییر کرد ✓",
    "Your password was changed": "رمزت عوض شد",
    "Current password is wrong": "رمز فعلی درست نیست",
    "New password must be at least 6 characters":
        "رمز جدید باید حداقل ۶ کاراکتر باشه",
    "The new password is the same as the old one": "رمز جدید با قبلی یکی‌ه",
    # ------------------------------------------------- the management panel
    "Management": "مدیریت",
    "Open the console": "باز کردن کنسول",
    "This account is one the team vouched for.": "این حساب رو تیم تأیید کرده.",
    "The network, for the team": "شبکه، از نگاه تیم",
    "Refresh": "به‌روزرسانی",
    "Loading {what}...": "در حال بارگذاری {what}...",
    "{what}   ·   {n} rows": "{what}   ·   ردیف: {n}",
    "Make team": "تیم کردن",
    "Remove from team": "خارج کردن از تیم",
    "This is not the management console": "این کنسول مدیریت نیست",
    "Users": "کاربران",
    "Traffic": "ترافیک",
    "Name": "نام",
    "ID": "شناسه",
    "Last seen": "آخرین بازدید",
    "Made": "ساخته",
    "PC": "سیستم",
    "Online": "آنلاین",
    "Data": "حجم",
    "Team": "تیم",
    "Limit": "سقف",
    "Day": "امروز",
    "Search...": "جستجو...",
    "Management access for this account changed": "دسترسی مدیریت این حساب عوض شد",
    "The server refused that.": "سرور این کار رو نپذیرفت.",
    "Use a whole number from 2 to 64": "یک عدد صحیح بین ۲ تا ۶۴ بنویس.",
    "A room name is 1-32 characters": "نام اتاق باید ۱ تا ۳۲ کاراکتر باشه.",
    "Delete": "حذف",
    "Sure?": "مطمئنی؟",
    "Close chat": "بستن گفتگو",
    "(management)": "(مدیریت)",
    "Enter room": "ورود به اتاق",
}
# a segmented button hands back whatever it shows, so the handlers need the way home
UNTR = {v: k for k, v in reversed(list(TR.items()))}


def un(value):
    """Turn a displayed string back into the English the code thinks in."""
    return UNTR.get(value, value) if isinstance(value, str) else value


def T(s):
    """Translate a fixed English string; anything dynamic passes straight through. The
    Persian that comes back is written the way Tk has to be given it."""
    if LANG[0] == "en" or not isinstance(s, str):
        return s
    return bidi(TR.get(s, s))


class word(str):
    """A piece of a line that is a word of the interface rather than a fact from the server.
    Marking it lets a line told later be told in the new language too - a room name or a
    username is never translated, but "let in" and "timeout" are."""


def fmt(template, **kw):
    """Translate the sentence shape first, then fill it in, so the word order can be different
    in Persian without breaking the value. A filled-in line usually carries a name or a number
    in Latin letters, and that is exactly what makes Tk lay the line out the wrong way round -
    so bidi() hands the pieces over in the order it has to be given them."""
    if LANG[0] == "en":
        return template.format(**kw)
    return bidi(TR.get(template, template).format(
        **{k: (T(v) if isinstance(v, word) else v) for k, v in kw.items()}))


def flip(opts, rtl):
    """Mirror one geometry manager's options: sides, anchors, padding, sticky."""
    o = dict(opts)
    if not rtl:
        return o
    if o.get("side") == "left":
        o["side"] = "right"
    elif o.get("side") == "right":
        o["side"] = "left"
    a = o.get("anchor", "")
    o["anchor"] = {"w": "e", "e": "w", "nw": "ne", "ne": "nw", "sw": "se", "se": "sw"}.get(a, a)
    px = o.get("padx")
    if isinstance(px, (tuple, list)) and len(px) == 2:
        o["padx"] = (px[1], px[0])
    st = o.get("sticky", "")
    if st:
        o["sticky"] = st.replace("w", "\u0001").replace("e", "w").replace("\u0001", "e")
    rx = o.get("relx")
    if rx is not None and str(rx) != "":
        try:
            o["relx"] = 1.0 - float(rx)
            o["x"] = -int(float(o.get("x", 0) or 0))
        except (TypeError, ValueError):
            pass
    return o


_GCK = {"pack": ("side", "anchor", "fill", "expand", "padx", "pady", "ipadx", "ipady"),
        "grid": ("column", "columnspan", "row", "rowspan", "sticky", "padx", "pady", "ipadx", "ipady"),
        "place": ("relx", "rely", "x", "y", "anchor", "width", "height", "relwidth", "relheight")}
_GDEF = {"pack": dict(side="left", anchor="center", fill="none", expand=0, padx=(0, 0), pady=(0, 0),
                      ipadx=0, ipady=0),
         "grid": dict(column=0, columnspan=1, row=0, rowspan=1, sticky="", padx=(0, 0), pady=(0, 0),
                      ipadx=0, ipady=0),
         "place": {}}
_NUM = {"relx", "rely", "x", "y", "width", "height", "relwidth", "relheight"}
_INT = {"expand", "column", "columnspan", "row", "rowspan", "ipadx", "ipady"}
# the names each manager actually takes. The mirror has to obey them: a grid widget handed
# pack's "side", or the "anchor" the flip always writes, makes Tcl refuse the call - and
# because the forget already happened by then, the word being drawn there just vanishes.
_OPTS = {"pack": frozenset(("after", "anchor", "before", "expand", "fill", "ipadx",
                            "ipady", "padx", "pady", "side")),
         "grid": frozenset(("column", "columnspan", "ipadx", "ipady", "padx", "pady",
                            "row", "rowspan", "sticky")),
         "place": frozenset(("anchor", "borderwidth", "height", "relheight", "relwidth",
                             "relx", "rely", "width", "x", "y"))}


def _gv(d, key, mgr):
    """One geometry option, read the same way whether Tcl gave a string, a tuple or a number."""
    v = d.get(key, _GDEF[mgr].get(key, ""))
    if key in ("padx", "pady"):
        if isinstance(v, (tuple, list)) and len(v) == 2:
            try:
                return int(v[0]), int(v[1])
            except (TypeError, ValueError):
                return 0, 0
        try:
            return int(v), int(v)
        except (TypeError, ValueError):
            return 0, 0
    if key == "sticky":
        return "".join(sorted({c for c in str(v) if c in "nesw"}))
    if key in _NUM:
        try:
            return round(float(v), 4)
        except (TypeError, ValueError):
            return None
    if key in _INT:
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0
    return str(v)


def geo_eq(a, b, mgr):
    return all(_gv(a, k, mgr) == _gv(b, k, mgr) for k in _GCK[mgr])


def _info(k, mgr):
    try:
        return dict(k.pack_info() if mgr == "pack" else
                    (k.grid_info() if mgr == "grid" else k.place_info()))
    except Exception:
        return {}


def mirror_of(en, mgr, rtl, cols=1):
    """Where the English arrangement puts a widget, and where this language wants it -
    written as options that manager accepts, so putting one back never fails."""
    o = flip(en, rtl)
    if rtl:
        if mgr == "grid":
            o["column"] = cols - int(en.get("column", 0) or 0) - int(en.get("columnspan", 1) or 1)
        if mgr == "place" and o.get("relx") is None:
            o.pop("x", None)
    return {a: b for a, b in o.items()
            if a in _OPTS[mgr] and a not in ("in", "before", "after") and b != ""}


def _plan(k, mgr, rtl, cols):
    """Where this language wants one widget, and where it sits now. None when the widget is
    hidden or has asked not to be moved - mirroring a hidden widget would pack it onto the
    screen. The English arrangement is remembered the first time we see it, so the mirror can
    be run again and again without drifting, and a spot the code itself moved becomes the
    new English one instead of being fought over."""
    if k.__dict__.get("_nomirror"):
        return None
    cur = _info(k, mgr)
    if not cur:
        return None
    snap = k.__dict__.get("_geo0")
    en = dict(cur) if snap is None or snap[0] != mgr else snap[1]
    k.__dict__["_geo0"] = (mgr, en)
    want = mirror_of(en, mgr, rtl, cols)
    last = k.__dict__.get("_geo1")          # the arrangement the mirror itself wrote
    if last is not None and not geo_eq(cur, last, mgr) and not geo_eq(cur, en, mgr):
        en = k.__dict__["_geo0"][1] = dict(cur)
        want = mirror_of(en, mgr, rtl, cols)
    k.__dict__["_geo1"] = dict(want)
    return cur, want


def _move(k, mgr, cur, want):
    """Put the widget down where `want` says, and never leave it with no manager at all."""
    try:
        getattr(k, mgr + "_forget")()
        getattr(k, mgr)(**want)
    except Exception:
        try:
            getattr(k, mgr)(**{a: b for a, b in cur.items()
                               if a in _OPTS[mgr] and a != "in" and b != ""})
        except Exception:
            pass


def _mirror_one(k, mgr, rtl, cols):
    """Put one widget where this language wants it, keeping the English intent we saw first."""
    plan = _plan(k, mgr, rtl, cols)
    if plan is None:
        return
    cur, want = plan
    if geo_eq(cur, want, mgr):
        return
    _move(k, mgr, cur, want)


def _group_order(w, group):
    """The stack the way it really sits. pack_slaves is the stacking order - the order the
    code packed them, with every before= and after= obeyed - while winfo_children is only the
    order they were born in. Reading the wrong one is how the player list ended up under the
    "waiting for your friends" line: that caption was built before any player, so birth order
    put it at the head of the column in both languages."""
    try:
        slaves = list(w.pack_slaves())
    except Exception:
        slaves = []
    in_group = {id(k) for k in group}
    seen = {id(k) for k in slaves if id(k) in in_group}
    return [k for k in slaves if id(k) in in_group] + [k for k in group if id(k) not in seen]


def _mirror_pack_group(w, kids, rtl, cols):
    """Move a whole packed column at once. pack puts a widget at the END of its side's stack,
    so re-packing only the ones that changed would shuffle the rest of the column - which is
    how the landing menu ended up with its friend list above the logo. The order they stand in
    now is read from the packer itself and written back with after=, so the stack keeps its
    shape in both languages: turning a column round flips which side it grows from, never
    which line is first."""
    group = [k for k, m in kids if m == "pack"]
    if not group:
        return
    order = _group_order(w, group)
    plans, move = [], False
    for k in order:
        plan = _plan(k, "pack", rtl, cols)
        plans.append(plan)
        if plan is not None and not geo_eq(plan[0], plan[1], "pack"):
            move = True
    if not move:
        return
    for k, plan in zip(order, plans):       # forget first: a half-packed stack is a shuffled one
        if plan is not None:
            try:
                k.pack_forget()
            except Exception:
                pass
    prev = None
    for k, plan in zip(order, plans):
        if plan is None:
            continue
        cur, want = plan
        want = dict(want)
        if prev is not None:
            want["after"] = prev
        _move(k, "pack", cur, want)
        prev = k


def _box(w):
    """A widget this app places its own children in: a window, a plain frame, a scroll list,
    or the glass a scroll list is built inside. Not a frame that merely inherits from one -
    the segmented switch is a CTkFrame too, and everything inside it belongs to customtkinter."""
    try:
        return w is w.winfo_toplevel() or type(w) in (ctk.CTkFrame, ctk.CTkScrollableFrame,
                                                      tk.Canvas)
    except Exception:
        return False


def _glass(w):
    """True for the case customtkinter wraps a scroll list in: the frame that holds its canvas,
    the bar beside it and the caption over both. None of those may move - the canvas has to keep
    the column that stretches - so they are walked through but never mirrored."""
    try:
        return any(type(k) is tk.Canvas and
                   any(type(g) is ctk.CTkScrollableFrame for g in k.winfo_children())
                   for k in w.winfo_children())
    except Exception:
        return False


def _kids(w):
    """Every child with the manager that moves it, or None for a child no manager holds.
    Only the boxes this app places things in are walked: customtkinter keeps its own parts
    - the label inside a button, the entry inside a box, the two buttons inside a
    segmented switch - grid-managed inside the widget, and moving one of those unpacks it,
    which is how a word being drawn there silently disappears."""
    if not _box(w):
        return []
    try:
        kids = list(w.winfo_children())
    except Exception:
        return []
    if _glass(w):
        return [(k, None) for k in kids]
    out = []
    for k in kids:
        for m in ("pack", "grid", "place"):
            if _info(k, m):
                out.append((k, m))
                break
        else:
            out.append((k, None))
    return out


def _cget(w, c):
    """One column's shape: how much slack it takes, the width it insists on, its share group."""
    d = w.grid_columnconfigure(c)
    return (int(d.get("weight", 0) or 0), int(d.get("minsize", 0) or 0),
            str(d.get("uniform", "") or ""))


def _cols_shape(w, cols, rtl):
    """The stretchy column crosses over with the widgets that sit in it. Without this the
    slack of a mirrored row opens up in the middle of it and pushes its halves apart."""
    if cols < 2:
        return
    try:
        base = w.__dict__.get("_cw0")
        if base is None:
            base = w.__dict__["_cw0"] = {c: _cget(w, c) for c in range(cols)}
    except Exception:
        return
    for c, cfg in base.items():
        at = cols - 1 - c if rtl else c
        try:
            if _cget(w, at) != cfg:
                w.grid_columnconfigure(at, weight=cfg[0], minsize=cfg[1], uniform=cfg[2])
        except Exception:
            pass


def mirror_tree(w, rtl):
    """Walk every page, panel and floating window and put each widget where the other
    language would have it. English is the arrangement the code writes, Persian is its
    mirror. A widget already sitting where it belongs is left alone, so this can run
    again whenever new content appears without disturbing what is already right."""
    kids = _kids(w)
    cols = 1
    for k, m in kids:
        if m == "grid":
            en = k.__dict__.setdefault("_geo0", ("grid", _info(k, "grid")))[1]
            cols = max(cols, int(en.get("column", 0) or 0) + int(en.get("columnspan", 1) or 1))
    if any(m == "grid" for _, m in kids):
        _cols_shape(w, cols, rtl)
    _mirror_pack_group(w, kids, rtl, cols)
    for k, m in kids:
        if m is not None and m != "pack":
            _mirror_one(k, m, rtl, cols)
    for k, m in kids:
        mirror_tree(k, rtl)


def retext_tree(w):
    """Hand every widget its words back in the language we are drawing in now."""
    for k in w.winfo_children():
        made = k.__dict__.get("_src_fmt")
        src = k.__dict__.get("_src")
        if made is not None:
            try:
                say = fmt(made[0], **made[1])      # the sentence built again, in the new words
                k.configure(text=say)
                k.__dict__.setdefault("_last", {})["text"] = say
                if isinstance(k, Label):
                    k.rejust()
                if isinstance(k, Btn):
                    k.refit()
            except Exception:
                pass
        elif src is not None:
            try:
                k.configure(text=T(src))
                k.__dict__.setdefault("_last", {})["text"] = T(src)
                if isinstance(k, Label):
                    k.rejust()
                if isinstance(k, Btn):
                    k.refit()
            except Exception:
                pass
        if isinstance(k, Seg):
            try:
                k.retext()
            except Exception:
                pass
        ph = k.__dict__.get("_src_ph")
        if ph:
            try:
                if isinstance(k, TextLine):
                    k.reph()
                else:
                    k.configure(placeholder_text=T(ph))
            except Exception:
                pass
        retext_tree(k)


class Label(ctk.CTkLabel):
    """A label that remembers the English it was written with, and the side its own words
    were meant to hug - a full-width label puts its text where `anchor` says, and Persian
    reads from the other side."""

    def __init__(self, master=None, **kw):
        if "text" in kw:
            self._src = kw["text"]
            kw["text"] = T(kw["text"])
        if kw.get("justify") in ("left", "right"):
            self._just = kw["justify"]
            kw["justify"] = "right" if (self._just == "left" and LANG[0] == "fa") else kw["justify"]
        if kw.get("anchor") in ("w", "e"):
            self._anch = kw["anchor"]
            kw["anchor"] = ("e" if self._anch == "w" else "w") if LANG[0] == "fa" else kw["anchor"]
        super().__init__(master, **kw)

    def rejust(self):
        j = getattr(self, "_just", None)
        if j:
            self.configure(justify="right" if (j == "left" and LANG[0] == "fa")
                                  else "left" if (j == "right" and LANG[0] == "fa") else j)
        a = getattr(self, "_anch", None)
        if a:
            self.configure(anchor="e" if (a == "w" and LANG[0] == "fa")
                                  else "w" if (a == "e" and LANG[0] == "fa") else a)


class Btn(ctk.CTkButton):
    """A button carrying the words of the language we are drawing in. Persian words are
    longer than the English they replace, so a button with a fixed width is widened to fit
    the word it actually shows - otherwise the label is clipped from both ends."""

    def __init__(self, master=None, **kw):
        if "text" in kw:
            self._src = kw["text"]
            kw["text"] = T(kw["text"])
        self._base = kw.get("width") or 0
        super().__init__(master, **kw)
        self.refit()

    def refit(self):
        """Wide enough for the word it shows, never narrower than the code asked for. Small
        buttons get a tighter fit - their rows have no slack for generous margins."""
        if not self._base:
            return
        try:
            f = self.cget("font")
            if isinstance(f, (tuple, list)):
                edge = 12 if self._base < 80 else 22
                want = max(self._base, tkfont.Font(font=f).measure(str(self.cget("text"))) + edge)
                if int(self.cget("width")) != want:
                    self.configure(width=want)
        except Exception:
            pass


class Chk(ctk.CTkCheckBox):
    def __init__(self, master=None, **kw):
        if "text" in kw:
            self._src = kw["text"]
            kw["text"] = T(kw["text"])
        super().__init__(master, **kw)


class Seg(ctk.CTkSegmentedButton):
    def __init__(self, master=None, **kw):
        if "values" in kw:
            self._src = list(kw["values"])
            kw["values"] = [T(v) for v in kw["values"]]
        super().__init__(master, **kw)

    def retext(self):
        keep = un(self.get())        # which button was picked, in English
        self.configure(values=[T(v) for v in self._src])
        self.set(T(keep))            # shown again in the language we are drawing in


def _colorref(hexcolor):
    h = hexcolor.lstrip("#")
    return int(h[4:6], 16) << 16 | int(h[2:4], 16) << 8 | int(h[0:2], 16)


def style_window(win):
    try:
        win.update_idletasks()
        user32, dwm = ctypes.windll.user32, ctypes.windll.dwmapi
        user32.GetParent.argtypes, user32.GetParent.restype = [c_void_p], c_void_p
        dwm.DwmSetWindowAttribute.argtypes = [c_void_p, c_uint32, c_void_p, c_uint32]
        hwnd = user32.GetParent(win.winfo_id()) or win.winfo_id()
        for attr, val in ((20, 1), (19, 1), (35, _colorref(BG)), (36, _colorref(TXT)), (34, _colorref(LINE))):
            v = ctypes.c_int(val)
            dwm.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(v), ctypes.sizeof(v))
    except Exception:
        pass


def make_icon(path):
    """The app icon: a big bold '42'."""
    from PIL import Image, ImageDraw, ImageFont
    S = 256
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((6, 6, S - 6, S - 6), radius=58, fill=CARD, outline=ACC, width=8)
    f = None
    for name, size in (("segoeuib.ttf", 150), ("arialbd.ttf", 150), ("arial.ttf", 150)):
        try:
            f = ImageFont.truetype(os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", name), size)
            break
        except OSError:
            continue
    if f is None:
        f = ImageFont.load_default()
    text = "42"
    l, t, r, b = d.textbbox((0, 0), text, font=f)
    d.text(((S - (r - l)) / 2 - l, (S - (b - t)) / 2 - t), text, font=f, fill=ACC)
    img.save(path, format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


class TextLine(ctk.CTkTextbox):
    """Single-line input on a Text widget: Persian (RTL) text types correctly."""

    def __init__(self, master, placeholder="", on_enter=None, height=40, on_type=None, **kw):
        super().__init__(master, height=height, wrap="none", activate_scrollbars=False, fg_color=CARD2,
                         border_width=1, border_color=LINE, corner_radius=8, font=(FONT, 14),
                         text_color=TXT, **kw)
        self.ph, self.on_enter, self.ph_on = placeholder, on_enter, False
        self._src_ph = placeholder
        self.ph = T(placeholder)
        self.on_type = on_type
        self.rtl_on = False
        self.tag_config("rtl", justify="right")
        self.tag_config("ph", foreground=GRAY)
        self.bind("<FocusIn>", lambda e: self.clear_ph())
        self.bind("<FocusOut>", lambda e: self.show_ph())
        self.bind("<Return>", self.enter)
        self.bind("<KeyRelease>", self.on_key)
        fix_clipboard(self)
        self.show_ph()

    def on_key(self, e=None):
        self.align()
        if self.on_type and not self.ph_on:
            self.on_type()

    def show_ph(self):
        if self.ph and not self.get("1.0", "end-1c"):
            self.insert("1.0", self.ph, "ph")
            self.ph_on = True

    def reph(self):
        """Same hint, in the language we are drawing in now."""
        self.ph = T(self._src_ph)
        if self.ph_on:
            self.delete("1.0", "end")
            self.ph_on = False
            self.show_ph()
        elif self.get("1.0", "end-1c") == self.ph:
            self.delete("1.0", "end")
            self.show_ph()

    def clear_ph(self):
        if self.ph_on:
            self.delete("1.0", "end")
            self.ph_on = False

    def enter(self, e=None):
        if self.on_enter:
            self.on_enter()
        return "break"

    def align(self):
        """Flip the line to right-to-left the moment Persian letters appear.
        Only touch the tags when the direction really changes - re-tagging every
        keystroke is what made the caret jump around behind the text."""
        if self.ph_on:
            return
        rtl = has_rtl(self.get("1.0", "end-1c"))
        if rtl == self.rtl_on:
            return
        self.rtl_on = rtl
        caret = self.index("insert")
        self.tag_remove("rtl", "1.0", "end")
        if rtl:
            self.tag_add("rtl", "1.0", "end")
        self.mark_set("insert", caret)
        self.update_idletasks()        # redraw now, so the caret is on the right on the first letter

    def value(self):
        return "" if self.ph_on else self.get("1.0", "end-1c").replace("\n", " ").strip()

    def set(self, text):
        self.clear_ph()
        self.delete("1.0", "end")
        self.insert("1.0", text)
        self.align()
        if not text and self.focus_get() is not self._textbox:
            self.show_ph()


class Splitter(ctk.CTkFrame):
    """A thin draggable line between two columns. Drag it and the column it follows takes
    that width - so a long username is read whole instead of being cut off, and nothing
    has to be guessed at or re-typed."""

    def __init__(self, master, apply, lo=200, hi=760):
        super().__init__(master, fg_color=LINE, corner_radius=3, width=8,
                         cursor="sb_h_double_arrow")
        self.apply, self.lo, self.hi = apply, lo, hi
        self.bind("<B1-Motion>", self.move)
        self.bind("<Enter>", lambda e: self.configure(fg_color=ACC))
        self.bind("<Leave>", lambda e: self.configure(fg_color=LINE))

    def move(self, e):
        box = self.master
        scale = max(0.5, getattr(self, "_widget_scaling", 1.0) or 1.0)
        if LANG[0] == "fa":     # the column grows from the right, so the ruler starts there
            w = box.winfo_rootx() + box.winfo_width() - e.x_root
        else:
            w = e.x_root - box.winfo_rootx()
        self.apply(max(self.lo, min(self.hi, int(w / scale))))


ROLE_BADGE = {"owner": ("👑 Owner", GOLD), "admin": ("🛡 Admin", BLUE), "member": ("Member", MUTED)}
# the word that trails a name wherever the roster or a chat line shows it
RANK_MARK = {"owner": "(owner)", "admin": "(admin)"}
# the team, standing inside someone else's room: every permission, and said in red
MGR_BADGE = ("Management", NAME_RED)
MGR_MARK = "(management)"


def by_name(entry):
    """The name a list is ordered by - case makes no difference to a player scanning
    down a column of names in either language."""
    return str(entry.get("name") or "").lower()


def by_role(entry):
    """The players column leads with the ranks: owner at the top, then the admins, then
    everybody else, each group on its own names. A rank that is not one of the three sits
    at the bottom rather than disappearing from the list."""
    return ({"owner": 0, "admin": 1, "member": 2}.get(entry.get("role") or "member", 3),
            by_name(entry))


def rank_mark(role, mgr=False):
    return MGR_MARK if mgr else RANK_MARK.get(role or "member", "")


def rank_color(role, mgr=False):
    """The colour a rank is written in - and the team's own word is always red."""
    if mgr:
        return NAME_RED
    return GOLD if role == "owner" else BLUE if role == "admin" else MUTED


def with_rank(name, role, mgr=False):
    """A name and the word that trails it. Here the mark is translated on the way in: this
    builds a sentence the code shows as it stands, and only a widget's own text is re-read
    in the other language when the app switches."""
    mark = rank_mark(role, mgr)
    return bidi(f"{name}  {T(mark)}") if mark else name


class App(ctk.CTk):
    def __init__(self, invite=None):
        super().__init__()
        self.attributes("-alpha", 0.0)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")
        self.title(APP_NAME)
        self.geometry("1000x680")
        self.minsize(920, 620)
        self.configure(fg_color=BG)
        self.closing, self.last_log, self.empty_on = False, "", False
        self.log_src = deque(maxlen=1500)   # every line in the words it was written in,
                                            # so the log can be said again in the new language
        self.ui_err_t, self.hangf = 0.0, None
        self.frozen_before, self.fa_font = "", None
        # a frozen UI is the one thing worth writing outside the app folder: it lands in the
        # system temp dir, is read back into the Logs page on the next start, and never stays
        try:
            if os.path.exists(HANG_FILE) and os.path.getsize(HANG_FILE):
                with open(HANG_FILE, "r", encoding="utf-8", errors="replace") as f:
                    old = f.read()[-4000:]
                os.remove(HANG_FILE)
                if old.strip():
                    self.frozen_before = old        # told once the log queue exists
            self.hangf = open(HANG_FILE, "w", buffering=1)
            self.hangf.write(f"--- {time.strftime('%Y-%m-%d %H:%M:%S')} session start ---\n")
        except OSError:
            self.hangf = None
        threading.excepthook = lambda a: self.q_put("THREAD ERROR:\n" + "".join(
            traceback.format_exception(a.exc_type, a.exc_value, a.exc_traceback)))
        self.logo_path = res_path(LOGO_FILE)
        self.ico_file = None
        try:
            ico = self.logo_path
            if not ico:
                ico = os.path.join(tempfile.gettempdir(), "vlan42_icon.ico")
                if not os.path.exists(ico):
                    make_icon(ico)
            self.iconbitmap(ico)
            self.ico_file = ico
        except Exception:
            pass
        self.logo_img = self.nav_logo = self.card_logo = None
        if self.logo_path:
            try:
                from PIL import Image
                im = Image.open(self.logo_path)
                im.size = max(im.info.get("sizes") or [im.size])
                im.load()
                im = im.convert("RGBA")
                self.logo_pil = im
                self.logo_img = ctk.CTkImage(light_image=im, dark_image=im, size=(84, 84))
                self.nav_logo = ctk.CTkImage(light_image=im, dark_image=im, size=(26, 26))
                self.card_logo = ctk.CTkImage(light_image=im, dark_image=im, size=(40, 40))
            except Exception:
                self.logo_img = self.nav_logo = self.card_logo = None

        self.link, self.node, self.busy, self.page = None, None, False, None
        self.q, self.cq, self.uq = queue.Queue(), queue.Queue(), queue.Queue()
        if self.frozen_before:
            self.q_put("Last session left a freeze report:\n" + self.frozen_before)
        self.rows, self.room_rows, self.stat = {}, {}, (time.time(), 0, 0)
        self.my_rooms, self.friends = [], {"friends": [], "requests": []}
        self.rooms_empty = None
        self.need_wintun, self.auto_connect = False, False
        self.last_args, self.invite_text, self.err = None, "", ""
        self.room_name, self.my_name = "", ""
        self.pending_enter = None       # invite token waiting for login
        self.role_key = None
        self.invite = None              # {"from","room","token"}
        self.awin = None
        self.cwin = None            # the management panel
        self.con_last = None        # the last table it was shown, so the words can change
        self.staff = False            # the team vouched for this account
        self.admin_tab = "Members"      # which part of the admin panel is showing
        self.role_defaults = None       # this room's own defaults for member and admin
        self.jwin = None                # join-request panel
        self.jreq, self.jreq_n = [], 0  # who knocked on the room door
        self.await_enter = None         # room id we are waiting to be let into
        self.hint_live, self.hint_t, self.hint_kind = False, 0, None   # the notice line
        self.rooms_t = 0.0
        self.entering_rid = None
        self.tab = None                  # the tab the player opened
        self.mirror_t = 0.0              # when to fold new widgets into the Persian mirror
        self.tabs = {}                   # key -> (holder frame, button, badge)
        self.pages = {}
        self.pms, self.pm_unread = {}, {}    # friend name -> thread / unread count
        self.sel_friend = None
        self.type_t = {}                     # thread -> when we last said "typing"
        self.typing_room, self.typing_pm = {}, {}   # name -> when the dots expire
        cfg = load_cfg()
        # the words the player chose, but the widgets are always built in the English
        # arrangement first - Persian is that arrangement seen in a mirror.
        first_lang = cfg.get("lang", "en")
        LANG[0], SOUND[0] = "en", bool(cfg.get("sound", True))
        self.body = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.build_nav()
        self.build_login(cfg)
        self.build_start(cfg)
        self.build_friends()
        self.build_logs()
        self.build_room()
        self.build_settings()
        self.build_hint()
        self.pages = {"login": self.pg_login, "start": self.pg_start, "friends": self.pg_friends,
                      "logs": self.pg_logs, "room": self.pg_room, "settings": self.pg_settings}
        self.show_page("login")
        if first_lang == "fa":
            LANG[0] = "fa"
            self.relayout()
        self.after(1000, self.refresh)
        self.after(60, self.show_main)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        if invite:
            tok = parse_invite(invite)
            if tok:
                self.pending_enter = tok   # sealed until the VPS opens it after login
                self.err = "Invite loaded - log in to join the room."

    def q_put(self, s):
        self.q.put(mask_net(s))        # the address of the network never reaches a screen

    def q_putf(self, template, **pieces):
        """A log line said from a template. Keeping the shape and its pieces, instead of the
        finished sentence, is what lets the log be told again after a language switch."""
        self.q.put((template, {k: mask_net(v) if isinstance(v, str) else v
                               for k, v in pieces.items()}))

    def say(self, item):
        """One stored log line, in the language the app is drawn in now."""
        if isinstance(item, tuple):
            return fmt(item[0], **item[1])
        return T(item)

    # ------------------------------------------------------------ small helpers
    def cap(self, parent, text):
        Label(parent, text=text, font=(FONT, 12), text_color=MUTED, anchor="w").pack(
            fill="x", padx=2, pady=(12, 3))

    def entry(self, parent, ph="", show=None):
        e = ctk.CTkEntry(parent, placeholder_text=T(ph), height=40, font=(FONT, 14), fg_color=CARD2,
                         border_color=LINE, text_color=TXT, show=show)
        e.__dict__["_src_ph"] = ph
        fix_clipboard(e)
        return e

    def btn(self, parent, text, cmd, color=ACC, hover=ACC_H, h=40, **kw):
        if "text_color" not in kw:
            kw["text_color"] = ACC_TXT if color == ACC else TXT
        opts = dict(height=h, fg_color=color, hover_color=hover, font=(FONT, 13, "bold"),
                    corner_radius=10)
        opts.update(kw)          # a caller may want its own corner or font, and it wins
        return Btn(parent, text=text, command=cmd, **opts)

    def flash(self, b, text):
        """Say something on a button for a moment, in the colour of a job done."""
        if not hasattr(b, "orig"):
            b.orig, b.orig_color = b.cget("text"), b.cget("text_color")
        b.configure(text=T(text), text_color=ACC)

        def back():
            try:
                b.configure(text=T(getattr(b, "_src", None) or b.orig), text_color=b.orig_color)
            except Exception:
                pass
        self.after(1400, back)

    def brand(self, win, title=""):
        """Every window of the app carries the same name, icon and dark title bar."""
        win.title(f"{APP_NAME} - {title}" if title else APP_NAME)
        if self.ico_file:
            try:
                win.iconbitmap(self.ico_file)
            except Exception:
                pass
        self.after(80, lambda: style_window(win))

    def panel_head(self, parent, title):
        """The branded header line used inside every panel."""
        h = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=0, border_width=1, border_color=LINE)
        h.pack(fill="x")
        row = ctk.CTkFrame(h, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=10)
        self.wordmark(row, 16, self.card_logo)
        Label(row, text=title, font=(FONT, 13), text_color=MUTED).pack(side="right")
        return h

    def support_line(self, parent, stack=False):
        """The small thank-you, and the way to it. Honest words: the servers run on what the
        supporters pay for, so this belongs on every page, not hidden in a corner."""
        row = ctk.CTkFrame(parent, fg_color="transparent")
        text = Label(row, text="Your support keeps our servers running - thank you.",
                     font=(FONT, 10), text_color=MUTED, justify="left")
        link = Label(row, text="reymit.ir/42level", font=(FONT, 10, "bold"),
                     text_color=ACC, cursor="hand2")
        link.bind("<Button-1>", lambda e: webbrowser.open(REYMIT_URL))
        if stack:                       # the left menu is 290 wide, so the words go under
            text.configure(wraplength=226)
            text.pack(anchor="w")
            link.pack(anchor="w", pady=(2, 0))
        else:
            text.pack(side="left")
            link.pack(side="left", padx=(7, 0))
        return row

    def page_head(self, parent, title):
        """The first line of a page. The name of the app is already in the bar above it, so
        this says only where you are - and who to thank for the machine answering. The place
        comes first, in the corner a reader starts from, and the thanks trail behind it."""
        h = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=0, border_width=1, border_color=LINE)
        h.pack(fill="x")
        row = ctk.CTkFrame(h, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=9)
        Label(row, text=title, font=(FONT, 13, "bold"), text_color=MUTED).pack(side="left")
        self.support_line(row).pack(side="right")
        return h

    # ------------------------------------------------------------ top navigation
    def wordmark(self, parent, sz=16, icon=None, padx=0, word_only=False):
        """VLAN 42. The picture already is the 42, so wherever a 42 is drawn - inside this
        line or as the big mark above it - the words say VLAN only. Never a second 42."""
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(side="left", padx=padx)
        Label(f, text="VLAN", font=(FONT, sz, "bold"), text_color=TXT).pack(side="left")
        if word_only:
            return f
        if icon:
            Label(f, image=icon, text="").pack(side="left", padx=(6, 0))
        else:
            Label(f, text="42", font=(FONT, sz, "bold"), text_color=ACC).pack(side="left", padx=(5, 0))
        return f

    def build_nav(self):
        self.nav = ctk.CTkFrame(self, fg_color=CARD, corner_radius=0, height=54)
        self.nav.pack(fill="x", side="top")
        self.nav.pack_propagate(False)
        row = ctk.CTkFrame(self.nav, fg_color="transparent")
        row.pack(fill="both", expand=True, padx=16, pady=9)
        self.wordmark(row, 16, self.nav_logo, padx=(2, 26))

        for i, (key, label) in enumerate((("start", "Rooms"), ("friends", "Friends"),
                                          ("room", "Room"), ("logs", "Logs"),
                                          ("settings", "Settings"))):
            holder = ctk.CTkFrame(row, fg_color="transparent")
            holder.pack(side="left", padx=(0, 8))
            if i:
                # the tabs are split by a green bar, never painted green themselves
                Label(holder, text="|", font=(FONT, 15, "bold"),
                             text_color=ACC).pack(side="left", padx=(0, 7))
            b = Btn(holder, text=label, width=16 + 9 * len(label), height=32, corner_radius=8,
                              font=(FONT, 13, "bold"), fg_color="transparent", hover_color=CARD2,
                              text_color=MUTED, border_width=1, border_color=CARD,
                              command=lambda k=key: self.select_tab(k))
            b.pack(side="left")
            badge = Label(holder, text="", font=(FONT, 11, "bold"), text_color="#ffffff",
                                 fg_color=RED, corner_radius=9, width=22, height=20)
            # packed only when there is a number to show, so no empty red circle by default
            self.tabs[key] = (holder, b, badge)
        self.tabs["room"][0].pack_forget()

        self.btn(row, "Logout", self.logout, CARD2, LINE, h=30, width=80).pack(side="right")
        self.lbl_nav_acct = Label(row, text="", font=(FONT, 12), text_color=MUTED)
        self.lbl_nav_acct.pack(side="right", padx=(0, 14))
        credit = Label(row, text="DEVELOPED BY : Hossein42\nUI / UX DESIGN : Erfan.Sh",
                              font=(FONT, 10), text_color=MUTED, justify="right")
        credit.pack(side="right", padx=(0, 18))

    def select_tab(self, key):
        if key == "room" and not self.node:
            key = "start"
        self.tab = key
        self.show_page(key)

    def update_tabs(self):
        for key, (holder, b, _) in self.tabs.items():
            if key == "room":
                if self.node:
                    holder.pack(side="left", padx=(0, 6), before=self.tabs["logs"][0])
                else:
                    holder.pack_forget()
            sel = self.page == key
            setw(b, fg_color=(CARD2 if sel else "transparent"),
                 border_color=CARD,
                 text_color=(TXT if sel else MUTED))
        if self.node:
            setw(self.tabs["room"][1], text=fmt("Room · {n}", n=self.room_name)[:24])

    def update_badges(self):
        """One number on the Friends tab: requests waiting plus unread chat lines - and on
        the Room tab, whoever is standing outside the door."""
        can = bool(self.node) and (self.my_role() == "owner" or self.my_perms().get("approve"))
        n = self.jreq_n if can else 0
        rb = self.tabs["room"][2]
        if n:
            setw(rb, text=str(n) if n < 100 else "99+")
            rb.pack(side="left", padx=(5, 0))
        else:
            setw(rb, text="")
            rb.pack_forget()
        n = len(self.friends.get("requests", [])) + sum(self.pm_unread.values())
        badge = self.tabs["friends"][2]
        if n:
            setw(badge, text=str(n) if n < 100 else "99+")
            badge.pack(side="left", padx=(0, 2))
        else:
            setw(badge, text="")
            badge.pack_forget()

    def blink_tick(self):
        """Pulse the signed-in name; it stops on its own once the link is gone."""
        if not (self.link and self.link.alive):
            return
        self.blink_on = not self.blink_on
        try:
            if self.lbl_acct_name.winfo_exists():
                self.lbl_acct_name.configure(
                    text_color=(NAME_RED if self.blink_on else NAME_DIM))
        except Exception:
            return
        self.after(700, self.blink_tick)

    # ------------------------------------------------------------ in-app notifications
    def build_hint(self):
        """The one line a notice lands in: above the page it belongs to, never a card
        floating over the window. The tab keeps its badge, so nothing is lost when the
        line fades away."""
        self.hint = ctk.CTkFrame(self, fg_color=CARD, corner_radius=0,
                                 border_width=1, border_color=ACC, height=40)
        self.hint.pack_propagate(False)
        self.hint_inner = ctk.CTkFrame(self.hint, fg_color="transparent")
        self.hint_inner.pack(fill="both", expand=True, padx=16, pady=5)
        self.hint.pack_forget()

    def notify(self, title, text, actions=None, keep=14, kind=None):
        """actions is a list of (label, command, color); the buttons answer from wherever
        you are and then the line steps back out of the way. kind says what the line is
        about, so the event that answers it can take the line away - a notice must not
        outlive the thing it was waiting for."""
        if not self.winfo_exists():
            return
        for c in self.hint_inner.winfo_children():
            c.destroy()
        for label, cmd, color in (actions or []):
            self.btn(self.hint_inner, label, lambda fn=cmd: self.answer_hint(fn),
                     color, CARD2, h=28, width=78).pack(side="right", padx=3)
        Label(self.hint_inner, text=title, font=(FONT, 12, "bold"),
                     text_color=ACC).pack(side="left")
        Label(self.hint_inner, text=text, font=(FONT, 12), text_color=TXT).pack(
            side="left", padx=(9, 0))
        self.hint_kind = kind
        self.hint_t = keep
        self.show_hint()
        self.beep()
        return self.hint

    def show_hint(self):
        self.hint.pack(fill="x", side="top", before=self.body)
        if not self.hint_live:
            self.hint_live = True
            self.after(1000, self.tick_hint)

    def hide_hint(self):
        self.hint_live, self.hint_t, self.hint_kind = False, 0, None
        if self.hint.winfo_manager() == "pack":
            self.hint.pack_forget()

    def clear_hint(self, *kinds):
        """Take the line away when the news it carried has just been answered."""
        if self.hint_kind in kinds:
            self.hide_hint()

    def tick_hint(self):
        if not self.hint_live:
            return
        self.hint_t -= 1
        if self.hint_t <= 0:
            return self.hide_hint()
        self.after(1000, self.tick_hint)

    def answer_hint(self, fn):
        self.hide_hint()
        fn()

    def note_friend_req(self, name):
        """A friend request is answered from the line itself - or later on the Friends page,
        where the same two buttons wait as long as you need them."""
        self.notify("Friend request", fmt("{name} wants to be your friend.", name=name), [
            ("✕", lambda: self.answer_req(name, False), CARD2),
            ("Accept", lambda: self.answer_req(name, True), ACC)])

    def answer_req(self, name, accept):
        self.friend_req(name, "friend_resp", accept=accept)

    def note_pm(self, name, text):
        if self.page == "friends":
            return
        self.notify("Message", f"{name}: {text[:70]}",
                    [("Open", lambda: self.open_pm_from_note(name), ACC)])

    def open_pm_from_note(self, name):
        self.select_tab("friends")
        self.open_pm(name)

    # ------------------------------------------------------------ the host answers the door
    def note_join_req(self, rq):
        """A guest knocked: answered from the line above the page, or from the Room tab's
        own list while the badge on it still counts."""
        self.notify("Join request", fmt("{name} wants to join the room.", name=rq["name"]), [
            ("✕", lambda: self.answer_join(rq, False), CARD2),
            ("Accept", lambda: self.answer_join(rq, True), ACC)])

    def answer_join(self, rq, accept):
        if not (self.link and self.link.alive):
            return

        def work():
            r = self.link.req("join_resp", room=rq["room"], user=rq["id"], accept=accept)
            if not r.get("ok"):
                self.q_putf("Could not answer the request: {err}", err=r.get("err"))
                return
            self.q_putf("{name} is {what}", name=rq["name"],
                        what=word("let in") if accept else word("turned away"))
            self.uq.put({"t": "jreq_upd", "room": rq["room"], "requests": r.get("requests", [])})
        threading.Thread(target=work, daemon=True).start()

    def refresh_jreq(self):
        rid = self.node.rid if self.node else None
        if rid is None or not (self.link and self.link.alive):
            return

        def work():
            r = self.link.req("join_list", room=rid)
            if r.get("ok"):
                self.uq.put({"t": "jreq_upd", "room": rid, "requests": r["requests"]})
        threading.Thread(target=work, daemon=True).start()

    def rebuild_requests(self):
        """Requests live inside the same admin window as the ranks and the ban list."""
        if not (self.awin and self.awin.winfo_exists()) or self.admin_tab != "Requests":
            return
        body = self.admin_clear(fmt("Waiting to be let in ({n})", n=len(self.jreq)))
        if not self.jreq:
            Label(body, text="Nobody is waiting.", font=(FONT, 13),
                  text_color=MUTED).pack(pady=30)
            return
        for rq in self.jreq:
            r = ctk.CTkFrame(body, fg_color=CARD, corner_radius=10, border_width=1, border_color=LINE)
            r.pack(fill="x", pady=4)
            Label(r, text=rq["name"], font=(FONT, 14), anchor="w").pack(side="left", padx=14)
            Label(r, text=time.strftime("%H:%M:%S", time.localtime(rq.get("ts", 0))),
                  font=(FONT, 11), text_color=MUTED).pack(side="left")
            self.btn(r, "✕", lambda q=rq: self.answer_join(q, False), CARD2, LINE, h=30,
                     width=46).pack(side="right", padx=(4, 12), pady=8)
            self.btn(r, "Accept", lambda q=rq: self.answer_join(q, True), ACC, ACC_H, h=30,
                     width=80).pack(side="right", padx=4, pady=8)
    def show_main(self):
        style_window(self)
        self.fade_in()
        self.after(400, lambda: style_window(self))
        self.after(2500, lambda: self.attributes("-alpha", 1.0))

    def fade_in(self, a=0.0):
        a = min(1.0, a + 0.14)
        try:
            self.attributes("-alpha", a)
        except Exception:
            return
        if a < 1.0:
            self.after(15, self.fade_in, a)

    # ------------------------------------------------------------ login page
    def build_login(self, cfg):
        self.pg_login = ctk.CTkFrame(self.body, fg_color=BG, corner_radius=0)
        wrap = ctk.CTkFrame(self.pg_login, fg_color="transparent")
        wrap.pack(fill="both", expand=True)
        wrap.grid_columnconfigure(0, weight=1)
        wrap.grid_rowconfigure(0, weight=1)
        card = ctk.CTkFrame(wrap, fg_color=CARD, corner_radius=18, border_width=1, border_color=LINE)
        card.grid(row=0, column=0)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=34, pady=26)
        if self.logo_img:
            Label(inner, image=self.logo_img, text="").pack(pady=(0, 4))
        Label(inner, text="Play together over a virtual local network.",
                     font=(FONT, 13), text_color=MUTED, justify="center").pack(pady=(6, 14))
        self.cap(inner, "Username")
        self.l_user = self.entry(inner, "Username")
        self.l_user.pack(fill="x")
        if cfg.get("user"):
            self.l_user.insert(0, cfg["user"])
        self.cap(inner, "Password")
        self.l_pwd = self.entry(inner, "Password", show="•")
        self.l_pwd.pack(fill="x")
        self.l_remember = Chk(inner, text="Remember me on this PC", font=(FONT, 13),
                              fg_color=ACC, hover_color=ACC_H, checkmark_color=BG)
        self.l_remember.pack(anchor="w", pady=(14, 0))
        if cfg.get("token"):
            self.l_remember.select()
        self.mode_btn = Seg(
            inner, values=["Login", "Register"], command=lambda v: None, height=38, font=(FONT, 13, "bold"),
            selected_color=ACC, selected_hover_color=ACC_H, unselected_color=CARD2, unselected_hover_color=LINE,
            fg_color=CARD2, text_color=TXT)
        self.mode_btn.pack(fill="x", pady=(16, 4))
        self.mode_btn.set("Login")
        self.b_auth = self.btn(inner, "Sign in", self.do_auth, h=46)
        self.b_auth.pack(fill="x", pady=(14, 0))
        self.lbl_login_err = Label(inner, text="", text_color=RED, font=(FONT, 12),
                                   wraplength=420, justify="left")
        self.lbl_login_err.pack(fill="x", pady=(10, 0))
        cr = Label(inner, text="coded by Hossein & Erfan", font=(FONT, 11), text_color=MUTED,
                   cursor="hand2")
        cr.pack(pady=(10, 0))
        cr.bind("<Button-1>", lambda e: webbrowser.open(GITHUB_URL))

    def do_auth(self):
        if self.busy:
            return
        u = self.l_user.get().strip()
        p = self.l_pwd.get()
        if not u or not p:
            setw(self.lbl_login_err, text="Enter your username and password.")
            return
        register = un(self.mode_btn.get()) == "Register"
        remember = bool(self.l_remember.get())
        self.busy = True
        setw(self.b_auth, text="Please wait...", state="disabled")

        def work():
            try:
                link = open_link(self.q_put)
                r = link.req("register" if register else "login", u=u, p=p, hw=machine_id())
                if not r.get("ok"):
                    self.uq.put({"t": "auth_fail", "err": r.get("err") or "Login failed"})
                    link.close()
                    return
                link.user = r["user"]
                link.token = r["token"]
                self.uq.put({"t": "auth_ok", "link": link, "remember": remember,
                             "staff": r.get("staff"),
                             "server": f"{link.host}:{link.port}", "user": r["user"]["name"]})
            except Exception as ex:
                self.uq.put({"t": "auth_fail", "err": mask_net(f"Cannot reach the {APP_NAME} network: {ex}")
                                 + net_hint(ex)})
        threading.Thread(target=work, daemon=True).start()

    def try_token_login(self):
        token = load_cfg().get("token") or ""
        if not token:
            return
        self.busy = True
        setw(self.b_auth, text="Signing in...", state="disabled")
        setw(self.lbl_login_err, text="Signing in with the saved session...", text_color=MUTED)

        def work():
            try:
                link = open_link(self.q_put)
                r = link.req("login_token", token=token)
                if r.get("ok"):
                    link.user = r["user"]
                    link.token = token
                    self.uq.put({"t": "auth_ok", "link": link, "remember": True,
                                 "staff": r.get("staff"),
                                 "server": f"{link.host}:{link.port}", "user": r["user"]["name"]})
                    return
                self.uq.put({"t": "auth_fail", "err": ""})   # silent: just show the login form
                link.close()
            except Exception:
                self.uq.put({"t": "auth_fail", "err": ""})
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ landing page
    def build_start(self, cfg):
        self.pg_start = ctk.CTkFrame(self.body, fg_color=BG, corner_radius=0)
        side = ctk.CTkFrame(self.pg_start, fg_color=CARD, corner_radius=0, width=290)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        if self.logo_img:
            Label(side, image=self.logo_img, text="").pack(anchor="w", padx=26, pady=(30, 0))
        title = ctk.CTkFrame(side, fg_color="transparent")
        title.pack(anchor="w", padx=30, pady=(8, 0) if self.logo_img else (44, 0))
        self.wordmark(title, 32, word_only=bool(self.logo_img))
        # 226 = the 290px menu minus its 2x30 padding; without this the Persian tagline is cut
        Label(side, text="Play together over a\nvirtual local network.", font=(FONT, 13),
                     text_color=MUTED, justify="left", wraplength=226).pack(anchor="w", padx=30, pady=(8, 22))
        # "signed in as <name>" - the name is bright red and pulses so you see it is live
        acct = ctk.CTkFrame(side, fg_color="transparent")
        acct.pack(anchor="w", padx=30, pady=(18, 0))
        Label(acct, text="signed in as", font=(FONT, 12), text_color=MUTED).pack(side="left")
        self.lbl_acct_name = Label(acct, text="", font=(FONT, 13, "bold"), text_color=NAME_RED)
        self.lbl_acct_name.pack(side="left", padx=(7, 0))
        self.lbl_acct = Label(side, text="", font=(FONT, 12), text_color=MUTED, anchor="w",
                                     justify="left", wraplength=226)
        self.lbl_acct.pack(anchor="w", padx=30, pady=(2, 0))
        self.support_line(side, stack=True).pack(anchor="w", padx=30, pady=(18, 0))
        self.blink_on = True

        # friends live on the Friends tab only - the menu stays a menu
        main = ctk.CTkFrame(self.pg_start, fg_color=BG, corner_radius=0)
        main.pack(side="left", fill="both", expand=True)
        main.grid_columnconfigure(0, weight=1, uniform="a")
        main.grid_columnconfigure(1, weight=1, uniform="a")
        main.grid_rowconfigure(2, weight=1)

        self.inv_bar = ctk.CTkFrame(main, fg_color=CARD, corner_radius=12, border_width=1, border_color=GOLD)
        self.lbl_invite = Label(self.inv_bar, text="", font=(FONT, 13), text_color=TXT, anchor="w")
        self.lbl_invite.pack(side="left", fill="x", expand=True, padx=14, pady=10)
        self.btn(self.inv_bar, "Join", lambda: self.join_by_invite(self.invite), h=32, width=70
                 ).pack(side="right", padx=(6, 10), pady=8)
        self.btn(self.inv_bar, "✕", lambda: self.set_invite(None), CARD2, LINE, h=32, width=40
                 ).pack(side="right", pady=8)

        card_c = ctk.CTkFrame(main, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        card_c.grid(row=1, column=0, sticky="nsew", padx=(16, 8), pady=(16, 8))
        ic = ctk.CTkFrame(card_c, fg_color="transparent")
        ic.pack(fill="both", expand=True, padx=20, pady=16)
        Label(ic, text="Create a room", font=(FONT, 15, "bold"), anchor="w").pack(fill="x")
        self.cap(ic, "Room name")
        self.h_room = TextLine(ic, "Room name")
        self.h_room.pack(fill="x")
        self.cap(ic, "Room password")
        pr = ctk.CTkFrame(ic, fg_color="transparent")
        pr.pack(fill="x")
        self.h_pwd = self.entry(pr, "Password")
        self.h_pwd.pack(side="left", fill="x", expand=True)
        self.btn(pr, "🎲", self.roll, CARD2, LINE, h=40, width=46).pack(side="left", padx=(8, 0))
        self.b_create = self.btn(ic, "Create room", self.create_room, h=44)
        self.b_create.pack(fill="x", pady=(16, 0))

        card_j = ctk.CTkFrame(main, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        card_j.grid(row=1, column=1, sticky="nsew", padx=(8, 16), pady=(16, 8))
        ij = ctk.CTkFrame(card_j, fg_color="transparent")
        ij.pack(fill="both", expand=True, padx=20, pady=16)
        Label(ij, text="Join a room", font=(FONT, 15, "bold"), anchor="w").pack(fill="x")
        self.cap(ij, "Invite code from your friend")
        gr = ctk.CTkFrame(ij, fg_color="transparent")
        gr.pack(fill="x")
        self.g_link = self.entry(gr, "xxxx.xxxx.xxxx...")
        self.g_link.pack(side="left", fill="x", expand=True)
        self.btn(gr, "Paste", self.paste_link, CARD2, LINE, h=40, width=70).pack(side="left", padx=(8, 0))
        self.b_join = self.btn(ij, "Join room", self.join_link, h=44)
        self.b_join.pack(fill="x", pady=(16, 0))

        card_r = ctk.CTkFrame(main, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        card_r.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=16, pady=(8, 16))
        ir = ctk.CTkFrame(card_r, fg_color="transparent")
        ir.pack(fill="both", expand=True, padx=20, pady=14)
        rh = ctk.CTkFrame(ir, fg_color="transparent")
        rh.pack(fill="x")
        Label(rh, text="My rooms", font=(FONT, 15, "bold")).pack(side="left")
        self.lbl_rooms_count = Label(rh, text="", font=(FONT, 12), text_color=MUTED)
        self.lbl_rooms_count.pack(side="right")
        self.rooms_list = ctk.CTkScrollableFrame(ir, fg_color="transparent")
        self.rooms_list.pack(fill="both", expand=True, pady=(8, 0))
        self.roll()

    # ------------------------------------------------------------ room page
    def build_room(self):
        self.pg_room = ctk.CTkFrame(self.body, fg_color=BG, corner_radius=0)
        self.room_w = 380             # the players column, until somebody drags the line
        left = self.room_left = ctk.CTkFrame(self.pg_room, fg_color="transparent", width=self.room_w)
        left.pack(side="left", fill="y", padx=(16, 0), pady=16)
        left.pack_propagate(False)

        hc = ctk.CTkFrame(left, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        hc.pack(fill="x")
        top = ctk.CTkFrame(hc, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 0))
        self.lbl_role = Label(top, text="", font=(FONT, 10, "bold"), fg_color=ACC,
                                     corner_radius=6, height=20, padx=8)
        self.lbl_role.pack(side="left")
        self.lbl_status = Label(top, text="● Connecting", font=(FONT, 12, "bold"), text_color=YELLOW)
        self.lbl_status.pack(side="right")
        self.lbl_room = Label(hc, text="", font=(FONT, 21, "bold"), anchor="w", wraplength=340)
        self.lbl_room.pack(fill="x", padx=16, pady=(8, 0))
        self.lbl_you = Label(hc, text="", font=(FONT, 12), text_color=MUTED, anchor="w", justify="left")
        self.lbl_you.pack(fill="x", padx=16, pady=(2, 0))
        self.lbl_stats = Label(hc, text="", font=("Consolas", 11), text_color=MUTED, anchor="w")
        self.lbl_stats.pack(fill="x", padx=16, pady=(0, 12))

        # the buttons are put down first, against the bottom edge: whatever height the
        # window is given, they are never the thing that gets squeezed out of sight
        act = self.room_act = ctk.CTkFrame(left, fg_color="transparent")
        act.pack(side="bottom", fill="x")
        self.row_host = ctk.CTkFrame(act, fg_color="transparent")
        self.b_inv = self.btn(self.row_host, "Copy invite code", self.copy_invite, CARD2, LINE, h=36)
        self.b_inv.pack(fill="x")
        self.row_mod = ctk.CTkFrame(act, fg_color="transparent")
        self.btn(self.row_mod, "Admin panel", self.show_admin, CARD2, LINE, h=36).pack(fill="x")
        self.row_common = ctk.CTkFrame(act, fg_color="transparent")
        self.row_common.pack(fill="x", pady=(0, 6))
        self.btn(self.row_common, "Logs", self.show_logs, CARD2, LINE, h=36).pack(
            side="left", expand=True, fill="x", padx=(0, 4))
        self.btn(act, "Leave room", self.leave, "#c0392b", "#a93226", h=40).pack(fill="x")

        pc = self.room_pc = ctk.CTkFrame(left, fg_color=CARD, corner_radius=14,
                                         border_width=1, border_color=LINE)
        pc.pack(fill="both", expand=True, pady=10)
        ph = ctk.CTkFrame(pc, fg_color="transparent")
        ph.pack(fill="x", padx=16, pady=(12, 0))
        Label(ph, text="Players", font=(FONT, 14, "bold")).pack(side="left")
        self.lbl_count = Label(ph, text="0 online", font=(FONT, 12), text_color=MUTED)
        self.lbl_count.pack(side="right")
        self.plist = ctk.CTkScrollableFrame(pc, fg_color="transparent")
        self.plist.pack(fill="both", expand=True, padx=6, pady=(6, 8))
        self.empty = Label(self.plist, text="", font=(FONT, 13), text_color=MUTED, justify="center")

        self.room_split = Splitter(self.pg_room, self.set_room_w, lo=300, hi=560)
        self.room_split.pack(side="left", fill="y", padx=(0, 8))

        right = ctk.CTkFrame(self.pg_room, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        right.pack(side="left", fill="both", expand=True, padx=(0, 16), pady=16)
        Label(right, text="Chat", font=(FONT, 14, "bold"), anchor="w").pack(fill="x", padx=18, pady=(14, 6))
        self.chatbox = ctk.CTkTextbox(right, font=(FONT, 13), wrap="word", fg_color=BG, text_color=TXT,
                                      corner_radius=10, border_width=1, border_color=LINE)
        fix_clipboard(self.chatbox)
        self.chatbox.pack(fill="both", expand=True, padx=14)
        for tag, kw in (("me", {"foreground": ACC}), ("them", {"foreground": "#5dade2"}),
                        ("sys", {"foreground": GRAY}), ("body", {"foreground": TXT}),
                        ("rtl", {"justify": "right"}), ("ltr", {"justify": "left"})):
            self.chatbox.tag_config(tag, **kw)
        self.chatbox.configure(state="disabled")
        self.lbl_typing = Label(right, text="", font=(FONT, 11, "italic"),
                                       text_color=MUTED, anchor="w")
        self.lbl_typing.pack(fill="x", padx=16, pady=(0, 2))
        crow = ctk.CTkFrame(right, fg_color="transparent")
        crow.pack(fill="x", padx=14, pady=12)
        self.chat_in = TextLine(crow, "Type a message...", on_enter=self.send_chat,
                                on_type=lambda: self.note_typing())
        self.chat_in.pack(side="left", fill="x", expand=True)
        self.btn(crow, "Send", self.send_chat, h=40, width=80).pack(side="left", padx=(8, 0))

    def set_room_w(self, w=None):
        """The width of the players column, set by the drag line beside it. The room name
        and a long player name are both read whole this way, at any window size."""
        self.room_w = int(w or self.room_w)
        self.room_left.configure(width=self.room_w)
        self.lbl_room.configure(wraplength=max(160, self.room_w - 40))

    def build_logs(self):
        self.pg_logs = ctk.CTkFrame(self.body, fg_color=BG, corner_radius=0)
        self.page_head(self.pg_logs, "Logs")
        self.logbox = ctk.CTkTextbox(self.pg_logs, font=("Consolas", 11), wrap="word",
                                     fg_color=CARD, text_color=TXT, corner_radius=12)
        # a Persian line belongs on the right, an English one on the left
        for tag, kw in (("rtl", {"justify": "right"}), ("ltr", {"justify": "left"})):
            self.logbox.tag_config(tag, **kw)
        fix_clipboard(self.logbox)
        self.logbox.pack(fill="both", expand=True, padx=16, pady=(12, 6))
        self.logbox.configure(state="disabled")
        br = ctk.CTkFrame(self.pg_logs, fg_color="transparent")
        br.pack(fill="x", padx=16, pady=(0, 14))
        for t, f in (("Copy log", self.copy_log),
                     ("Diagnostics", self.run_diag), ("Diag ZIP", self.export_zip)):
            self.btn(br, t, f, CARD2, LINE, h=32).pack(side="left", expand=True, fill="x", padx=3)

    def show_logs(self):
        self.select_tab("logs")

    # ------------------------------------------------------------ settings
    def build_settings(self):
        self.pg_settings = ctk.CTkFrame(self.body, fg_color=BG, corner_radius=0)
        self.page_head(self.pg_settings, "Settings")
        # three cards, and a window that is not always tall enough for all of them
        self.set_body = ctk.CTkScrollableFrame(self.pg_settings, fg_color=BG)
        self.set_body.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        card = ctk.CTkFrame(self.set_body, fg_color=CARD, corner_radius=14,
                            border_width=1, border_color=LINE)
        card.pack(fill="x", padx=12, pady=12)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=20, pady=18)

        self.cap(inner, "Language")
        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(fill="x")
        self.seg_lang = Seg(row, values=["English", "فارسی"], command=self.set_lang, height=38,
                            font=(FONT, 13, "bold"), fg_color=CARD2, selected_color=ACC,
                            selected_hover_color=ACC_H, unselected_color=CARD2, text_color=TXT)
        self.seg_lang.pack(side="left")
        self.seg_lang.set("فارسی" if LANG[0] == "fa" else "English")
        Label(row, text="Persian turns the whole app right-to-left.", font=(FONT, 11),
              text_color=MUTED).pack(side="left", padx=(14, 0))

        self.cap(inner, "Message sound")
        srow = ctk.CTkFrame(inner, fg_color="transparent")
        srow.pack(fill="x")
        self.seg_sound = Seg(srow, values=["On", "Off"], command=self.set_sound, height=38,
                             font=(FONT, 13, "bold"), fg_color=CARD2, selected_color=ACC,
                             selected_hover_color=ACC_H, unselected_color=CARD2, text_color=TXT)
        self.seg_sound.pack(side="left")
        self.seg_sound.set("Off" if not SOUND[0] else "On")
        self.btn(srow, "Test sound", lambda: self.beep(pm=True), CARD2, LINE,
                 h=34, width=100).pack(side="left", padx=(14, 0))

        self.pwd_card = ctk.CTkFrame(self.set_body, fg_color=CARD, corner_radius=14,
                                     border_width=1, border_color=LINE)
        pin = ctk.CTkFrame(self.pwd_card, fg_color="transparent")
        pin.pack(fill="both", expand=True, padx=20, pady=18)
        self.cap(pin, "Password")
        self.p_old = self.entry(pin, "Current password", show="*")
        self.p_old.pack(fill="x", pady=(0, 6))
        self.p_new = self.entry(pin, "New password", show="*")
        self.p_new.pack(fill="x", pady=(0, 6))
        self.p_again = self.entry(pin, "New password again", show="*")
        self.p_again.pack(fill="x")
        prow = ctk.CTkFrame(pin, fg_color="transparent")
        prow.pack(fill="x", pady=(10, 0))
        self.b_pwd = self.btn(prow, "Change password", self.change_password, h=38, width=170)
        self.b_pwd.pack(side="left")
        self.p_err = Label(prow, text="", font=(FONT, 12), text_color=MUTED, anchor="w")
        self.p_err.pack(side="left", padx=(14, 0))

        self.team_card = ctk.CTkFrame(self.set_body, fg_color=CARD, corner_radius=14,
                                      border_width=1, border_color=GOLD)
        tin = ctk.CTkFrame(self.team_card, fg_color="transparent")
        tin.pack(fill="both", expand=True, padx=20, pady=18)
        self.cap(tin, "Management")
        trow = ctk.CTkFrame(tin, fg_color="transparent")
        trow.pack(fill="x")
        self.b_console = self.btn(trow, "Open the console", self.show_console, ACC, ACC_H, h=38,
                                  width=170)
        self.b_console.pack(side="left")
        Label(trow, text="This account is one the team vouched for.", font=(FONT, 12),
              text_color=MUTED).pack(side="left", padx=(14, 0))

    def show_settings_cards(self):
        """The password card needs an account behind it and the console card needs the
        team's yes - so neither is on the page before its time."""
        for card in (self.pwd_card, self.team_card):
            card.pack_forget()
        if self.link:
            self.pwd_card.pack(fill="x", padx=12, pady=(0, 12))
        if self.staff:
            self.team_card.pack(fill="x", padx=12, pady=(0, 12))

    def set_lang(self, value):
        lang = "fa" if un(value).startswith("فارسی") else "en"
        if lang == LANG[0]:
            return
        LANG[0] = lang
        cfg = load_cfg()
        cfg["lang"] = lang
        save_cfg(cfg)
        self.relayout()
        self.q_putf("Language: {which}", which="Persian" if lang == "fa" else "English")

    def change_password(self):
        """The account's own password, changed from Settings. The current one is asked for,
        so a seat left unlocked is not a way in."""
        oldp, newp, again = self.p_old.get(), self.p_new.get(), self.p_again.get()
        if not (self.link and self.link.alive):
            setw(self.p_err, text="You are not signed in.", text_color=RED)
            return
        if not oldp or not newp:
            setw(self.p_err, text="Fill in the current and the new password.", text_color=RED)
            return
        if newp != again:
            setw(self.p_err, text="The two new passwords do not match.", text_color=RED)
            return
        self.busy = True
        setw(self.b_pwd, text="Please wait...", state="disabled")

        def work():
            r = self.link.req("change_password", old=oldp, new=newp)
            self.uq.put({"t": "pwd_ans", "r": r})
        threading.Thread(target=work, daemon=True).start()

    def password_answer(self, r):
        self.busy = False
        setw(self.b_pwd, text="Change password", state="normal")
        if not r.get("ok"):
            setw(self.p_err, text=r.get("err") or "The change failed.", text_color=RED)
            return
        cfg = load_cfg()
        if cfg.get("token") and r.get("token"):
            cfg["token"] = r["token"]          # "remember me" keeps working, with the new one
            save_cfg(cfg)
        for e in (self.p_old, self.p_new, self.p_again):
            e.delete(0, "end")
        self.q_put("Your password was changed")
        setw(self.p_err, text="Password changed OK", text_color=ACC)

    def set_sound(self, value):
        SOUND[0] = un(value) == "On"
        cfg = load_cfg()
        cfg["sound"] = SOUND[0]
        save_cfg(cfg)
        if SOUND[0]:
            self.beep(pm=True)

    # ------------------------------------------------------------ both languages
    def mirror_all(self, rtl):
        mirror_tree(self, rtl)
        for k in self.winfo_children():
            if isinstance(k, tk.Toplevel):
                mirror_tree(k, rtl)

    def apply_font(self):
        """The family the language just picked draws in: Vazir for Persian, the UI font
        for English. Widgets built later read the same FONT, so they follow automatically."""
        global FONT
        if LANG[0] == "fa":
            if self.fa_font is None:
                self.fa_font = pick_fa_font(self)
            want = self.fa_font or FONT_EN
        else:
            want = FONT_EN
        if want != FONT:
            FONT = want
            refamily(self, want)

    def _dim(self, off):
        """Fade the window - and every floating card with it - out and back. Turning the
        language over moves about every widget the app has, and a player watching that happen
        sees a stumble: hundreds of small jumps over half a second. Hidden while the tree is
        turned round, the two languages simply trade places."""
        for w in [self] + [k for k in self.winfo_children() if isinstance(k, tk.Toplevel)]:
            try:
                if w.winfo_exists():
                    w.attributes("-alpha", 0.0 if off else 1.0)
            except Exception:
                pass

    def relayout(self):
        """Answer the whole app in the language just picked: pen and words first, then every
        row that carries text is built anew, and only then does the mirror move what survives.
        Mirroring a widget that is about to be destroyed leaves customtkinter redrawing a
        canvas that is gone - a crash, and a card whose border never finished drawing."""
        rtl = LANG[0] == "fa"
        self._dim(True)
        try:
            self.apply_font()
            try:
                retext_tree(self)
            except Exception as e:
                self.q_putf("Layout: {e}", e=e)
            for fn in (self.update_tabs, self.update_badges, self.rebuild_friends,
                       self.pm_show, lambda: self.show_page(self.page),
                       lambda: self.node and self.update_room(self.node)):
                try:
                    fn()
                except Exception:
                    pass
            try:
                if self.my_rooms is not None:
                    for row in self.room_rows.values():
                        row["sig"] = None          # say every landing row again, in the new words
                    self.on_my_rooms(self.my_rooms)
            except Exception:
                pass
            try:
                if self.node:
                    self.role_key = None      # the rows carry words too, so build them anew
                    self.update_room_rows()
            except Exception:
                pass
            try:
                if self.cwin and self.cwin.winfo_exists():
                    if self.con_last:
                        self.console_ready(*self.con_last)   # the table and its note, in the new words
                    else:
                        self.console_draw()
            except Exception:
                pass
            try:
                self.redraw_log()      # the history is told again, in the words just picked
            except Exception:
                pass
            try:
                self.mirror_all(rtl)
            except Exception as e:
                self.q_putf("Layout: {e}", e=e)
        finally:
            # every move is on the books before the window is shown again, so the new language
            # arrives as one picture instead of a series of half-finished ones
            try:
                self.update_idletasks()
            except Exception:
                pass
            self._dim(False)

    # ------------------------------------------------------------ pages
    def show_page(self, name):
        for pg in self.pages.values():
            pg.pack_forget()
        if name == "login":
            self.nav.pack_forget()
        else:
            # the tabs stay the first thing under the title bar: a live notice line goes
            # between them and the page, never above the menu
            ref = self.hint if self.hint.winfo_manager() == "pack" else self.body
            self.nav.pack(fill="x", side="top", before=ref)
        self.body.pack(fill="both", expand=True)
        if name == "room":
            role = (self.node.room.get("my_role") if self.node else None) or "member"
            mgr = self.is_mgr()
            badge, color = MGR_BADGE if mgr else ROLE_BADGE.get(role, ROLE_BADGE["member"])
            setw(self.lbl_role, text=badge, fg_color=(color if mgr else
                                                      (ACC if role == "owner" else BLUE if role == "admin" else CARD2)),
                 text_color=(TXT if role == "member" else ACC_TXT if role == "owner" else "white"))
            self.lbl_room.configure(text=self.room_name)
            self.row_host.pack_forget()
            self.row_mod.pack_forget()
            self.row_host.pack(fill="x", pady=(0, 6), before=self.row_common)
            if role in ("owner", "admin"):
                self.row_mod.pack(fill="x", pady=(0, 6), before=self.row_common)
        page = self.pages.get(name, self.pages["login"])
        if name == "settings":
            self.show_settings_cards()      # the password card and the team card
        page.pack(fill="both", expand=True)
        self.page = name
        try:
            # a hidden page cannot be mirrored (pack would show it), so it is set right as it appears
            mirror_tree(page, LANG[0] == "fa")
        except Exception:
            pass
        self.update_tabs()
        if name == "friends":
            self.pm_show()
            self.rebuild_friends()

    # ------------------------------------------------------------ auth events
    def on_auth_ok(self, ev):
        self.link = ev["link"]
        self.staff = bool(ev.get("staff"))
        self.link.push_cb = lambda p: self.uq.put(p)
        self.link.down_cb = self.on_link_down
        self.my_name = ev["user"]
        cfg = load_cfg()
        cfg["user"] = ev["user"]
        cfg["token"] = ev["link"].token if ev["remember"] else ""
        save_cfg(cfg)
        self.busy = False
        setw(self.b_auth, text="Sign in", state="normal")
        setw(self.lbl_login_err, text="")
        setw(self.lbl_nav_acct, text=self.my_name)
        setw(self.lbl_acct_name, text=self.my_name)
        setf(self.lbl_acct, "{app} network online", {"app": APP_NAME})
        self.blink_on = True
        self.blink_tick()
        self.tab = "start"
        self.show_page("start")
        self.q_putf("Logged in as {name}", name=self.my_name)
        self.refresh_rooms()
        self.refresh_friends()
        if self.pending_enter:
            tok = self.pending_enter
            self.pending_enter = None
            self.join_by_invite({"from": "invite code", "room": "room", "token": tok})

    def on_auth_fail(self, ev):
        self.busy = False
        setw(self.b_auth, text="Sign in", state="normal")
        setw(self.lbl_login_err, text=ev.get("err") or "", text_color=RED if ev.get("err") else MUTED)

    def on_staff(self, ev):
        """The team just vouched for this account, or stopped vouching. The card and the
        panel follow at once - nobody has to sign out and in again to see what they were
        given."""
        self.staff = bool(ev.get("on"))
        if self.page == "settings":
            self.show_settings_cards()
        if self.cwin and self.cwin.winfo_exists():
            self.console_load()
        self.q_put(T("Management access for this account changed"))

    def on_link_down(self, why):
        self.uq.put({"t": "link_down", "why": why})

    def logout(self):
        if self.node:
            self.leave()
        if self.link:
            self.link.close()
            self.link = None
        cfg = load_cfg()
        cfg["token"] = ""
        save_cfg(cfg)
        self.rows = {}
        self.clear_rooms()
        self.tab = None
        self.pms, self.pm_unread, self.sel_friend = {}, {}, None
        self.friends = {"friends": [], "requests": []}
        self.rebuild_friends()
        self.hide_hint()
        for w in (self.awin, self.jwin, self.cwin):
            if w:
                try:
                    w.destroy()
                except Exception:
                    pass
        self.awin = self.jwin = self.cwin = None
        self.con_last = None
        self.staff = False
        self.admin_tab, self.jreq, self.jreq_n, self.await_enter = "Members", [], 0, None
        self.show_page("login")

    # ------------------------------------------------------------ rooms (landing)
    def refresh_rooms(self, force=False):
        """Inside a room the list is not polled, but entering, leaving and removing
        still say so at once - the landing page must never show a stale room."""
        if not (self.link and self.link.alive) or (self.node and not force):
            return
        self.rooms_t = time.time()

        def work():
            r = self.link.req("my_rooms")
            if r.get("ok") and self.link and self.link.alive:
                self.uq.put({"t": "my_rooms", "rooms": r["rooms"]})
        threading.Thread(target=work, daemon=True).start()

    def room_sig(self, room):
        online = sum(1 for m in room.get("members", []) if m.get("online"))
        return (room.get("name"), len(room.get("members", [])), online,
                room.get("my_role"), room.get("limit"), self.inside(room))

    def inside(self, room):
        """Is this the room the player is standing in right now?"""
        return bool(self.node and room and self.node.rid == room.get("id"))

    def find_room(self, rid):
        for room in self.my_rooms:
            if room.get("id") == rid:
                return room
        return None

    def clear_rooms(self):
        """Forget every landing row - used on logout so nothing is left untracked."""
        for row in self.room_rows.values():
            try:
                row["frame"].destroy()
            except Exception:
                pass
        self.room_rows = {}
        self.my_rooms = []
        if self.rooms_empty:
            try:
                self.rooms_empty.destroy()
            except Exception:
                pass
        self.rooms_empty = None

    def show_rooms_empty(self, show):
        """One tracked placeholder widget - it must never stack up on redraw."""
        if show and self.rooms_empty is None:
            self.rooms_empty = Label(
                self.rooms_list, text="No rooms yet - create one or join with an invite code.",
                font=(FONT, 13), text_color=MUTED)
            self.rooms_empty.pack(pady=30)
        elif not show and self.rooms_empty is not None:
            w, self.rooms_empty = self.rooms_empty, None
            try:
                w.destroy()
            except Exception:
                pass

    def add_room_row(self, room):
        r = ctk.CTkFrame(self.rooms_list, fg_color=CARD2, corner_radius=10)
        r.pack(fill="x", pady=4, padx=2)
        r.grid_columnconfigure(1, weight=1)
        row = {"frame": r, "sig": None,
               "mark": Label(r, font=(FONT, 20)),
               "name": Label(r, font=(FONT, 14, "bold"), anchor="w"),
               "info": Label(r, font=(FONT, 11), text_color=MUTED, anchor="w"),
               "host": Label(r, font=(FONT, 10), text_color=GOLD, anchor="w")}
        row["mark"].grid(row=0, column=0, rowspan=3, padx=(14, 8), pady=10)
        row["name"].grid(row=0, column=1, sticky="w", pady=(8, 0))
        row["info"].grid(row=1, column=1, sticky="w", pady=(0, 8))
        row["host"].grid(row=2, column=1, sticky="w", pady=(0, 8))
        # the buttons live as long as the room does and always read the freshest dict
        Btn(r, text="✕", width=36, height=32, font=(FONT, 13), corner_radius=8,
                      fg_color=CARD, hover_color="#3a2a2a", text_color=RED,
                      command=lambda q=room["id"]: self.remove_room(self.find_room(q))
                      ).grid(row=0, column=2, rowspan=3, padx=(6, 4))
        row["enter"] = self.btn(r, "Enter", lambda q=room["id"]: self.enter_room(self.find_room(q)),
                                h=32, width=80)
        row["enter"].grid(row=0, column=3, rowspan=3, padx=(0, 12))
        self.set_room_row(row, room)
        return row

    def set_room_row(self, row, room):
        role = room.get("my_role") or "member"
        online = sum(1 for m in room.get("members", []) if m.get("online"))
        mark, color = (("👑", GOLD) if role == "owner" else
                       ("🛡", BLUE) if role == "admin" else ("●", MUTED))
        setw(row["mark"], text=mark, text_color=color)
        inhere = self.inside(room)
        setw(row["name"], text=room["name"] + (f"   ·   {T('inside this room')}" if inhere else ""),
             text_color=(ACC if inhere else TXT))
        setw(row["info"], text=fmt("{m} members · {o} online · you are {role} · limit {limit}",
                                   m=len(room.get("members", [])), o=online, role=T(role),
                                   limit=room.get("limit")))
        host = "you host this room" if role == "owner" else ""
        setw(row["host"], text=host)
        if host:
            row["host"].grid()
        else:
            row["host"].grid_remove()     # no empty gap in rooms someone else hosts
        row["sig"] = self.room_sig(room)

    def on_my_rooms(self, rooms):
        """Landing list: rebuild only what actually changed - never churn the rows."""
        self.my_rooms = rooms or []
        if self.await_enter is not None and not self.node:
            r = self.find_room(self.await_enter)
            if r:
                self.await_enter = None
                self.tab = "room"
                self.after(60, lambda: self.enter_room(r))
        setf(self.lbl_rooms_count, "{n} / {m} rooms",
             {"n": len(self.my_rooms), "m": MAX_ROOMS})
        alive = set()
        for room in self.my_rooms:
            rid = room.get("id")
            alive.add(rid)
            row = self.room_rows.get(rid)
            if row is None:
                self.room_rows[rid] = self.add_room_row(room)
            elif row["sig"] != self.room_sig(room):
                self.set_room_row(row, room)
        for rid in [k for k in self.room_rows if k not in alive]:
            try:
                self.room_rows.pop(rid)["frame"].destroy()
            except Exception:
                pass
        self.show_rooms_empty(not self.my_rooms)

    def roll(self):
        """The host names the room; only the password is thrown by the dice.
        It comes from the OS entropy pool (secrets), never from random()."""
        self.h_pwd.delete(0, "end")
        self.h_pwd.insert(0, roll_password())

    def paste_link(self):
        try:
            txt = self.clipboard_get().strip()
        except Exception:
            txt = ""
        self.g_link.delete(0, "end")
        self.g_link.insert(0, txt)

    def create_room(self):
        if not self.link or self.busy:
            return
        room, pwd = self.h_room.value(), self.h_pwd.get().strip()
        if not (room and pwd):
            self.q_put("Room name and password are required."); self.show_logs(); return
        self.busy = True

        def work():
            r = self.link.req("create_room", name=room, pwd=pwd)
            self.busy = False
            if r.get("ok"):
                self.invite_text = r["invite"]
                self.uq.put({"t": "enter_room", "room": r["room"]})
            else:
                self.q_putf("Create room failed: {err}", err=r.get("err"))
        threading.Thread(target=work, daemon=True).start()

    def join_link(self):
        if not self.g_link.get().strip():
            self.paste_link()
        tok = parse_invite(self.g_link.get())
        if not tok:
            self.q_put("This is not a valid invite code. Ask your friend to send it again.")
            self.show_logs()
            return
        self.join_by_invite({"from": "invite code", "room": "room", "token": tok})

    def join_by_invite(self, inv):
        if not inv or self.busy or not self.link:
            return
        self.busy = True

        def work():
            r = self.link.req("join_room", inv=inv.get("token") or "")
            self.busy = False
            if r.get("ok"):
                if r.get("pending"):
                    self.uq.put({"t": "join_pending", "name": r.get("room_name"),
                                 "msg": r.get("msg")})
                else:
                    self.uq.put({"t": "enter_room", "room": r["room"]})
            else:
                self.q_putf("Join failed: {err}", err=r.get("err"))
        threading.Thread(target=work, daemon=True).start()

    def set_invite(self, inv):
        self.invite = inv
        if inv:
            setf(self.lbl_invite, "{who} invited you to the room '{room}'",
                 {"who": inv["from"], "room": inv["room"]})
            self.inv_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=16, pady=(16, 0))
        else:
            self.inv_bar.grid_forget()

    def remove_room(self, room):
        if not room or not self.link:
            return

        def work():
            r = self.link.req("remove_room", room=room["id"])
            if r.get("ok"):
                self.q_putf("Removed '{room}' from your rooms", room=room["name"])
            else:
                self.q_putf("Remove failed: {err}", err=r.get("err"))
            self.refresh_rooms()
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ room session
    def enter_room(self, room):
        if not room or not self.link:
            return
        if self.inside(room):
            self.select_tab("room")
            return
        if self.node:
            old = self.node
            self.node, self.busy, self.room_name = None, True, room["name"]
            self.q_putf("Leaving {old} for {new}", old=old.room.get("name", "?"),
                           new=room["name"])
            self.clear_hint("join")

            def switch():
                try:
                    old.stop()          # the old room's cable is unplugged first...
                except Exception:
                    pass
                self.busy = False
                self.uq.put({"t": "enter_room", "room": room})   # ...then the new one is taken
            threading.Thread(target=switch, daemon=True).start()
            return
        if self.busy:
            self.q_put("Still finishing the previous room - one moment.")
            return
        self.err = ""
        self.clear_hint("join")         # entering any room ends the waiting for this one
        node = VpsNode(self.link, room, self.q_put, self.uq.put)
        node.chat_cb = lambda nm, tx, ts: self.cq.put((nm, tx, ts))
        self.room_name, self.role_key = room["name"], None
        self.invite_text = room.get("invite", "")   # sealed by the server, never built here
        node.update_state(room)
        self.chat_clear()
        self.node, self.busy, self.entering_rid = node, True, room.get("id")
        self.tab = "room"
        self.refresh_rooms(True)

        def go():
            try:
                node.start()
            except WintunMissing as ex:
                self.q_put(f"ERROR: {ex}")
                self.need_wintun = True
                self.node = None
                self.tab = "start"
                self.cleanup(node)
            except Exception as ex:
                self.q_put(f"ERROR: {ex}\n{traceback.format_exc()}")
                self.err = mask_net(f"Could not start: {str(ex)[:160]}")
                self.node = None
                self.tab = "start"
                self.cleanup(node)
            self.busy = False
            self.entering_rid = None
        threading.Thread(target=go, daemon=True).start()

    def leave(self):
        if self.busy or not self.node:
            return
        self.clear_hint("join")
        node, self.node, self.busy = self.node, None, True
        self.role_key = None
        if self.tab in (None, "room"):     # whoever left from Friends or Logs stays there
            self.tab = "start"

        def stop():
            node.stop()
            self.busy = False
            self.q_put("Left the room")
            self.refresh_rooms()
        threading.Thread(target=stop, daemon=True).start()

    def cleanup(self, node):
        try:
            node.stop()
        except Exception:
            pass

    def ask_wintun(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            title="Select wintun.dll or the wintun zip (wintun-0.14.1.zip)",
            filetypes=[("Wintun", "wintun.dll *.zip"), ("All files", "*.*")])
        if not path:
            self.err = "wintun.dll is required. Press the button again after you have it."
            return

        def work():
            try:
                install_wintun_from(path, self.q.put)
                self.auto_connect = True
            except Exception as ex:
                self.q_put(f"ERROR: {ex}")
        threading.Thread(target=work, daemon=True).start()

    def copy_text(self, txt):
        self.clipboard_clear()
        self.clipboard_append(txt)

    def invite_code(self):
        """The sealed code for the room we stand in. The server makes it and the client only
        ever carries it - and if a room list forgot to bring it along, the live room state
        still holds it, so the button is never a dead one inside a room."""
        if not self.invite_text and self.node:
            self.invite_text = ((self.node.room or {}).get("invite")) or ""
        return self.invite_text

    def copy_invite(self):
        """The room's sealed code goes to the clipboard and the button answers with a green
        tick, exactly like a player line does when it hands over an IP. No window to chase."""
        code = self.invite_code()
        if not code:
            self.notify("Invite code", "The room has no invite code yet - the server may "
                                       "need updating. Ask the team to run their start_server.bat again.")
            return
        self.copy_text(code)
        self.flash(self.b_inv, "Copied ✓")
        self.q_putf("Invite code copied - send it to a friend")

    # ------------------------------------------------------------ management console
    CON_VIEWS = ("Users", "Rooms", "Traffic")
    # key, header, width in pixels. One column - the one called "name" - is allowed to
    # stretch; every other column is the same width in the header and in every row, so the
    # words above line up with the values below however long they are.
    CON_COLS = {
        "Users": (("name", "Name", 0), ("id", "ID", 46), ("last", "Last seen", 140),
                  ("created", "Made", 140), ("machine", "PC", 120), ("rooms", "Rooms", 92),
                  ("online", "Online", 46), ("bytes", "Data", 80), ("staff", "Team", 40)),
        "Rooms": (("id", "ID", 46), ("name", "Room", 0), ("owner", "Owner", 150),
                  ("members", "Members", 70), ("online", "Online", 60), ("limit", "Limit", 74),
                  ("created", "Made", 140)),
        "Traffic": (("name", "Name", 0), ("day", "Day", 140), ("bytes", "Data", 80)),
    }
    CON_ACT = {"Users": (142,), "Rooms": (96, 92, 116), "Traffic": ()}

    def admin(self, cmd):
        """One line to the server's management commands, over the same encrypted channel.
        The stamp is what says who: without the key file on this PC it is empty, and the
        server answers 'not the management console'."""
        if not (self.link and self.link.alive):
            return {"t": "admin", "ok": False, "err": "Not connected"}
        return self.link.req("admin", stamp=staff_stamp(), cmd=cmd)

    def show_console(self):
        if self.cwin and self.cwin.winfo_exists():
            self.cwin.deiconify()
            self.cwin.lift()
            return
        w = self.cwin = ctk.CTkToplevel(self)
        w.geometry("1040x660")
        w.configure(fg_color=BG)
        self.brand(w, "Management")
        self.panel_head(w, "The network, for the team")
        bar = ctk.CTkFrame(w, fg_color="transparent")
        bar.pack(fill="x", padx=14, pady=(10, 2))
        self.con_seg = Seg(bar, values=list(self.CON_VIEWS), command=self.console_view,
                           height=34, font=(FONT, 12, "bold"), fg_color=CARD2,
                           selected_color=ACC, selected_hover_color=ACC_H,
                           unselected_color=CARD2, text_color=TXT)
        self.con_seg.pack(side="left")
        self.con_find = self.entry(bar, "Search...")
        self.con_find.pack(side="left", fill="x", expand=True, padx=12)
        self.con_find.bind("<KeyRelease>", lambda e: self.console_draw())
        self.btn(bar, "Refresh", self.console_load, CARD2, LINE, h=34, width=100).pack(side="right")
        self.con_head = ctk.CTkFrame(w, fg_color="transparent")
        self.con_head.pack(fill="x", padx=12, pady=(6, 0))
        self.con_body = ctk.CTkScrollableFrame(w, fg_color="transparent")
        self.con_body.pack(fill="both", expand=True, padx=12, pady=(2, 6))
        self.con_note = Label(w, text="", font=(FONT, 11), text_color=MUTED, anchor="w")
        self.con_note.pack(fill="x", padx=16, pady=(0, 10))
        try:
            self.con_gap = int(self.con_body._scrollbar.winfo_reqwidth()) + 4
        except Exception:
            self.con_gap = 20
        self.con_view, self.con_rows, self.con_sort, self.con_desc = "Users", [], "name", False
        self.console_load()

    def console_view(self, value):
        self.con_sort = "name"
        self.set_admin_view(un(value))

    def set_admin_view(self, view):
        self.con_view = view
        if self.cwin and self.cwin.winfo_exists():
            try:
                self.con_seg.set(T(view))
            except Exception:
                pass
            self.console_load()

    def console_load(self):
        """Ask the server for the whole view in a thread, so the window stays responsive."""
        if not (self.cwin and self.cwin.winfo_exists()):
            return
        view = self.con_view
        setw(self.con_note, text=fmt("Loading {what}...", what=T(view)))
        for c in self.con_body.winfo_children():
            c.destroy()

        def work():
            r = self.admin(view.lower())
            self.uq.put({"t": "con_rows", "view": view, "r": r})
        threading.Thread(target=work, daemon=True).start()

    def console_ready(self, view, r):
        if not (self.cwin and self.cwin.winfo_exists()) or view != self.con_view:
            return
        self.con_last = (view, r)          # the language switch says the note over again
        if not r.get("ok"):
            self.con_rows = []
            setw(self.con_note, text=T(r.get("err") or "The server refused that."), text_color=RED)
            self.console_draw()
            return
        self.con_rows = r.get("rows") or []
        setw(self.con_note, text=fmt("{what}   ·   {n} rows", n=len(self.con_rows),
                                     what=fmt("signed in as") + " " + str(self.my_name)),
             text_color=MUTED)
        self.console_draw()

    def con_cell(self, parent, text, col, anchor="w"):
        """One table cell: the same column position in the header and in every row."""
        cell = Label(parent, text=text, font=(FONT, 12), anchor=anchor,
                           text_color=MUTED if anchor == "e" else TXT)
        cell.grid(row=0, column=col, sticky="nsew", padx=6, pady=5)
        return cell

    def console_shape(self, w):
        """The widths this view measured, written into one frame. The header and every row get
        the same numbers, so a word sits over the value it names and only the name column
        stretches - in the header and in every row at the same place."""
        lead = self.con_lead
        for i, px in enumerate(self.con_cols):
            w.grid_columnconfigure(i, minsize=px, weight=1 if i == lead else 0)

    def console_draw(self):
        if not (self.cwin and self.cwin.winfo_exists()):
            return
        cols = self.CON_COLS[self.con_view]
        keys = [c[0] for c in cols]
        for c in self.con_head.winfo_children() + self.con_body.winfo_children():
            c.destroy()
        heads = []
        for n_, (key, label, px) in enumerate(cols):
            # width 0: the column decides how wide a header is. Nine buttons of customtkinter's
            # default 140 pixels would leave the stretching columns nothing to stand on.
            btn = self.btn(self.con_head, label, lambda k=key: self.console_sort(k),
                           CARD2, LINE, h=30, corner_radius=8, width=0)
            if self.con_sort == key:
                # the arrow says which way the table is ordered, so it needs no words
                btn.configure(text=T(label) + (" ▲" if not self.con_desc else " ▼"))
            btn.grid(row=0, column=n_, sticky="nsew", padx=6, pady=2)
            btn.update_idletasks()        # a fresh customtkinter button only knows its own
            heads.append(btn)             # width after an idle pass, and the columns need it
        # what the header words really need, in this language and this pen, plus what the
        # code asked for - and the same numbers go into every row below
        self.con_lead = next(i for i, c in enumerate(cols) if c[0] == "name")
        self.con_cols = [max(px, b.winfo_reqwidth() + 12)
                         for (_, _, px), b in zip(cols, heads)]
        self.con_cols += list(self.CON_ACT[self.con_view])
        self.console_shape(self.con_head)
        # the list keeps room at its edge for its own scrollbar; the header keeps the same
        # room in a column of its own, or its words stop short of the values they name
        self.con_head.grid_columnconfigure(len(self.con_cols), minsize=self.con_gap, weight=0)

        needle = (self.con_find.get() or "").strip().lower()
        rows = [r for r in self.con_rows
                if not needle or any(needle in str(r.get(k, "")).lower() for k in keys)]
        good = [r for r in rows if isinstance(r.get(self.con_sort), (int, float, str))]
        try:
            good.sort(key=lambda r: (str(r.get(self.con_sort)).lower()
                                     if isinstance(r.get(self.con_sort), str) else r.get(self.con_sort)),
                      reverse=self.con_desc)
        except TypeError:
            pass
        for r in rows:
            if r not in good:
                good.append(r)

        body = self.con_body
        edit = self.staff and self.con_view in ("Users", "Rooms")
        for i, r in enumerate(good):
            row = ctk.CTkFrame(body, fg_color=CARD if i % 2 == 0 else CARD2,
                               corner_radius=10, border_width=1, border_color=LINE)
            row.pack(fill="x", pady=2)
            self.console_shape(row)
            lim = nm = None
            for n_, (key, label, px) in enumerate(cols):
                v = r.get(key)
                if key == "name" and self.con_view == "Rooms" and edit:
                    # the team may also give a room another name, in the row it sits in
                    nm = ctk.CTkEntry(row, height=26, font=(FONT, 12), fg_color=BG,
                                      border_color=LINE, text_color=TXT)
                    nm.grid(row=0, column=n_, sticky="nsew", padx=6, pady=4)
                    fix_clipboard(nm)
                    nm.insert(0, str(v))
                    continue
                if key == "limit" and edit:
                    # the team can retune how many players a room holds, right in the row
                    lim = ctk.CTkEntry(row, height=26, width=56, font=(FONT, 12),
                                       justify="center", fg_color=BG, border_color=LINE,
                                       text_color=TXT)
                    lim.grid(row=0, column=n_, sticky="ns", padx=6, pady=4)
                    fix_clipboard(lim)
                    lim.insert(0, str(v))
                    continue
                if key in ("created", "last"):
                    v = when(v)
                elif key == "bytes":
                    v = human_size(v)
                elif key == "online":
                    v = "●" if v else "○"
                elif key == "staff":
                    v = "★" if v else "-"
                elif key == "rooms":
                    # the count sorts, the ids are what the team actually wants to see
                    ids = r.get("room_ids") or []
                    v = ", ".join(str(x) for x in ids) if ids else "-"
                self.con_cell(row, str(v) if n_ == self.con_lead else
                              con_clip(str(v), self.con_cols[n_] - 12), n_)
            if edit:
                if self.con_view == "Users":
                    act = "Remove from team" if r.get("staff") else "Make team"
                    self.btn(row, act, lambda who=str(r.get("name")), on=not r.get("staff"):
                             self.set_team(who, on), CARD2, LINE, h=26, width=130
                             ).grid(row=0, column=len(cols), padx=6, pady=4)
                else:
                    save = self.btn(row, "Save", None, ACC, ACC_H, h=26, width=84)
                    save.configure(command=lambda rid=r.get("id"), n=nm, e=lim:
                                    self.save_room(rid, n.get() if n else "",
                                                   e.get() if e else ""))
                    save.grid(row=0, column=len(cols), padx=(0, 6), pady=4)
                    dele = self.btn(row, "Delete", None, "#c0392b", "#a93226", h=26, width=84)
                    dele.configure(command=lambda rid=r.get("id"), b=dele: self.drop_room(rid, b))
                    dele.grid(row=0, column=len(cols) + 1, padx=(0, 6), pady=4)
                    self.btn(row, "Enter room", lambda rid=r.get("id"): self.enter_room_admin(rid),
                             CARD2, LINE, h=26, width=110).grid(row=0, column=len(cols) + 2,
                                                                padx=(0, 6), pady=4)

    def set_team(self, who, on):
        """Move one account in or out of the team. The server only ever listens when the
        stamp came from the key file, so this is a door only the team's own PC can open."""
        self.send_admin(("set admin " if on else "remove admin ") + who)

    def save_room(self, rid, name, limit):
        """A room's name and its ceiling, typed in the row and checked here and again there."""
        name = (name or "").strip()
        if not (1 <= len(name) <= 32):
            return self.notify("Management", T("A room name is 1-32 characters"))
        if not str(limit).isdigit() or not (2 <= int(limit) <= 64):
            return self.notify("Management", T("Use a whole number from 2 to 64"))
        self.send_admins([f"set room {rid} {name}", f"set limit {rid} {limit}"])

    def enter_room_admin(self, rid):
        """Step into a room the team does not own - from the panel, without a password and
        without asking the host. Inside, every permission of that room is theirs."""
        def work():
            r = self.admin(f"enter room {rid}")
            self.uq.put({"t": "con_enter", "r": r})
        threading.Thread(target=work, daemon=True).start()

    def drop_room(self, rid, b):
        """Deleting a room is not one click: the button asks first, and forgets the question
        after a few seconds so an old click cannot delete anything by accident."""
        if b.__dict__.get("armed", 0) > time.time():
            b.__dict__["armed"] = 0
            return self.send_admin(f"remove room {rid}")
        b.__dict__["armed"] = time.time() + 5
        setw(b, text="Sure?")
        self.after(5200, lambda w=b: self.disarm(w))

    def disarm(self, b):
        if b.winfo_exists() and b.__dict__.get("armed", 0) <= time.time():
            setw(b, text="Delete")

    def send_admin(self, cmd):
        def work():
            r = self.admin(cmd)
            self.uq.put({"t": "con_done", "r": r})
        threading.Thread(target=work, daemon=True).start()

    def send_admins(self, cmds):
        """A few commands in one go, and the table reloads once - a row that saves a name
        and a ceiling must not flicker twice."""
        def work():
            out = [self.admin(c) for c in cmds]
            self.uq.put({"t": "con_done", "r": next((r for r in out if not r.get("ok")),
                                                    {"t": "admin", "ok": True})})
        threading.Thread(target=work, daemon=True).start()

    def console_answer(self, r):
        if not r.get("ok"):
            self.notify("Management", T(r.get("err") or "The server refused that."))

    def console_sort(self, key):
        if self.con_sort == key:
            self.con_desc = not self.con_desc
        else:
            self.con_sort, self.con_desc = key, False
        self.console_draw()

    # ------------------------------------------------------------ moderation
    def my_role(self):
        return (self.node.room.get("my_role") if self.node else None) or "member"

    def is_mgr(self):
        """The team, standing in a room they do not own: every permission is theirs, and
        the room says so in red beside their name."""
        return bool(((self.node.room if self.node else {}).get("my_perms") or {}).get("manage"))

    def my_perms(self):
        room = self.node.room if self.node else {}
        if self.my_role() == "owner" or self.is_mgr():
            return dict({k: True for k in PERM_LABELS}, manage=True)
        got = room.get("my_perms") or {}
        # a server that has never heard of inviting still answers the old five ticks, and
        # an admin of such a room may moderate exactly as it always could - but not invite
        return dict(got, invite=bool(got.get("invite"))) if "invite" not in got else got

    def refresh_room_state(self):
        """Ask for the room as it stands now, so a rule the owner just changed shows up on
        everybody's screen in the same second."""
        if not self.link or not self.link.alive:
            return
        rid = self.node.rid if self.node else None
        if rid is None:
            return

        def work():
            r = self.link.req("room_state", room=rid)
            if r.get("ok"):
                self.uq.put({"t": "room_state", "room": r["room"]})
        threading.Thread(target=work, daemon=True).start()

    def kick_user(self, uid):
        if not self.node:
            return
        rid = self.node.rid

        def work():
            r = self.link.req("kick", room=rid, user=uid)
            if not r.get("ok"):
                self.q_putf("Kick failed: {err}", err=r.get("err"))
        threading.Thread(target=work, daemon=True).start()

    def ban_user(self, uid):
        if not self.node:
            return
        rid = self.node.rid
        from tkinter import simpledialog
        reason = simpledialog.askstring(f"{APP_NAME} - Ban", "Reason for the ban (optional):", parent=self) or ""
        if reason is None:
            return

        def work():
            r = self.link.req("ban", room=rid, user=uid, reason=reason)
            if not r.get("ok"):
                self.q_putf("Ban failed: {err}", err=r.get("err"))
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ admin panel
    def show_admin(self, tab=None):
        """One window for the whole room control: ranks, permissions, kick, ban, ban list."""
        if self.awin and self.awin.winfo_exists():
            self.awin.deiconify()
            if tab:
                self.set_admin_tab(tab)
            return
        w = self.awin = ctk.CTkToplevel(self)
        w.geometry("600x620")
        w.configure(fg_color=BG)
        self.brand(w, "Admin panel")
        self.panel_head(w, "Room control")
        self.admin_seg = Seg(
            w, values=["Members", "Requests", "Ban list", "Role defaults"],
            command=self.set_admin_tab, height=36,
            font=(FONT, 13, "bold"), selected_color=ACC, selected_hover_color=ACC_H,
            unselected_color=CARD2, unselected_hover_color=LINE, fg_color=CARD2, text_color=TXT)
        self.admin_seg.pack(fill="x", padx=12, pady=(12, 0))
        self.admin_seg.set(T(self.admin_tab))
        self.admin_body = ctk.CTkScrollableFrame(w, fg_color="transparent")
        self.admin_body.pack(fill="both", expand=True, padx=12, pady=12)
        self.open_admin_tab(self.admin_tab)

    def set_admin_tab(self, tab):
        tab = un(tab)
        self.admin_tab = tab
        if self.awin and self.awin.winfo_exists():
            try:
                self.admin_seg.set(T(tab))
            except Exception:
                pass
        self.open_admin_tab(tab)

    def open_admin_tab(self, tab):
        """What each part of the admin window shows when it is picked."""
        if tab == "Ban list":
            self.refresh_bans()
        elif tab == "Requests":
            self.refresh_jreq()
            self.rebuild_requests()
        elif tab == "Role defaults":
            self.get_roles()
        else:
            self.rebuild_admin()

    def refresh_bans(self):
        rid = self.node.rid if self.node else None
        if rid is None:
            return

        def work():
            r = self.link.req("ban_list", room=rid)
            if r.get("ok"):
                self.uq.put({"t": "ban_list", "bans": r["bans"]})
            else:
                self.q_putf("Ban list failed: {err}", err=r.get("err"))
        threading.Thread(target=work, daemon=True).start()

    def admin_clear(self, heading=""):
        """Empty the one body frame of the admin window; a heading is said in the room's
        own words, so a caller may pass one already built from a sentence."""
        body = self.admin_body
        for c in body.winfo_children():
            c.destroy()
        if heading:
            self.cap(body, heading)
        return body

    def rebuild_admin(self):
        if not (self.awin and self.awin.winfo_exists()) or not self.node or self.admin_tab != "Members":
            return
        room = self.node.room
        owner = self.my_role() == "owner"
        perms = self.my_perms()
        if owner:
            body = self.admin_clear("Rank, permissions and the member limit")
            card = ctk.CTkFrame(body, fg_color=CARD, corner_radius=12, border_width=1, border_color=LINE)
            card.pack(fill="x")
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=12)
            Label(row, text="Member limit:", font=(FONT, 13)).pack(side="left")
            lim = ctk.CTkEntry(row, width=70, height=32, fg_color=CARD2, border_color=LINE)
            fix_clipboard(lim)
            lim.insert(0, str(room.get("limit") or 16))
            lim.pack(side="left", padx=8)

            def set_limit():
                try:
                    v = int(lim.get())
                except ValueError:
                    return

                def work():
                    r = self.link.req("set_limit", room=self.node.rid, limit=v)
                    if not r.get("ok"):
                        self.q_putf("Limit failed: {err}", err=r.get("err"))
                threading.Thread(target=work, daemon=True).start()
            self.btn(row, "Set", set_limit, CARD2, LINE, h=32, width=60).pack(side="left")
            self.cap(body, "Members - tap a rank or a permission to change it")
        else:
            have = ", ".join(PERM_LABELS[k] for k, on in perms.items() if on) or "none"
            body = self.admin_clear(f"Admin permissions you were given: {have}")
        for m in sorted(room.get("members", []), key=by_name):
            if m["id"] == self.link.user["id"]:
                continue
            role = m.get("role", "member")
            card = ctk.CTkFrame(body, fg_color=CARD, corner_radius=12, border_width=1, border_color=LINE)
            card.pack(fill="x", pady=4)
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=14, pady=(10, 0))
            badge, color = ROLE_BADGE.get(role, ROLE_BADGE["member"])
            Label(top, text=m["name"], font=(FONT, 14, "bold"), anchor="w").pack(side="left")
            Label(top, text=badge, font=(FONT, 11, "bold"), text_color=color).pack(side="left", padx=8)
            if owner:
                def toggle(q=m):
                    if q["role"] == "admin":
                        self.req_admin(q["id"], False, {})
                    else:
                        self.req_admin(q["id"], True, {k: q.get("perms", {}).get(k, False) for k in PERM_LABELS})
                self.btn(top, "Remove admin" if role == "admin" else "Make admin", toggle,
                         CARD2, LINE, h=30, width=110).pack(side="right")
            if role == "member":
                if owner or perms.get("kick"):
                    self.btn(top, "Kick", lambda q=m["id"]: self.kick_user(q), CARD2, LINE, h=30,
                             width=64).pack(side="right", padx=(0, 4))
                if owner or perms.get("ban"):
                    self.btn(top, "Ban", lambda q=m["id"]: self.ban_user(q), "#5c2a2a", "#7a3838",
                             h=30, width=60).pack(side="right", padx=(0, 4))
            if owner:
                # ticks per person, member or admin: what *this* one may do in *this*
                # room. Three to a line, because six of them do not fit on one - and an
                # untouched tick keeps following the room's own default for that role.
                prow = ctk.CTkFrame(card, fg_color="transparent")
                prow.pack(fill="x", padx=14, pady=(4, 10))
                boxes, lrow = {}, None
                for n_, k in enumerate(PERM_LABELS):
                    if n_ % 3 == 0:
                        lrow = ctk.CTkFrame(prow, fg_color="transparent")
                        lrow.pack(anchor="w", pady=1)
                    cb = Chk(lrow, text=PERM_LABELS[k], font=(FONT, 12), fg_color=ACC,
                             hover_color=ACC_H, checkmark_color=ACC_TXT)
                    if m.get("perms", {}).get(k):
                        cb.select()
                    cb.pack(side="left", padx=(0, 14))
                    boxes[k] = cb

                def apply_perms(q=m, bx=boxes):
                    self.req_perms(q["id"], {k: bool(cb.get()) for k, cb in bx.items()})
                self.btn(prow, "Apply", apply_perms, CARD2, LINE, h=28, width=70).pack(side="right")

    def get_roles(self):
        """Ask this room what a member and an admin may do by default."""
        rid = self.node.rid if self.node else None
        if rid is None:
            return

        def work():
            r = self.link.req("get_roles", room=rid)
            if r.get("ok"):
                self.uq.put({"t": "get_roles", "ok": True, "defaults": r.get("defaults") or {}})
        threading.Thread(target=work, daemon=True).start()

    def rebuild_roles(self):
        """The room's own defaults: what a tick means for everyone in this room who has no
        tick of their own. Nothing here reaches another room, and nothing here is global."""
        if not (self.awin and self.awin.winfo_exists()) or self.admin_tab != "Role defaults":
            return
        d = self.role_defaults or {}
        owner = self.my_role() == "owner"
        body = self.admin_clear("What a member and an admin may do in this room by default")
        self.role_boxes = {}
        for role in ("member", "admin"):
            card = ctk.CTkFrame(body, fg_color=CARD, corner_radius=12, border_width=1, border_color=LINE)
            card.pack(fill="x", pady=4)
            prow = ctk.CTkFrame(card, fg_color="transparent")
            prow.pack(fill="x", padx=14, pady=(4, 10))
            Label(prow, text=fmt("{role} - by default", role=T(ROLE_BADGE[role][0])),
                        font=(FONT, 13, "bold"), text_color=ROLE_BADGE[role][1]).pack(side="left",
                                                                                        padx=(0, 12))
            # two lines of ticks: a role's name is longer than any single permission
            boxes = {}
            for n, k in enumerate(PERM_LABELS):
                lrow = ctk.CTkFrame(prow, fg_color="transparent")
                lrow.pack(anchor="w", pady=1)
                cb = Chk(lrow, text=PERM_LABELS[k], font=(FONT, 12), fg_color=ACC,
                         hover_color=ACC_H, checkmark_color=ACC_TXT,
                         state=("normal" if owner else "disabled"))
                if (d.get(role) or {}).get(k):
                    cb.select()
                cb.pack(side="left")
                boxes[k] = cb
            self.role_boxes[role] = boxes
        def save():
            got = {r: {k: bool(cb.get()) for k, cb in boxes.items()}
                   for r, boxes in self.role_boxes.items()}
            rid = self.node.rid if self.node else None
            if rid is None:
                return

            def work():
                r = self.link.req("set_roles", room=rid, defaults=got)
                self.uq.put({"t": "set_roles", "ok": r.get("ok"),
                             "defaults": r.get("defaults"), "err": r.get("err")})
            threading.Thread(target=work, daemon=True).start()
        self.btn(body, "Save", save, ACC, ACC_H, h=34).pack(fill="x", pady=(10, 4))

    def req_perms(self, uid, perms):
        """Tick what one person may do in this room, whatever role they hold."""
        rid = self.node.rid if self.node else None
        if rid is None:
            return

        def work():
            r = self.link.req("set_perms", room=rid, user=uid, perms=perms)
            if not r.get("ok"):
                self.q_putf("Permission failed: {err}", err=r.get("err"))
        threading.Thread(target=work, daemon=True).start()

    def req_admin(self, uid, admin, perms):
        rid = self.node.rid if self.node else None
        if rid is None:
            return

        def work():
            r = self.link.req("set_admin", room=rid, user=uid, admin=admin, perms=perms)
            if not r.get("ok"):
                self.q_putf("Admin update failed: {err}", err=r.get("err"))
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ ban panel
    def rebuild_bans(self, bans):
        """The ban list is a section of the admin window, not a window of its own."""
        if not (self.awin and self.awin.winfo_exists()) or self.admin_tab != "Ban list":
            return
        can = self.my_role() == "owner" or self.my_perms().get("unban")
        body = self.admin_clear(f"Banned from this room ({len(bans)})")
        if not bans:
            Label(body, text="No banned users in this room.", font=(FONT, 13),
                         text_color=MUTED).pack(pady=30)
            return
        for b in bans:
            r = ctk.CTkFrame(body, fg_color=CARD, corner_radius=10, border_width=1, border_color=LINE)
            r.pack(fill="x", pady=4)
            Label(r, text=b["name"], font=(FONT, 14, "bold"), anchor="w").pack(side="left", padx=14)
            Label(r, text=fmt("by {who}  ·  {why}", who=b["by"],
                            why=T(b["reason"] or "no reason")),
                         font=(FONT, 11), text_color=MUTED, anchor="w").pack(side="left", padx=6)

            def unban(q=b["id"]):

                def work():
                    rr = self.link.req("unban", room=self.node.rid, user=q)
                    if rr.get("ok"):
                        self.q_putf("User {name} unbanned", name=q)
                        self.refresh_bans()
                    else:
                        self.q_putf("Unban failed: {err}", err=rr.get("err"))
                threading.Thread(target=work, daemon=True).start()
            if can:
                self.btn(r, "Unban", unban, CARD2, LINE, h=30, width=80).pack(side="right", padx=12, pady=8)

    # ------------------------------------------------------------ friends
    def build_friends(self):
        self.pg_friends = ctk.CTkFrame(self.body, fg_color=BG, corner_radius=0)
        self.page_head(self.pg_friends, "Friends & Chat")
        cols = self.fr_cols = ctk.CTkFrame(self.pg_friends, fg_color="transparent")
        cols.pack(fill="both", expand=True, padx=16, pady=(10, 14))
        self.fr_w = 340             # the list column, until somebody drags the line
        cols.grid_rowconfigure(0, weight=1)
        self.fr_pm_on = False

        left = ctk.CTkFrame(cols, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        left.grid(row=0, column=0, sticky="nsew")
        li = ctk.CTkFrame(left, fg_color="transparent")
        li.pack(fill="both", expand=True, padx=12, pady=12)
        sr = ctk.CTkFrame(li, fg_color="transparent")
        sr.pack(fill="x")
        self.fr_search = self.entry(sr, "Search username...")
        self.fr_search.pack(side="left", fill="x", expand=True)
        self.fr_search.bind("<Return>", lambda e: self.do_search())
        self.btn(sr, "Search", self.do_search, CARD2, LINE, h=40, width=76).pack(side="left", padx=(8, 0))
        self.fr_results = ctk.CTkFrame(li, fg_color="transparent", width=0, height=0)
        self.fr_results.pack(fill="x", pady=(4, 0))
        self.fr_body = ctk.CTkScrollableFrame(li, fg_color="transparent")
        self.fr_body.pack(fill="both", expand=True, pady=(4, 0))

        # the line between the list and the chat, and the chat itself, only appear once
        # a friend has been picked - until then the list owns the whole page
        self.fr_split = Splitter(cols, self.set_fr_w, lo=240, hi=620)
        right = self.fr_right = ctk.CTkFrame(cols, fg_color=CARD, corner_radius=14,
                                             border_width=1, border_color=LINE)
        hh = ctk.CTkFrame(right, fg_color="transparent")
        hh.pack(fill="x", padx=16, pady=(12, 4))
        self.btn(hh, "Close chat", self.close_pm, CARD2, LINE, h=28, width=104).pack(side="right")
        self.pm_title = Label(hh, text="No chat open", font=(FONT, 15, "bold"))
        self.pm_title.pack(side="left")
        self.pm_state = Label(hh, text="", font=(FONT, 12), text_color=MUTED)
        self.pm_state.pack(side="right")
        self.pm_box = ctk.CTkTextbox(right, font=(FONT, 13), wrap="word", fg_color=BG, text_color=TXT,
                                     corner_radius=10, border_width=1, border_color=LINE)
        fix_clipboard(self.pm_box)
        self.pm_box.pack(fill="both", expand=True, padx=14)
        for tag, kw in (("me", {"foreground": ACC}), ("them", {"foreground": "#5dade2"}),
                        ("sys", {"foreground": GRAY}), ("body", {"foreground": TXT}),
                        ("rtl", {"justify": "right"}), ("ltr", {"justify": "left"})):
            self.pm_box.tag_config(tag, **kw)
        self.pm_box.configure(state="disabled")
        self.pm_typing = Label(right, text="", font=(FONT, 11, "italic"),
                                      text_color=MUTED, anchor="w")
        self.pm_typing.pack(fill="x", padx=18, pady=(0, 2))
        crow = ctk.CTkFrame(right, fg_color="transparent")
        crow.pack(fill="x", padx=14, pady=12)
        self.pm_in = TextLine(crow, "Type a message...", on_enter=self.send_pm,
                              on_type=lambda: self.note_typing(self.sel_friend))
        self.pm_in.pack(side="left", fill="x", expand=True)
        self.btn(crow, "Send", self.send_pm, h=40, width=80).pack(side="left", padx=(8, 0))

    def refresh_friends(self):
        if not (self.link and self.link.alive):
            return

        def work():
            r = self.link.req("friends")
            if r.get("ok"):
                self.uq.put({"t": "friend_upd", "friends": r.get("friends", []),
                             "requests": r.get("requests", [])})
        threading.Thread(target=work, daemon=True).start()

    def do_search(self):
        q = self.fr_search.get().strip()

        def work():
            r = self.link.req("search", q=q)
            if r.get("ok"):
                self.uq.put({"t": "search", "users": r["users"]})
        threading.Thread(target=work, daemon=True).start()

    def show_search_results(self, users):
        for c in self.fr_results.winfo_children():
            c.destroy()
        if not users:
            Label(self.fr_results, text="No users found.", font=(FONT, 12),
                         text_color=MUTED).pack(pady=8)
            return
        for u in users[:8]:
            r = ctk.CTkFrame(self.fr_results, fg_color=CARD, corner_radius=8)
            r.pack(fill="x", pady=2)
            Label(r, text=u["name"], font=(FONT, 13), anchor="w").pack(side="left", padx=12, pady=6)

            def add(q=u["name"]):
                self.friend_req(q, "add_friend")
            self.btn(r, "Add", add, CARD2, LINE, h=28, width=64).pack(side="right", padx=10, pady=5)

    def friend_apply(self, r):
        """A friend action carries the fresh list of whoever did it: show it at once."""
        if "friends" in r:
            self.friends = {"friends": r.get("friends", []), "requests": r.get("requests", [])}
            self.rebuild_friends()

    def friend_req(self, name, cmd, **kw):
        """add_friend / friend_resp / remove_friend, then apply the answer immediately."""
        def work():
            r = self.link.req(cmd, user=name, **kw)
            if not r.get("ok"):
                self.q_putf("{cmd} failed: {err}", cmd=cmd.replace("_", " "), err=r.get("err"))
                return
            self.friend_apply(r)
            if cmd == "add_friend" and r.get("accepted"):
                self.q_putf("{name} is now your friend", name=name)
        threading.Thread(target=work, daemon=True).start()

    def rebuild_friends(self):
        if not (self.fr_body and self.fr_body.winfo_exists()):
            return
        for c in self.fr_body.winfo_children():
            c.destroy()
        fdata = self.friends
        if fdata.get("requests"):
            self.cap(self.fr_body, fmt("Friend requests ({n})", n=len(fdata["requests"])))
            for rq in sorted(fdata["requests"], key=by_name):
                r = ctk.CTkFrame(self.fr_body, fg_color=CARD, corner_radius=10,
                                 border_width=1, border_color=YELLOW)
                r.pack(fill="x", pady=3, padx=2)
                # the buttons are packed first: they keep their room and a long name is the
                # thing that gives way, not the word inside a button. Nothing touches the
                # card's edge, or its own background paints the border line away.
                self.btn(r, "✕", lambda q=rq["name"]: self.friend_req(q, "friend_resp", accept=False),
                         CARD2, LINE, h=28, width=36).pack(side="right", padx=3, pady=2)
                self.btn(r, "Accept", lambda q=rq["name"]: self.friend_req(q, "friend_resp", accept=True),
                         h=28, width=76).pack(side="right", padx=3, pady=2)
                Label(r, text=rq["name"], font=(FONT, 13, "bold"), anchor="w").pack(
                    side="left", padx=(10, 4), pady=2, fill="x", expand=True)
        self.cap(self.fr_body, fmt("Friends ({n})", n=len(fdata.get("friends", []))))
        if not fdata.get("friends"):
            Label(self.fr_body, text="No friends yet - search a username above.", font=(FONT, 12),
                         text_color=MUTED).pack(pady=8)
        for f in sorted(fdata.get("friends", []), key=by_name):
            picked = f["name"] == self.sel_friend
            r = ctk.CTkFrame(self.fr_body, fg_color=CARD, corner_radius=10,
                             border_width=1, border_color=(ACC if picked else LINE))
            r.pack(fill="x", pady=3, padx=2)
            # buttons first, so they keep their room and the name is what gives way - and
            # only as wide as their word needs, because the row has no slack to spare.
            # Nothing reaches the card's edge, or it paints the border line away.
            self.btn(r, "✕", lambda q=f["name"]: self.friend_req(q, "remove_friend"), CARD2, LINE,
                     h=28, width=32).pack(side="right", padx=3, pady=2)
            if self.node:
                self.btn(r, "Invite", lambda q=f["name"]: self.invite_friend(q), CARD2, LINE,
                         h=28, width=54).pack(side="right", padx=3, pady=2)
            unread = self.pm_unread.get(f["name"], 0)
            if unread:
                self.unread_badge(r, unread).pack(side="right", padx=(3, 0), pady=2)
            self.btn(r, "Chat", lambda q=f["name"]: self.open_pm(q), CARD2, LINE, h=28, width=56
                     ).pack(side="right", padx=3, pady=2)
            Label(r, text="●", text_color=(GREEN if f.get("online") else GRAY),
                         font=(FONT, 12)).pack(side="left", padx=(10, 3), pady=2)
            Label(r, text=fmt("{name}  (online)", name=f["name"]) if f.get("online")
                        else f["name"], font=(FONT, 13), anchor="w").pack(
                side="left", padx=(0, 4), pady=2, fill="x", expand=True)
        self.update_badges()

    def unread_badge(self, parent, n):
        """The red circle with the number of lines still unread inside it."""
        return Label(parent, text=str(n) if n < 100 else "99+", font=(FONT, 10, "bold"),
                     text_color="#ffffff", fg_color=RED, corner_radius=9, width=22, height=20)

    # ------------------------------------------------------------ friend to friend chat
    def pm_panel(self, on):
        """Show or hide the chat column and the line that splits it off the list. With no
        friend picked, the list is the page."""
        self.fr_pm_on = bool(on)
        if on:
            self.fr_split.grid(row=0, column=1, sticky="ns")
            self.fr_right.grid(row=0, column=2, sticky="nsew")
        else:
            self.fr_split.grid_forget()
            self.fr_right.grid_forget()
        self.set_fr_w(self.fr_w)

    def set_fr_w(self, w=None):
        """The list column's width - typed by the drag, kept for the next time the chat opens."""
        self.fr_w = int(w or self.fr_w)
        cols, on = self.fr_cols, self.fr_pm_on
        cols.grid_columnconfigure(0, minsize=self.fr_w if on else 0, weight=0 if on else 1)
        cols.grid_columnconfigure(1, minsize=8 if on else 0, weight=0)
        cols.grid_columnconfigure(2, minsize=280 if on else 0, weight=1 if on else 0)

    def close_pm(self):
        self.sel_friend = None
        self.pm_panel(False)
        self.pm_show()
        self.rebuild_friends()
        self.update_badges()

    def open_pm(self, name):
        self.sel_friend = name
        self.pm_unread.pop(name, None)
        self.pm_panel(True)
        self.rebuild_friends()
        self.pm_show()

    def pm_show(self):
        if not (self.pm_box and self.pm_box.winfo_exists()):
            return
        name = self.sel_friend
        self.pm_box.configure(state="normal")
        self.pm_box.delete("1.0", "end")
        if not name:
            self.pm_panel(False)        # nobody picked: the list owns the page
            setw(self.pm_title, text="No chat open")
            setw(self.pm_state, text="pick a friend on the left")
            self.pm_box.configure(state="disabled")
            return
        self.pm_panel(True)             # a friend is picked: the chat column is on the page
        if self.page == "friends":
            self.pm_unread.pop(name, None)      # looking at it now, so it is not waiting anymore
        f = next((x for x in self.friends.get("friends", []) if x["name"] == name), None)
        setw(self.pm_title, text=name)
        setw(self.pm_state, text="online" if f and f.get("online") else "offline")
        for who, text, ts in self.pms.get(name, []):
            self.chat_add(who, text, "me" if who == "You" else "them", ts, box=self.pm_box)
        self.pm_box.configure(state="disabled")

    def pm_add(self, name, who, text, ts=None, mine=False):
        self.pms.setdefault(name, []).append((who, text, ts))
        if name == self.sel_friend and self.page == "friends":
            self.chat_add(who, text, "me" if mine else "them", ts, box=self.pm_box)
            if not mine:
                self.beep(pm=True)
            return
        if not mine:            # nobody is looking at it: count it on the tab and on the row
            self.pm_unread[name] = self.pm_unread.get(name, 0) + 1
            self.rebuild_friends()
            self.note_pm(name, text)
            self.beep(pm=True)

    def send_pm(self):
        txt, name = self.pm_in.value(), self.sel_friend
        if not txt or not name or not (self.link and self.link.alive):
            return
        self.pm_in.set("")

        def work():
            r = self.link.req("pm", user=name, text=txt)
            if r.get("ok"):
                self.uq.put({"t": "pm_own", "to": name, "text": txt, "ts": r.get("ts"),
                             "delivered": r.get("delivered")})
            else:
                self.uq.put({"t": "pm_err", "err": r.get("err") or "could not send"})
        threading.Thread(target=work, daemon=True).start()

    def focused(self):
        """True only while this window is the thing on screen you are talking through."""
        try:
            return self.state() != "iconic" and bool(self.winfo_focuses())
        except Exception:
            return False

    def beep(self, pm=False):
        """The chat sound rings for the app you are looking at - never over a game, and
        never at all when the message sound is off. A friend's words get the team's own
        sound file; anything else keeps the system ding."""
        if not SOUND[0] or not self.focused():
            return
        if pm and play_file(res_path(SND_FILE)):
            return
        if winsound:
            try:
                winsound.PlaySound("SystemAsterisk", winsound.SND_ALIAS)
            except Exception:
                pass

    def invite_friend(self, name):
        if not self.node:
            return

        def work():
            r = self.link.req("invite", user=name, room=self.node.rid)
            if r.get("ok"):
                self.q_putf("Invite sent to {name}", name=name)
            else:
                self.q_putf("Invite failed: {err}", err=r.get("err"))
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ chat
    def chat_clear(self):
        self.chatbox.configure(state="normal")
        self.chatbox.delete("1.0", "end")
        self.chatbox.configure(state="disabled")

    def chat_add(self, who, text, tag, ts=None, box=None):
        box = box or self.chatbox
        stamp = time.strftime("%H:%M", time.localtime(ts or time.time()))
        if tag == "sys":                      # the app's own words; a player's are not
            who, text = T(who), T(text)
        rtl = has_rtl(text)
        j = "rtl" if rtl else "ltr"
        box.configure(state="normal")
        box.insert("end", f"{who}  {stamp}\n", (tag, j))
        box.insert("end", bidi(text) + "\n\n", ("body", j))
        box.mark_set("insert", "end-1c")      # no stray caret in the read-only log
        box.see("end")
        box.configure(state="disabled")

    # ------------------------------------------------------------ "is typing"
    def note_typing(self, to=None):
        """Say it on the wire at most twice in five seconds - enough for the dots."""
        if not (self.link and self.link.alive) or not self.node and not to:
            return
        key = to or "room"
        now = time.time()
        if now - self.type_t.get(key, 0.0) < 2.5:
            return
        self.type_t[key] = now
        self.link.notify_server("typing", **({"user": to} if to else {}))

    def typing_line(self, names):
        if not names:
            return ""
        if len(names) == 1:
            return fmt("{name} is typing ...", name=names[0])
        if len(names) == 2:
            return fmt("{a} and {b} are typing ...", a=names[0], b=names[1])
        return fmt("{n} people are typing ...", n=len(names))

    def tick_typing(self):
        """Drop the stale names and repaint both indicators."""
        now = time.time()
        live = self.typing_room = {k: v for k, v in self.typing_room.items()
                                   if v > now and self.node}
        if self.lbl_typing.winfo_exists():
            setw(self.lbl_typing, text=self.typing_line(sorted(live)))
        who = self.sel_friend
        live = self.typing_pm = {k: v for k, v in self.typing_pm.items()
                                 if v > now and k == who}
        if self.pm_typing.winfo_exists():
            setw(self.pm_typing, text=self.typing_line(sorted(live)))

    def send_chat(self):
        txt = self.chat_in.value()
        if not txt:
            return
        n = self.node
        if not (n and n.running):
            self.chat_add("system", "Not connected", "sys")
            return
        self.chat_in.set("")
        if n.send_chat(txt):
            self.chat_add("You", txt, "me")
            self.beep()
        else:
            self.chat_add("system", "Could not send - check the connection to the server", "sys")

    # ------------------------------------------------------------ logs
    def redraw_log(self):
        """The log is words too. Its lines are kept in the language they were written in, so
        turning the app over says the whole history again - in the new language, in the order
        the new language reads, and ready to be copied without a scramble."""
        try:
            self.logbox.configure(state="normal")
            self.logbox.delete("1.0", "end")
            for stamp, raw in self.log_src:
                line = stamp + self.say(raw) + "\n"
                self.logbox.insert("end", line, ("rtl" if has_rtl(line) else "ltr",))
            self.logbox.see("end")
            self.logbox.configure(state="disabled")
        except Exception:
            pass

    def copy_log(self):
        self.clipboard_clear()
        self.clipboard_append(self.logbox.get("1.0", "end"))
        self.q_put("Log copied to clipboard")

    def run_diag(self):
        self.q_put(self.node.diag() if self.node else "Not connected")

    def export_zip(self):
        log_text = self.logbox.get("1.0", "end")
        diag = self.node.diag() if self.node else "Not connected"
        self.q_put("Collecting diagnostics (a few seconds)...")

        def work():
            try:
                path = os.path.join(APP_DIR, f"vlan42_diag_{time.strftime('%Y%m%d_%H%M%S')}.zip")
                cmds = {"ipconfig.txt": "ipconfig /all", "getmac.txt": "getmac",
                        "firewall.txt": "netsh advfirewall show allprofiles",
                        "interfaces.txt": "netsh interface show interface", "routes.txt": "route print"}
                with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
                    z.writestr("session_log.txt", log_text)
                    z.writestr("diag.txt", diag)
                    try:
                        cfg = load_cfg()
                        cfg.pop("token", None)
                        z.writestr("vlan42.json", json.dumps(cfg, indent=2))
                    except Exception:
                        pass
                    for fname, cmd in cmds.items():
                        try:
                            z.writestr(fname, oem_decode(sh(cmd).stdout))
                        except Exception as ex:
                            z.writestr(fname, f"failed: {ex}")
                self.q_putf("Diagnostics ZIP saved: {path}", path=path)
                subprocess.Popen(f'explorer /select,"{path}"')
            except Exception:
                self.q_put(f"ZIP export failed:\n{traceback.format_exc()}")
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ periodic UI update
    def refresh(self):
        if self.closing:
            return
        try:
            if self.hangf:
                faulthandler.dump_traceback_later(10, file=self.hangf)
            self.tick()
        except Exception:
            if time.time() - self.ui_err_t > 30:
                self.ui_err_t = time.time()
                self.q_put("UI error (the app keeps running):\n" + traceback.format_exc())
        finally:
            if not self.closing:
                try:
                    idle = self.state() == "iconic"
                except Exception:
                    idle = False
                self.after(2500 if idle else 1000, self.refresh)

    def report_callback_exception(self, exc, val, tb):
        self.q_put("UI callback error:\n" + "".join(traceback.format_exception(exc, val, tb)))

    def tick(self):
        if LANG[0] == "fa" and time.time() >= self.mirror_t:
            # rows, notices and panels built since the last switch get into the mirror too
            self.mirror_t = time.time() + 0.8
            try:
                self.mirror_all(True)
            except Exception:
                pass
        if self.need_wintun and not self.busy:
            self.need_wintun = False
            self.ask_wintun()
        if self.auto_connect and not self.busy and not self.node and self.link and self.link.alive \
                and self.my_rooms:
            self.auto_connect = False
            room = next((r for r in self.my_rooms if r.get("my_role") == "owner"), self.my_rooms[0])
            self.enter_room(room)
        lines = []
        while True:
            try:
                raw = self.q.get_nowait()
            except queue.Empty:
                break
            stamp = time.strftime("%H:%M:%S ")
            self.log_src.append((stamp, raw))
            lines.append(stamp + self.say(raw) + "\n")
        if lines:
            self.last_log = lines[-1][9:].split("\n", 1)[0][:90]
            self.logbox.configure(state="normal")
            for line in lines:            # every line keeps the side its language wants
                self.logbox.insert("end", line, ("rtl" if has_rtl(line) else "ltr",))
            n = int(self.logbox.index("end-1c").split(".")[0])
            if n > 1500:
                self.logbox.delete("1.0", f"{n - 1200}.0")
            self.logbox.see("end")
            self.logbox.configure(state="disabled")
        while not self.cq.empty():
            nm, tx, ts = self.cq.get()
            self.chat_add(nm, tx, "them", ts)
            self.beep()
            for k in [k for k in self.typing_room if nm.startswith(k)]:
                self.typing_room.pop(k, None)   # they finished the line they were typing
        while not self.uq.empty():
            self.on_event(self.uq.get_nowait())
        self.tick_typing()
        n = self.node
        if not self.link:
            want = "login"
        else:
            want = self.tab or ("room" if n else "start")
            if want == "room" and not n:
                want = "start"
        if want != self.page:
            self.show_page(want)
        if n:
            self.update_room(n)
        if want == "start":
            self.update_start()
        else:
            if self.busy:
                setw(self.lbl_login_err, text=self.last_log, text_color=MUTED)
            elif not self.lbl_login_err.cget("text"):
                setw(self.lbl_login_err, text=self.err, text_color=RED)

    def on_event(self, ev):
        t = ev.get("t")
        if t == "auth_ok":
            self.on_auth_ok(ev)
        elif t == "auth_fail":
            self.on_auth_fail(ev)
        elif t == "pwd_ans":
            self.password_answer(ev["r"])
        elif t == "con_rows":
            self.console_ready(ev["view"], ev["r"])
        elif t == "con_done":
            self.console_answer(ev["r"])
            self.console_load()
        elif t == "con_enter":
            self.console_answer(ev["r"])
            if ev["r"].get("ok") and ev["r"].get("room"):
                self.enter_room(ev["r"]["room"])      # leaves whatever room this is now
        elif t == "staff":
            self.on_staff(ev)
        elif t == "my_rooms":
            self.on_my_rooms(ev["rooms"])
        elif t == "enter_room":
            self.enter_room(ev["room"])
        elif t == "room_state":
            room = ev.get("room")
            if not room:
                return
            if self.node and room["id"] == self.node.rid:
                self.node.update_state(room)
                self.room_name = room["name"]
                self.jreq_n = max(self.jreq_n, int(room.get("pending") or 0))
                self.update_badges()
                self.update_room_rows()
                if self.awin and self.awin.winfo_exists():
                    self.rebuild_admin()
            for i, r in enumerate(self.my_rooms):
                # a member who never entered the room must still see the roster change now
                if r.get("id") == room["id"]:
                    self.my_rooms[i] = room
                    self.on_my_rooms(self.my_rooms)
                    break
        elif t == "typing":
            who, rid = ev.get("from"), ev.get("room")
            if who and who != self.my_name:
                if rid:
                    if self.node and rid == self.node.rid:
                        self.typing_room[who] = time.time() + 4
                else:
                    self.typing_pm[who] = time.time() + 4
        elif t == "chat":
            if self.node and ev.get("room") == self.node.rid \
                    and ev.get("from") != self.my_name:
                who = with_rank(ev.get("from", "?"), ev.get("role"))
                self.cq.put((who, ev.get("text", ""), ev.get("ts")))
        elif t == "kicked":
            if self.node and ev.get("room") == self.node.rid:
                self.q_putf("You were kicked from the room by {by}", by=ev.get("by"))
                self.chat_add("system", fmt("You were kicked by {by}.", by=ev.get("by")), "sys")
                self.tab = "start"
                self.leave()
                self.refresh_rooms()
        elif t == "banned":
            if self.node and ev.get("room") == self.node.rid:
                self.q_putf("You were banned from the room by {by} ({reason})",
                       by=ev.get("by"), reason=ev.get("reason") or "no reason")
                self.chat_add("system", fmt("You were banned by {by} ({reason}).",
                                      by=ev.get("by"), reason=ev.get("reason") or "no reason"), "sys")
                self.tab = "start"
                self.leave()
                self.refresh_rooms()
        elif t == "get_roles":
            if ev.get("ok"):
                self.role_defaults = ev.get("defaults") or {}
                self.rebuild_roles()
        elif t == "set_roles":
            if ev.get("ok"):
                self.role_defaults = ev.get("defaults") or {}
                self.q_put("Room defaults saved")
                self.refresh_room_state()
            else:
                self.q_put(ev.get("err") or "Saving the defaults failed")
        elif t == "member_offline":
            why = ev.get("reason") or "timeout"
            self.q_putf("{name} went offline: {why}", name=ev.get("name", "?"), why=word(why))
        elif t == "peer_timeout":
            why = ev.get("reason") or "timeout"
            self.chat_add("system", f"{ev.get('name', '?')} - {T(why)}", "sys")
        elif t == "friend_upd":
            self.friends = {"friends": ev.get("friends", []), "requests": ev.get("requests", [])}
            self.rebuild_friends()
            if self.page == "friends":
                self.pm_show()
        elif t == "join_pending":
            self.q_put(ev.get("msg") or "The host must approve you before you can enter")
            self.notify("Join request", fmt("Waiting for the host of {room}", room=ev.get("name") or ""),
                        keep=30, kind="join")
        elif t == "join_ok":
            self.clear_hint("join")           # the answer is here: the waiting line is done
            self.q_putf("{who} let you into {room}", who=ev.get("by", "?"),
                           room=ev.get("name", ""))
            self.await_enter = ev.get("room")
            self.refresh_rooms(True)
        elif t == "join_no":
            self.clear_hint("join")
            self.q_putf("{who} did not let you in", who=ev.get("by", "?"))
        elif t == "jreq":
            rq = {"room": ev.get("room"), "id": ev.get("user"), "name": ev.get("from", "?"),
                  "ts": ev.get("ts", time.time())}
            self.jreq = [x for x in self.jreq if x["id"] != rq["id"]] + [rq]
            self.jreq_n = max(int(ev.get("count") or 0), len(self.jreq))
            self.note_join_req(rq)
            self.update_badges()
            self.rebuild_requests()
        elif t == "jreq_upd":
            if ev.get("requests") is not None:
                self.jreq = [dict(x, room=ev.get("room")) for x in ev["requests"]]
                self.jreq_n = len(self.jreq)
            else:
                self.jreq_n = int(ev.get("count") or 0)
                self.refresh_jreq()
            self.update_badges()
            self.rebuild_requests()
        elif t == "friend_req":
            self.q_putf("{who} sent you a friend request", who=ev.get("from"))
            self.note_friend_req(ev.get("from", "?"))
            self.refresh_friends()
        elif t == "pm":
            self.pm_add(ev.get("from", "?"), ev.get("from", "?"), ev.get("text", ""), ev.get("ts"))
        elif t == "pm_own":
            self.pm_add(ev["to"], "You", ev["text"], ev.get("ts"), mine=True)
            if not ev.get("delivered"):
                self.q_putf("{who} is not online - your message was not delivered", who=ev["to"])
        elif t == "pm_err":
            self.q_putf("Chat failed: {err}", err=ev.get("err"))
        elif t == "search":
            self.show_search_results(ev.get("users", []))
        elif t == "ban_list":
            self.rebuild_bans(ev.get("bans", []))
        elif t == "invite":
            self.set_invite(ev)
            self.q_putf("{who} invited you to the room '{room}'",
                       who=ev.get("from"), room=ev.get("room"))
        elif t == "signed_elsewhere":
            if self.node:
                self.leave()
            if self.link:
                self.link.close()
                self.link = None
            self.clear_rooms()
            self.err = "This account was used to sign in on another device."
            self.show_page("login")
        elif t == "link_down":
            if not self.link:
                return        # already handled (logout / signed in elsewhere)
            self.q_putf("Connection to the server lost: {why}", why=ev.get("why", ""))
            if self.node:
                self.leave()
            if self.link:
                self.link.close()
                self.link = None
            self.clear_rooms()
            self.err = "Connection to the server lost. Please log in again."
            self.show_page("login")

    def update_start(self):
        if self.page != "start":
            return
        # the list is kept alive by events (create/join/remove/kick/room_state);
        # this slow poll is only a safety net, so the rows never visibly refresh
        if not self.node and self.link and self.link.alive and time.time() - self.rooms_t > 25:
            self.refresh_rooms()
        for rid, row in self.room_rows.items():
            if rid == self.entering_rid:
                txt = "Entering…"
            elif self.node and rid == self.node.rid:
                txt = "Open"            # you are already inside: this opens the room page
            else:
                txt = "Enter"
            setw(row["enter"], text=txt)
        if self.node and self.entering_rid:
            setf(self.lbl_acct, "entering '{room}' - preparing the virtual adapter...",
                 {"room": self.room_name}, text_color=YELLOW)
        elif self.node:
            setf(self.lbl_acct, "inside '{room}' - the room stays connected",
                 {"room": self.room_name}, text_color=ACC)
        elif self.err:
            setw(self.lbl_acct, text=self.err, text_color=RED)
        else:
            setf(self.lbl_acct, "{app} network online", {"app": APP_NAME}, text_color=MUTED)
        for b, t, in ((self.b_create, "Create room"), (self.b_join, "Join room")):
            setw(b, text=t, state="normal")

    # ------------------------------------------------------------ room UI
    def update_room_rows(self):
        """(Re)build the player rows when the roster or my permissions change."""
        if not self.node:
            return
        room = self.node.room
        key = (tuple(sorted((m["id"], m.get("role")) for m in room.get("members", []))),
               room.get("my_role"), json.dumps(room.get("my_perms") or {}, sort_keys=True))
        if key == self.role_key:
            return
        self.role_key = key
        for row in self.rows.values():
            try:
                row[0].destroy()
            except Exception:
                pass
        self.rows = {}
        perms = self.my_perms()
        mine_id = self.link.user["id"] if (self.link and self.link.user) else None
        # top to bottom by rank first - owner, admin, member - and by name inside a rank.
        # The key below carries every member's role, so a rank that changes reorders the
        # column on the very next word the server sends.
        for m in sorted(room.get("members", []), key=by_role):
            pid = m["id"]
            mine = pid == mine_id
            role = m.get("role", "member")
            # one line per player, inside a card of its own: dot, name, ip, ping, buttons.
            # every piece sits two pixels off the edge - a child that reaches the edge paints
            # its own background over the card's border and leaves the line in pieces.
            r = ctk.CTkFrame(self.plist, fg_color=(LINE if mine else CARD2), corner_radius=10,
                             border_width=1, border_color=(ACC if mine else LINE),
                             width=0, height=0)
            r.pack(fill="x", pady=3, padx=4)
            # width=0 keeps an empty holder from claiming the 200x200 customtkinter default
            btns = ctk.CTkFrame(r, fg_color="transparent", width=0, height=0)
            btns.pack(side="right", padx=(2, 6), pady=2)
            ping = Label(r, text="...", font=(FONT, 12), width=44, anchor="e")
            ping.pack(side="right", padx=(3, 2), pady=2)
            info = Label(r, text=m.get("vip", ""), font=(FONT, 12), text_color=MUTED,
                                anchor="e", width=70)
            info.pack(side="right", padx=(8, 3), pady=2)
            dot = Label(r, text="●", font=(FONT, 14),
                              text_color=(GREEN if m.get("online") else GRAY))
            dot.pack(side="left", padx=(8, 4), pady=2)
            who = ctk.CTkFrame(r, fg_color="transparent", width=0, height=0)
            who.pack(side="left", fill="x", expand=True, padx=(0, 4), pady=2)
            name = Label(who, font=(FONT, 13), anchor="w",
                               text=fmt("{who}   (you)", who=m.get("name", "?")) if mine
                               else m.get("name", "?"))
            name.pack(side="left")
            mgr = bool((m.get("perms") or {}).get("manage"))
            rank = Label(who, text=rank_mark(role, mgr), font=(FONT, 11),
                               text_color=rank_color(role, mgr))
            rank.pack(side="left", padx=(6, 0))
            if not mine:
                if self.my_role() == "owner" or perms.get("kick"):
                    kb = Btn(btns, text="Kick", width=44, height=26, font=(FONT, 11),
                                       corner_radius=8, fg_color=CARD, hover_color=LINE, text_color=YELLOW,
                                       command=lambda q=pid: self.kick_user(q))
                    kb.pack(side="left", padx=1)
                if self.my_role() == "owner" or perms.get("ban"):
                    bb = Btn(btns, text="Ban", width=44, height=26, font=(FONT, 11),
                                       corner_radius=8, fg_color=CARD, hover_color=LINE, text_color=RED,
                                       command=lambda q=pid: self.ban_user(q))
                    bb.pack(side="left", padx=1)
            for w in (r, dot, who, name, rank, info, ping):
                w.configure(cursor="hand2")
                w.bind("<Button-1>", lambda e, q=pid: self.copy_peer_ip(q))
            self.rows[pid] = (r, name, info, ping, dot)
        # the caption that waits for friends belongs under the roster. pack does not move a
        # widget it already manages when you only change its padding, and the rows that used
        # to hold it down there were just destroyed - so say plainly where it sits now.
        # Without this the column reads "nobody here yet" first and the players after it.
        if self.empty_on and self.rows:
            self.empty.pack(pady=50, after=self.rows[list(self.rows)[-1]][0])
        # and the list always starts at its top: rank order is read from the first line,
        # not from wherever the last rebuild happened to leave the scroll
        try:
            self.plist._parent_canvas.yview_moveto(0)
        except Exception:
            pass

    def peer_vip(self, n, pid):
        """The virtual IP a player holds in this room - the roster is the authority."""
        m = next((x for x in n.room.get("members", []) if x["id"] == pid), None)
        return (m or {}).get("vip") or (n.peers.get(pid) or {}).get("vip") or ""

    def copy_peer_ip(self, pid):
        """Any player line, mine included, hands over the virtual IP it shows - and says so
        on the line itself, because a clipboard has no news of its own."""
        n = self.node
        if not n:
            return
        vip = self.peer_vip(n, pid)
        if not vip:
            return
        self.clipboard_clear()
        self.clipboard_append(vip)
        row = self.rows.get(pid)
        if row:
            try:
                setw(row[2], text="Copied ✓", text_color=ACC)
                row[2].__dict__["_hold"] = time.time() + 1.6    # the line holds still, then
            except Exception:                                   # puts its IP back on its own
                pass
        self.q_putf("{vip} copied - paste it into the game", vip=vip)

    def update_room(self, n):
        self.invite_text = n.room.get("invite") or self.invite_text   # the server keeps it fresh
        setw(self.lbl_you, text=fmt("{who}   ·   {vip}   ·   role: {r}",
                                     who=with_rank(self.my_name, self.my_role(), self.is_mgr()),
                                     vip=n.vip,
                                     r=T(ROLE_BADGE.get(self.my_role(), ROLE_BADGE["member"])[0])))
        self.update_room_rows()
        mine_id = self.link.user["id"] if (self.link and self.link.user) else None
        online = 0
        now = time.time()
        for pid, row in self.rows.items():
            r, name, info, ping, dot = row
            if now < getattr(info, "_hold", 0):     # a freshly copied line keeps its mark
                continue
            info.__dict__.pop("_hold", None)
            if pid == mine_id:
                # my own line: the round trip to the VPS is the number that matters
                setw(dot, text_color=GREEN)
                setw(info, text=self.peer_vip(n, pid) or n.vip or "")
                if n.srv_rtt:
                    setw(ping, text=f"{n.srv_rtt:.0f} ms",
                         text_color=GREEN if n.srv_rtt < 60 else YELLOW if n.srv_rtt < 120 else RED)
                else:
                    setw(ping, text="...", text_color=YELLOW)
                online += 1
                continue
            p = n.peers.get(pid)
            if not p:
                continue
            vip = self.peer_vip(n, pid)
            live = bool(p.get("online")) and not p.get("timed_out")
            setw(dot, text_color=GREEN if live else GRAY)
            setw(name, text=p.get("name", "?"))
            if p.get("timed_out"):
                setw(ping, text="timeout", text_color=RED)
                setw(info, text=fmt("{vip}  ·  no answer since {t}", vip=vip,
                                    t=time.strftime("%H:%M:%S", time.localtime(p.get("last", 0)))))
            elif not p.get("online"):
                setw(ping, text="offline", text_color=GRAY)
                setw(info, text=vip)
            else:
                rtt = p.get("rtt")
                if rtt is None:
                    setw(ping, text="...", text_color=YELLOW)
                else:
                    setw(ping, text=f"{rtt:.0f} ms",
                         text_color=GREEN if rtt < 60 else YELLOW if rtt < 120 else RED)
                setw(info, text=vip)
                online += 1
        if self.link and self.link.alive:
            # one person standing inside is still a room attached to the server
            setw(self.lbl_status, text="● Connected", text_color=GREEN)
        else:
            setw(self.lbl_status, text="● Waiting", text_color=YELLOW)
        setw(self.lbl_count, text=fmt("{n} online", n=online))
        t0, tx0, rx0 = self.stat
        if now - t0 >= 1:
            setw(self.lbl_stats, text=f"↑ {(n.tx - tx0) / (now - t0) / 1024:.1f} KB/s   "
                                      f"↓ {(n.rx - rx0) / (now - t0) / 1024:.1f} KB/s")
            self.stat = (now, n.tx, n.rx)
        if n.peers:
            if self.empty_on:
                self.empty.pack_forget()
                self.empty_on = False
        else:
            setw(self.empty, text="Waiting for your friends...\nSend them the invite code.")
            if not self.empty_on:
                self.empty.pack(pady=50)
                self.empty_on = True

    # ------------------------------------------------------------ close
    def on_close(self):
        self.closing = True
        try:
            faulthandler.cancel_dump_traceback_later()
        except Exception:
            pass
        self.withdraw()
        node, self.node = self.node, None
        link, self.link = self.link, None

        def finish():
            try:
                if node:
                    node.stop()
                if link:
                    link.close()
            except Exception:
                pass
            self._finish_close()
        t = threading.Thread(target=finish, daemon=True)
        t.start()
        t0 = time.time()

        def wait():
            if t.is_alive() and time.time() - t0 < 5:
                self.after(80, wait)
            else:
                self._finish_close()
        wait()

    def _finish_close(self):
        try:
            faulthandler.cancel_dump_traceback_later()
            if self.hangf:
                self.hangf.close()
            try:
                os.remove(HANG_FILE)        # a clean exit leaves no file behind
            except OSError:
                pass
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    if "--make-icon" in sys.argv:
        i = sys.argv.index("--make-icon")
        make_icon(sys.argv[i + 1] if len(sys.argv) > i + 1 else "V.Lan.42.ico")
        sys.exit()
    if os.name != "nt":
        sys.exit("This version supports Windows only.")
    if not is_admin():
        args = sys.argv[1:] if getattr(sys, "frozen", False) else sys.argv
        exe = sys.executable
        if not getattr(sys, "frozen", False):
            pyw = exe.replace("python.exe", "pythonw.exe")
            exe = pyw if os.path.exists(pyw) else exe
        ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, " ".join(f'"{a}"' for a in args), None, 1)
        sys.exit()
    if already_running():
        ctypes.windll.user32.MessageBoxW(0, f"{APP_NAME} is already running.", APP_NAME, 0x40)
        sys.exit()
    register_protocol()
    inv_arg = next((a for a in sys.argv[1:] if a.lower().startswith(("vlan42://", "esh-vlan://"))), None)
    try:
        app = App(inv_arg)
        if load_cfg().get("token"):
            app.after(500, app.try_token_login)
        app.mainloop()
    except Exception:
        err = traceback.format_exc()
        try:
            with open(os.path.join(APP_DIR, "vlan42_crash.txt"), "a", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S\n") + err + "\n")
        except OSError:
            pass
        ctypes.windll.user32.MessageBoxW(0, f"{APP_NAME} stopped because of an error.\n"
                                         f"Details: vlan42_crash.txt\n\n" + err[-700:], APP_NAME, 0x10)
