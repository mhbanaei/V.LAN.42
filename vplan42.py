# -*- coding: utf-8 -*-
"""
V.Lan.42 - virtual LAN for games over your own VPS (Windows, run as Admin)

How it works:
  * Server        : your VPS runs vlan42_server.py (start it with start_server.bat)
                    Players never enter an address - the team supplies it in
                    SERVER_HOSTS or a vlan42_servers.txt shipped with the app.
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

APP_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
CFG_FILE = os.path.join(APP_DIR, "vlan42.json")
IFACE = "V-Lan-42"
APP_NAME = "V LAN 42"
LOGO_FILE = "V.Lan.42.ico"
GITHUB_URL = "https://github.com/mhbanaei"
DEFAULT_PORT = 4242
MAX_ROOMS = 3
# Users only ever sign in with a username and password - the app never asks for an address.
# The V.Lan.42 team runs start_server.bat on each VPS and supplies its IP here, or ships a
# vlan42_servers.txt (next to V.Lan.42.exe / in the build folder) with one "ip" or "ip:port" per line.
SERVER_HOSTS = []
SERVER_HOSTS_FILE = "vlan42_servers.txt"
PERM_LABELS = {"kick": "Kick", "ban": "Ban", "unban": "Unban", "limit": "Member limit"}


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
class VpsLink:
    """Encrypted TCP control channel to the V.Lan.42 server."""

    def __init__(self, host, port, log):
        self.host, self.port, self.log = host, port, log
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


def open_link(log):
    """Return a control link to the first VPS that answers."""
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
        self.log(f"Connecting to room '{self.room['name']}' through {self.link.host} ...")
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
            raise OSError(f"No answer from the {APP_NAME} relay on UDP {self.link.port} at {self.link.host}. "
                          f"Open inbound UDP {self.link.port} on the VPS (its own firewall *and* the panel "
                          f"of the hosting company). Check it with:  python vlan42_check.py {self.link.host}")
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
                    self.log(f"UDP relay ready ({self.link.host})")
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
                if alone:
                    self._ping_t = time.time()
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
                 f"Server {self.link.host}:{self.link.port} | link {'up' if self.link.alive else 'DOWN'}"
                 f" | server ping {f'{self.srv_rtt:.0f}ms' if self.srv_rtt else '?'}",
                 f"Room {self.room.get('name')} #{self.rid} | virtual IP {self.vip}",
                 "Thread heartbeat (seconds ago): " + ", ".join(f"{k}={now - v:.0f}" for k, v in self.hb.items())
                 + f", tun={now - getattr(self.tun, 'last_loop', now):.0f}"]
        for uid, p in list(self.peers.items()):
            lines.append(f"  peer {p.get('name')} {p.get('vip')} online={p.get('online')} "
                         f"rtt={p.get('rtt', -1) if p.get('rtt') is not None else -1:.0f}ms "
                         f"loss={p.get('loss', 0):.0f}% timed_out={p.get('timed_out')}")
        return "\n".join(lines)


# ----------------------------------------------------------------- invite links
INVITE_PREFIX = "vlan42://join/"


def make_invite(code, pwd):
    raw = json.dumps({"c": code, "p": pwd}, separators=(",", ":")).encode()
    return INVITE_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def parse_invite(text):
    try:
        code = text.strip().rstrip("/").split("/")[-1].strip()
        d = json.loads(base64.urlsafe_b64decode(code + "=" * (-len(code) % 4)))
        return str(d["c"]), str(d["p"])
    except Exception:
        return None


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
ACC, ACC_H, BLUE = "#2ecc71", "#27ae60", "#3498db"
TXT, MUTED = "#e8edf3", "#8896a8"
GREEN, YELLOW, RED, GRAY = "#2ecc71", "#f1c40f", "#e74c3c", "#6b7686"
GOLD = "#f5c542"
FONT = "Segoe UI"


def has_rtl(text):
    return any("\u0590" <= c <= "\u08ff" or "\ufb1d" <= c <= "\ufdff" or "\ufe70" <= c <= "\ufeff" for c in text)


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
    cache = w.__dict__.setdefault("_last", {})
    ch = {k: v for k, v in kw.items() if cache.get(k) != v}
    if ch:
        cache.update(ch)
        w.configure(**ch)


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

    def __init__(self, master, placeholder="", on_enter=None, height=40, **kw):
        super().__init__(master, height=height, wrap="none", activate_scrollbars=False, fg_color=CARD2,
                         border_width=1, border_color=LINE, corner_radius=8, font=(FONT, 14),
                         text_color=TXT, **kw)
        self.ph, self.on_enter, self.ph_on = placeholder, on_enter, False
        self.tag_config("rtl", justify="right")
        self.tag_config("ph", foreground=GRAY)
        self.bind("<FocusIn>", lambda e: self.clear_ph())
        self.bind("<FocusOut>", lambda e: self.show_ph())
        self.bind("<Return>", self.enter)
        self.bind("<KeyRelease>", lambda e: self.align())
        fix_clipboard(self)
        self.show_ph()

    def show_ph(self):
        if self.ph and not self.get("1.0", "end-1c"):
            self.insert("1.0", self.ph, "ph")
            self.ph_on = True

    def clear_ph(self):
        if self.ph_on:
            self.delete("1.0", "end")
            self.ph_on = False

    def enter(self, e=None):
        if self.on_enter:
            self.on_enter()
        return "break"

    def align(self):
        if self.ph_on:
            return
        self.tag_remove("rtl", "1.0", "end")
        if has_rtl(self.get("1.0", "end-1c")):
            self.tag_add("rtl", "1.0", "end")

    def value(self):
        return "" if self.ph_on else self.get("1.0", "end-1c").replace("\n", " ").strip()

    def set(self, text):
        self.clear_ph()
        self.delete("1.0", "end")
        self.insert("1.0", text)
        self.align()
        if not text and self.focus_get() is not self._textbox:
            self.show_ph()


ROLE_BADGE = {"owner": ("👑 Owner", GOLD), "admin": ("🛡 Admin", BLUE), "member": ("Member", MUTED)}


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
        self.closing, self.last_log, self.logf, self.empty_on = False, "", None, False
        self.ui_err_t, self.hangf = 0.0, None
        try:
            hp = os.path.join(APP_DIR, "vlan42_hang.txt")
            self.hangf = open(hp, "w" if os.path.exists(hp) and os.path.getsize(hp) > 200_000 else "a", buffering=1)
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
        self.rows, self.room_rows, self.stat = {}, {}, (time.time(), 0, 0)
        self.my_rooms, self.friends = [], {"friends": [], "requests": []}
        self.rooms_empty = None
        self.need_wintun, self.auto_connect = False, False
        self.last_args, self.invite_text, self.err = None, "", ""
        self.room_name, self.my_name = "", ""
        self.pending_enter = None       # room dict waiting for login
        self.role_key = None
        self.invite = None              # {"from","room","code","pwd"}
        self.awin = self.bwin = None
        self.rooms_t = 0.0
        self.entering_rid = None
        self.tab = None                  # the tab the player opened
        self.tabs = {}                   # key -> (holder frame, button, badge)
        self.pages = {}
        self.pms, self.pm_unread = {}, {}    # friend name -> thread / unread count
        self.sel_friend = None
        cfg = load_cfg()
        self.body = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.build_nav()
        self.build_login(cfg)
        self.build_start(cfg)
        self.build_friends()
        self.build_logs()
        self.build_room()
        self.pages = {"login": self.pg_login, "start": self.pg_start, "friends": self.pg_friends,
                      "logs": self.pg_logs, "room": self.pg_room}
        self.show_page("login")
        self.after(1000, self.refresh)
        self.after(60, self.show_main)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        if invite:
            r = parse_invite(invite)
            if r:
                self.pending_enter = r  # (code, pwd): joined automatically after login
                self.err = "Invite loaded - log in to join the room."

    def q_put(self, s):
        self.q.put(s)

    # ------------------------------------------------------------ small helpers
    def cap(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=(FONT, 12), text_color=MUTED, anchor="w").pack(
            fill="x", padx=2, pady=(12, 3))

    def entry(self, parent, ph="", show=None):
        e = ctk.CTkEntry(parent, placeholder_text=ph, height=40, font=(FONT, 14), fg_color=CARD2,
                         border_color=LINE, text_color=TXT, show=show)
        fix_clipboard(e)
        return e

    def btn(self, parent, text, cmd, color=ACC, hover=ACC_H, h=40, **kw):
        return ctk.CTkButton(parent, text=text, command=cmd, height=h, fg_color=color, hover_color=hover,
                             font=(FONT, 13, "bold"), corner_radius=10, **kw)

    def flash(self, b, text):
        if not hasattr(b, "orig"):
            b.orig = b.cget("text")
        b.configure(text=text)

        def back():
            try:
                b.configure(text=b.orig)
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
        if self.card_logo:
            ctk.CTkLabel(row, image=self.card_logo, text="").pack(side="left")
        name = ctk.CTkFrame(row, fg_color="transparent")
        name.pack(side="left", padx=(10, 0))
        ctk.CTkLabel(name, text="V LAN", font=(FONT, 16, "bold"), text_color=TXT).pack(side="left")
        ctk.CTkLabel(name, text="42", font=(FONT, 16, "bold"), text_color=ACC).pack(side="left", padx=(5, 0))
        ctk.CTkLabel(row, text=title, font=(FONT, 13), text_color=MUTED).pack(side="right")
        return h

    # ------------------------------------------------------------ top navigation
    def build_nav(self):
        self.nav = ctk.CTkFrame(self, fg_color=CARD, corner_radius=0, height=54)
        self.nav.pack(fill="x", side="top")
        self.nav.pack_propagate(False)
        row = ctk.CTkFrame(self.nav, fg_color="transparent")
        row.pack(fill="both", expand=True, padx=16, pady=9)
        if self.nav_logo:
            ctk.CTkLabel(row, image=self.nav_logo, text="").pack(side="left")
        nm = ctk.CTkFrame(row, fg_color="transparent")
        nm.pack(side="left", padx=(9, 24))
        ctk.CTkLabel(nm, text="V LAN", font=(FONT, 16, "bold"), text_color=TXT).pack(side="left")
        ctk.CTkLabel(nm, text="42", font=(FONT, 16, "bold"), text_color=ACC).pack(side="left", padx=(5, 0))

        for key, label in (("start", "Rooms"), ("friends", "Friends & Chat"),
                           ("room", "Room"), ("logs", "Logs")):
            holder = ctk.CTkFrame(row, fg_color="transparent")
            holder.pack(side="left", padx=(0, 6))
            b = ctk.CTkButton(holder, text=label, width=16 + 9 * len(label), height=32, corner_radius=8,
                              font=(FONT, 13, "bold"), fg_color="transparent", hover_color=CARD2,
                              text_color=MUTED, border_width=1, border_color=CARD,
                              command=lambda k=key: self.select_tab(k))
            b.pack(side="left")
            badge = ctk.CTkLabel(holder, text="", font=(FONT, 11, "bold"), text_color="#0b1f12",
                                 fg_color=ACC, corner_radius=9, width=22, height=20)
            badge.pack(side="left", padx=(0, 2))
            self.tabs[key] = (holder, b, badge)
        self.tabs["room"][0].pack_forget()

        self.btn(row, "Logout", self.logout, CARD2, LINE, h=30, width=80).pack(side="right")
        self.lbl_nav_acct = ctk.CTkLabel(row, text="", font=(FONT, 12), text_color=MUTED)
        self.lbl_nav_acct.pack(side="right", padx=(0, 14))

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
                 border_color=(ACC if sel else CARD),
                 text_color=(TXT if sel else MUTED))
        if self.node:
            setw(self.tabs["room"][1], text=f"Room · {self.room_name}"[:24])

    def update_badges(self):
        """One number on the Friends tab: requests waiting plus unread chat lines."""
        n = len(self.friends.get("requests", [])) + sum(self.pm_unread.values())
        badge = self.tabs["friends"][2]
        if n:
            setw(badge, text=str(n) if n < 100 else "99+")
            badge.pack(side="left", padx=(0, 2))
        else:
            setw(badge, text="")
            badge.pack_forget()
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
            ctk.CTkLabel(inner, image=self.logo_img, text="").pack(pady=(0, 4))
        ctk.CTkLabel(inner, text="Play together over a virtual local network.",
                     font=(FONT, 13), text_color=MUTED, justify="center").pack(pady=(6, 14))
        self.cap(inner, "Username")
        self.l_user = self.entry(inner, "Username")
        self.l_user.pack(fill="x")
        if cfg.get("user"):
            self.l_user.insert(0, cfg["user"])
        self.cap(inner, "Password")
        self.l_pwd = self.entry(inner, "Password", show="•")
        self.l_pwd.pack(fill="x")
        self.l_remember = ctk.CTkCheckBox(inner, text="Remember me on this PC", font=(FONT, 13),
                                          fg_color=ACC, hover_color=ACC_H, checkmark_color=BG)
        self.l_remember.pack(anchor="w", pady=(14, 0))
        if cfg.get("token"):
            self.l_remember.select()
        self.mode_btn = ctk.CTkSegmentedButton(
            inner, values=["Login", "Register"], command=lambda v: None, height=38, font=(FONT, 13, "bold"),
            selected_color=ACC, selected_hover_color=ACC_H, unselected_color=CARD2, unselected_hover_color=LINE,
            fg_color=CARD2, text_color=TXT)
        self.mode_btn.pack(fill="x", pady=(16, 4))
        self.mode_btn.set("Login")
        self.b_auth = self.btn(inner, "Sign in", self.do_auth, h=46)
        self.b_auth.pack(fill="x", pady=(14, 0))
        self.lbl_login_err = ctk.CTkLabel(inner, text="", text_color=RED, font=(FONT, 12),
                                          wraplength=420, justify="left")
        self.lbl_login_err.pack(fill="x", pady=(10, 0))
        cr = ctk.CTkLabel(inner, text="coded by Hossein & Erfan", font=(FONT, 11), text_color=MUTED,
                          cursor="hand2")
        cr.pack(pady=(10, 0))
        cr.bind("<Button-1>", lambda e: webbrowser.open(GITHUB_URL))

    def do_auth(self):
        if self.busy:
            return
        u = self.l_user.get().strip()
        p = self.l_pwd.get()
        if not u or not p:
            self.lbl_login_err.configure(text="Enter your username and password.")
            return
        register = self.mode_btn.get() == "Register"
        remember = bool(self.l_remember.get())
        self.busy = True
        self.b_auth.configure(text="Please wait...", state="disabled")

        def work():
            try:
                link = open_link(self.q_put)
                r = link.req("register" if register else "login", u=u, p=p)
                if not r.get("ok"):
                    self.uq.put({"t": "auth_fail", "err": r.get("err") or "Login failed"})
                    link.close()
                    return
                link.user = r["user"]
                link.token = r["token"]
                self.uq.put({"t": "auth_ok", "link": link, "remember": remember,
                             "server": f"{link.host}:{link.port}", "user": r["user"]["name"]})
            except Exception as ex:
                self.uq.put({"t": "auth_fail", "err": f"Cannot reach the {APP_NAME} network: {ex}" + net_hint(ex)})
        threading.Thread(target=work, daemon=True).start()

    def try_token_login(self):
        token = load_cfg().get("token") or ""
        if not token:
            return
        self.busy = True
        self.b_auth.configure(text="Signing in...", state="disabled")
        self.lbl_login_err.configure(text="Signing in with the saved session...", text_color=MUTED)

        def work():
            try:
                link = open_link(self.q_put)
                r = link.req("login_token", token=token)
                if r.get("ok"):
                    link.user = r["user"]
                    link.token = token
                    self.uq.put({"t": "auth_ok", "link": link, "remember": True,
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
            ctk.CTkLabel(side, image=self.logo_img, text="").pack(anchor="w", padx=26, pady=(30, 0))
        title = ctk.CTkFrame(side, fg_color="transparent")
        title.pack(anchor="w", padx=30, pady=(8, 0) if self.logo_img else (44, 0))
        ctk.CTkLabel(title, text="V LAN", font=(FONT, 32, "bold"), text_color=TXT).pack(side="left")
        ctk.CTkLabel(title, text="42", font=(FONT, 32, "bold"), text_color=ACC).pack(side="left", padx=(8, 0))
        ctk.CTkLabel(side, text="Play together over a\nvirtual local network.", font=(FONT, 13),
                     text_color=MUTED, justify="left").pack(anchor="w", padx=30, pady=(8, 22))
        self.lbl_acct = ctk.CTkLabel(side, text="", font=(FONT, 12), text_color=MUTED, anchor="w",
                                     justify="left")
        self.lbl_acct.pack(anchor="w", padx=30, pady=(18, 0))
        cr = ctk.CTkLabel(side, text="coded by Hossein & Erfan\ngithub.com/mhbanaei", font=(FONT, 11),
                          text_color=MUTED, justify="left", cursor="hand2")
        cr.pack(side="bottom", anchor="w", padx=30, pady=(0, 22))
        cr.bind("<Button-1>", lambda e: webbrowser.open(GITHUB_URL))

        main = ctk.CTkFrame(self.pg_start, fg_color=BG, corner_radius=0)
        main.pack(side="left", fill="both", expand=True)
        main.grid_columnconfigure(0, weight=1, uniform="a")
        main.grid_columnconfigure(1, weight=1, uniform="a")
        main.grid_rowconfigure(2, weight=1)

        self.inv_bar = ctk.CTkFrame(main, fg_color=CARD, corner_radius=12, border_width=1, border_color=GOLD)
        self.lbl_invite = ctk.CTkLabel(self.inv_bar, text="", font=(FONT, 13), text_color=TXT, anchor="w")
        self.lbl_invite.pack(side="left", fill="x", expand=True, padx=14, pady=10)
        self.btn(self.inv_bar, "Join", lambda: self.join_by_invite(self.invite), h=32, width=70
                 ).pack(side="right", padx=(6, 10), pady=8)
        self.btn(self.inv_bar, "✕", lambda: self.set_invite(None), CARD2, LINE, h=32, width=40
                 ).pack(side="right", pady=8)

        card_c = ctk.CTkFrame(main, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        card_c.grid(row=1, column=0, sticky="nsew", padx=(16, 8), pady=(16, 8))
        ic = ctk.CTkFrame(card_c, fg_color="transparent")
        ic.pack(fill="both", expand=True, padx=20, pady=16)
        ctk.CTkLabel(ic, text="Create a room", font=(FONT, 15, "bold"), anchor="w").pack(fill="x")
        self.cap(ic, "Room name")
        rr = ctk.CTkFrame(ic, fg_color="transparent")
        rr.pack(fill="x")
        self.h_room = TextLine(rr, "Room name")
        self.h_room.pack(side="left", fill="x", expand=True)
        self.btn(rr, "🎲", self.roll, CARD2, LINE, h=40, width=46).pack(side="left", padx=(8, 0))
        self.cap(ic, "Room password")
        self.h_pwd = self.entry(ic, "Password")
        self.h_pwd.pack(fill="x")
        self.b_create = self.btn(ic, "Create room", self.create_room, h=44)
        self.b_create.pack(fill="x", pady=(16, 0))

        card_j = ctk.CTkFrame(main, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        card_j.grid(row=1, column=1, sticky="nsew", padx=(8, 16), pady=(16, 8))
        ij = ctk.CTkFrame(card_j, fg_color="transparent")
        ij.pack(fill="both", expand=True, padx=20, pady=16)
        ctk.CTkLabel(ij, text="Join a room", font=(FONT, 15, "bold"), anchor="w").pack(fill="x")
        self.cap(ij, "Invite link from your friend")
        gr = ctk.CTkFrame(ij, fg_color="transparent")
        gr.pack(fill="x")
        self.g_link = self.entry(gr, "vlan42://join/...")
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
        ctk.CTkLabel(rh, text="My rooms", font=(FONT, 15, "bold")).pack(side="left")
        self.lbl_rooms_count = ctk.CTkLabel(rh, text="", font=(FONT, 12), text_color=MUTED)
        self.lbl_rooms_count.pack(side="right")
        self.rooms_list = ctk.CTkScrollableFrame(ir, fg_color="transparent")
        self.rooms_list.pack(fill="both", expand=True, pady=(8, 0))
        self.roll()

    # ------------------------------------------------------------ room page
    def build_room(self):
        self.pg_room = ctk.CTkFrame(self.body, fg_color=BG, corner_radius=0)
        left = ctk.CTkFrame(self.pg_room, fg_color="transparent", width=380)
        left.pack(side="left", fill="y", padx=(16, 8), pady=16)
        left.pack_propagate(False)

        hc = ctk.CTkFrame(left, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        hc.pack(fill="x")
        top = ctk.CTkFrame(hc, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 0))
        self.lbl_role = ctk.CTkLabel(top, text="", font=(FONT, 10, "bold"), fg_color=ACC,
                                     corner_radius=6, height=20, padx=8)
        self.lbl_role.pack(side="left")
        self.lbl_status = ctk.CTkLabel(top, text="● Connecting", font=(FONT, 12, "bold"), text_color=YELLOW)
        self.lbl_status.pack(side="right")
        self.lbl_room = ctk.CTkLabel(hc, text="", font=(FONT, 21, "bold"), anchor="w", wraplength=340)
        self.lbl_room.pack(fill="x", padx=16, pady=(8, 0))
        self.lbl_you = ctk.CTkLabel(hc, text="", font=(FONT, 12), text_color=MUTED, anchor="w", justify="left")
        self.lbl_you.pack(fill="x", padx=16, pady=(2, 0))
        self.lbl_stats = ctk.CTkLabel(hc, text="", font=("Consolas", 11), text_color=MUTED, anchor="w")
        self.lbl_stats.pack(fill="x", padx=16, pady=(0, 12))

        pc = ctk.CTkFrame(left, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        pc.pack(fill="both", expand=True, pady=10)
        ph = ctk.CTkFrame(pc, fg_color="transparent")
        ph.pack(fill="x", padx=16, pady=(12, 0))
        ctk.CTkLabel(ph, text="Players", font=(FONT, 14, "bold")).pack(side="left")
        self.lbl_count = ctk.CTkLabel(ph, text="0 online", font=(FONT, 12), text_color=MUTED)
        self.lbl_count.pack(side="right")
        self.plist = ctk.CTkScrollableFrame(pc, fg_color="transparent")
        self.plist.pack(fill="both", expand=True, padx=6, pady=(6, 8))
        self.empty = ctk.CTkLabel(self.plist, text="", font=(FONT, 13), text_color=MUTED, justify="center")

        act = ctk.CTkFrame(left, fg_color="transparent")
        act.pack(fill="x")
        self.row_host = ctk.CTkFrame(act, fg_color="transparent")
        self.b_inv = self.btn(self.row_host, "Copy invite", self.copy_invite, CARD2, LINE, h=36)
        self.b_inv.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.btn(self.row_host, "QR", self.show_qr, CARD2, LINE, h=36, width=56).pack(side="left")
        self.row_mod = ctk.CTkFrame(act, fg_color="transparent")
        self.btn(self.row_mod, "Admin panel", self.show_admin, CARD2, LINE, h=36).pack(
            side="left", expand=True, fill="x", padx=(0, 4))
        self.btn(self.row_mod, "Bans", self.show_bans, CARD2, LINE, h=36).pack(side="left")
        self.row_common = ctk.CTkFrame(act, fg_color="transparent")
        self.row_common.pack(fill="x", pady=(0, 6))
        self.b_ip = self.btn(self.row_common, "Copy my IP", self.copy_ip, CARD2, LINE, h=36)
        self.b_ip.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.btn(self.row_common, "Logs", self.show_logs, CARD2, LINE, h=36, width=70).pack(side="left")
        self.btn(act, "Leave room", self.leave, "#c0392b", "#a93226", h=40).pack(fill="x")

        right = ctk.CTkFrame(self.pg_room, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        right.pack(side="left", fill="both", expand=True, padx=(8, 16), pady=16)
        ctk.CTkLabel(right, text="Chat", font=(FONT, 14, "bold"), anchor="w").pack(fill="x", padx=18, pady=(14, 6))
        self.chatbox = ctk.CTkTextbox(right, font=(FONT, 13), wrap="word", fg_color=BG, text_color=TXT,
                                      corner_radius=10, border_width=1, border_color=LINE)
        self.chatbox.pack(fill="both", expand=True, padx=14)
        for tag, kw in (("me", {"foreground": ACC}), ("them", {"foreground": "#5dade2"}),
                        ("sys", {"foreground": GRAY}), ("body", {"foreground": TXT}),
                        ("rtl", {"justify": "right"}), ("ltr", {"justify": "left"})):
            self.chatbox.tag_config(tag, **kw)
        self.chatbox.configure(state="disabled")
        crow = ctk.CTkFrame(right, fg_color="transparent")
        crow.pack(fill="x", padx=14, pady=12)
        self.chat_in = TextLine(crow, "Type a message...", on_enter=self.send_chat)
        self.chat_in.pack(side="left", fill="x", expand=True)
        self.btn(crow, "Send", self.send_chat, h=40, width=80).pack(side="left", padx=(8, 0))

    def build_logs(self):
        self.pg_logs = ctk.CTkFrame(self.body, fg_color=BG, corner_radius=0)
        self.panel_head(self.pg_logs, "Logs")
        self.logbox = ctk.CTkTextbox(self.pg_logs, font=("Consolas", 11), wrap="word",
                                     fg_color=CARD, text_color=TXT, corner_radius=12)
        fix_clipboard(self.logbox)
        self.logbox.pack(fill="both", expand=True, padx=16, pady=(12, 6))
        self.logbox.configure(state="disabled")
        br = ctk.CTkFrame(self.pg_logs, fg_color="transparent")
        br.pack(fill="x", padx=16, pady=(0, 14))
        for t, f in (("Copy log", self.copy_log), ("Save log", self.save_log),
                     ("Diagnostics", self.run_diag), ("Diag ZIP", self.export_zip)):
            self.btn(br, t, f, CARD2, LINE, h=32).pack(side="left", expand=True, fill="x", padx=3)

    def show_logs(self):
        self.select_tab("logs")

    # ------------------------------------------------------------ pages
    def show_page(self, name):
        for pg in self.pages.values():
            pg.pack_forget()
        if name == "login":
            self.nav.pack_forget()
        else:
            self.nav.pack(fill="x", side="top", before=self.body)
        self.body.pack(fill="both", expand=True)
        if name == "room":
            role = (self.node.room.get("my_role") if self.node else None) or "member"
            badge, color = ROLE_BADGE.get(role, ROLE_BADGE["member"])
            setw(self.lbl_role, text=badge, fg_color=(ACC if role == "owner" else BLUE if role == "admin" else CARD2),
                 text_color=(TXT if role == "member" else "#0b1f12" if role == "owner" else "white"))
            self.lbl_room.configure(text=self.room_name)
            self.row_host.pack_forget()
            self.row_mod.pack_forget()
            self.row_host.pack(fill="x", pady=(0, 6), before=self.row_common)
            if role in ("owner", "admin"):
                self.row_mod.pack(fill="x", pady=(0, 6), before=self.row_common)
        self.pages.get(name, self.pages["login"]).pack(fill="both", expand=True)
        self.page = name
        self.update_tabs()
        if name == "friends":
            self.pm_show()
            self.rebuild_friends()

    # ------------------------------------------------------------ auth events
    def on_auth_ok(self, ev):
        self.link = ev["link"]
        self.link.push_cb = lambda p: self.uq.put(p)
        self.link.down_cb = self.on_link_down
        self.my_name = ev["user"]
        cfg = load_cfg()
        cfg["user"] = ev["user"]
        cfg["token"] = ev["link"].token if ev["remember"] else ""
        save_cfg(cfg)
        self.busy = False
        self.b_auth.configure(text="Sign in", state="normal")
        self.lbl_login_err.configure(text="")
        setw(self.lbl_nav_acct, text=self.my_name)
        setw(self.lbl_acct, text=f"signed in as {self.my_name}\n{APP_NAME} network online")
        self.tab = "start"
        self.show_page("start")
        self.q_put(f"Logged in as {self.my_name} (server {ev['server']})")
        self.refresh_rooms()
        self.refresh_friends()
        if self.pending_enter:
            code, pwd = self.pending_enter
            self.pending_enter = None
            self.join_by_invite({"from": "invite link", "room": "room", "code": code, "pwd": pwd})

    def on_auth_fail(self, ev):
        self.busy = False
        self.b_auth.configure(text="Sign in", state="normal")
        self.lbl_login_err.configure(text=ev.get("err") or "", text_color=RED if ev.get("err") else MUTED)

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
        for w in (self.awin, self.bwin):
            if w:
                try:
                    w.destroy()
                except Exception:
                    pass
        self.awin = self.bwin = None
        self.show_page("login")

    # ------------------------------------------------------------ rooms (landing)
    def refresh_rooms(self):
        if not (self.link and self.link.alive) or self.node:
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
                room.get("my_role"), room.get("limit"))

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
            self.rooms_empty = ctk.CTkLabel(
                self.rooms_list, text="No rooms yet - create one or join with an invite link.",
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
               "mark": ctk.CTkLabel(r, font=(FONT, 20)),
               "name": ctk.CTkLabel(r, font=(FONT, 14, "bold"), anchor="w"),
               "info": ctk.CTkLabel(r, font=(FONT, 11), text_color=MUTED, anchor="w"),
               "host": ctk.CTkLabel(r, font=(FONT, 10), text_color=GOLD, anchor="w")}
        row["mark"].grid(row=0, column=0, rowspan=3, padx=(14, 8), pady=10)
        row["name"].grid(row=0, column=1, sticky="w", pady=(8, 0))
        row["info"].grid(row=1, column=1, sticky="w", pady=(0, 8))
        row["host"].grid(row=2, column=1, sticky="w", pady=(0, 8))
        # the buttons live as long as the room does and always read the freshest dict
        ctk.CTkButton(r, text="✕", width=36, height=32, font=(FONT, 13), corner_radius=8,
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
        setw(row["name"], text=room["name"])
        setw(row["info"], text=f"{len(room.get('members', []))} members · {online} online · "
                              f"you are {role} · limit {room.get('limit')}")
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
        setw(self.lbl_rooms_count, text=f"{len(self.my_rooms)} / {MAX_ROOMS} rooms")
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
        self.h_room.set("room-" + secrets.token_hex(3))
        self.h_pwd.delete(0, "end")
        self.h_pwd.insert(0, secrets.token_urlsafe(8))

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
                self.q_put(f"Create room failed: {r.get('err')}")
        threading.Thread(target=work, daemon=True).start()

    def join_link(self):
        if not self.g_link.get().strip():
            self.paste_link()
        inv = parse_invite(self.g_link.get())
        if not inv:
            self.q_put("This is not a valid invite link. Ask your friend to send it again.")
            self.show_logs()
            return
        self.join_by_invite({"from": "link", "room": "room", "code": inv[0], "pwd": inv[1]})

    def join_by_invite(self, inv):
        if not inv or self.busy or not self.link:
            return
        self.busy = True

        def work():
            r = self.link.req("join_room", code=inv["code"], pwd=inv["pwd"])
            self.busy = False
            if r.get("ok"):
                self.invite_text = make_invite(inv["code"], inv["pwd"])
                self.uq.put({"t": "enter_room", "room": r["room"]})
            else:
                self.q_put(f"Join failed: {r.get('err')}")
        threading.Thread(target=work, daemon=True).start()

    def set_invite(self, inv):
        self.invite = inv
        if inv:
            self.lbl_invite.configure(text=f"{inv['from']} invited you to the room '{inv['room']}'")
            self.inv_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=16, pady=(16, 0))
        else:
            self.inv_bar.grid_forget()

    def remove_room(self, room):
        if not room or not self.link:
            return

        def work():
            r = self.link.req("remove_room", room=room["id"])
            if r.get("ok"):
                self.q_put(f"Removed '{room['name']}' from your rooms")
            else:
                self.q_put(f"Remove failed: {r.get('err')}")
            self.refresh_rooms()
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ room session
    def enter_room(self, room):
        if not room or not self.link:
            return
        if self.busy or self.node:
            self.q_put("Still finishing the previous room - one moment.")
            return
        self.err = ""
        node = VpsNode(self.link, room, self.q_put, self.uq.put)
        node.chat_cb = lambda nm, tx, ts: self.cq.put((nm, tx, ts))
        self.room_name, self.role_key = room["name"], None
        self.invite_text = make_invite(room.get("code", ""), room.get("pwd", ""))
        node.update_state(room)
        self.chat_clear()
        self.node, self.busy, self.entering_rid = node, True, room.get("id")
        self.tab = "room"

        def go():
            try:
                node.start()
            except WintunMissing as ex:
                self.q.put(f"ERROR: {ex}")
                self.need_wintun = True
                self.node = None
                self.tab = "start"
                self.cleanup(node)
            except Exception as ex:
                self.q.put(f"ERROR: {ex}\n{traceback.format_exc()}")
                self.err = f"Could not start: {str(ex)[:160]}"
                self.node = None
                self.tab = "start"
                self.cleanup(node)
            self.busy = False
            self.entering_rid = None
        threading.Thread(target=go, daemon=True).start()

    def leave(self):
        if self.busy or not self.node:
            return
        node, self.node, self.busy = self.node, None, True
        self.role_key = None
        if self.tab in (None, "room"):     # whoever left from Friends or Logs stays there
            self.tab = "start"

        def stop():
            node.stop()
            self.busy = False
            self.q.put("Left the room")
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
                self.q.put(f"ERROR: {ex}")
        threading.Thread(target=work, daemon=True).start()

    def copy_invite(self):
        self.clipboard_clear()
        self.clipboard_append(self.invite_text)
        self.flash(self.b_inv, "Copied ✓")

    def copy_ip(self):
        if self.node:
            self.clipboard_clear()
            self.clipboard_append(self.node.vip)
            self.flash(self.b_ip, "Copied ✓")

    def show_qr(self):
        try:
            import qrcode
        except ImportError:
            self.q_put("QR needs:  pip install qrcode[pil]")
            self.show_logs()
            return
        qr = qrcode.QRCode(box_size=8, border=2)
        qr.add_data(self.invite_text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").get_image().convert("RGB")
        top = ctk.CTkToplevel(self)
        top.configure(fg_color=CARD)
        self.brand(top, "Invite QR")
        self.panel_head(top, "Invite QR")
        photo = ctk.CTkImage(light_image=img, dark_image=img, size=img.size)
        lbl = ctk.CTkLabel(top, image=photo, text="")
        lbl.image = photo
        lbl.pack(padx=24, pady=(24, 8))
        ctk.CTkLabel(top, text="Scan with your phone to copy the invite text,\nthen send it to your friend.",
                     text_color=MUTED).pack()
        self.btn(top, "Copy invite", self.copy_invite, h=36).pack(pady=14)

    # ------------------------------------------------------------ moderation
    def my_role(self):
        return (self.node.room.get("my_role") if self.node else None) or "member"

    def my_perms(self):
        room = self.node.room if self.node else {}
        if self.my_role() == "owner":
            return {"kick": True, "ban": True, "unban": True, "limit": True}
        return room.get("my_perms") or {}

    def kick_user(self, uid):
        if not self.node:
            return
        rid = self.node.rid

        def work():
            r = self.link.req("kick", room=rid, user=uid)
            if not r.get("ok"):
                self.q.put(f"Kick failed: {r.get('err')}")
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
                self.q.put(f"Ban failed: {r.get('err')}")
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ admin panel
    def show_admin(self):
        if self.awin and self.awin.winfo_exists():
            self.awin.deiconify()
            return
        w = self.awin = ctk.CTkToplevel(self)
        w.geometry("560x560")
        w.configure(fg_color=BG)
        self.brand(w, "Admin panel")
        self.panel_head(w, "Roles and permissions")
        self.admin_body = ctk.CTkScrollableFrame(w, fg_color="transparent")
        self.admin_body.pack(fill="both", expand=True, padx=12, pady=12)
        self.rebuild_admin()

    def rebuild_admin(self):
        if not (self.awin and self.awin.winfo_exists()) or not self.node:
            return
        body = self.admin_body
        for c in body.winfo_children():
            c.destroy()
        room = self.node.room
        if self.my_role() == "owner":
            card = ctk.CTkFrame(body, fg_color=CARD, corner_radius=12, border_width=1, border_color=LINE)
            card.pack(fill="x")
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=12)
            ctk.CTkLabel(row, text="Member limit:", font=(FONT, 13)).pack(side="left")
            lim = ctk.CTkEntry(row, width=70, height=32, fg_color=CARD2, border_color=LINE)
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
                        self.q.put(f"Limit failed: {r.get('err')}")
                threading.Thread(target=work, daemon=True).start()
            self.btn(row, "Set", set_limit, CARD2, LINE, h=32, width=60).pack(side="left")
            self.cap(body, "Members - roles and admin permissions (owner only)")
        else:
            self.cap(body, "Admin permissions you were given:")
            pl = ", ".join(PERM_LABELS[k] for k, on in self.my_perms().items() if on) or "none"
            ctk.CTkLabel(body, text=pl, font=(FONT, 13), text_color=TXT, anchor="w").pack(fill="x", padx=4)
        for m in room.get("members", []):
            if m["id"] == self.link.user["id"]:
                continue
            card = ctk.CTkFrame(body, fg_color=CARD, corner_radius=12, border_width=1, border_color=LINE)
            card.pack(fill="x", pady=4)
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=14, pady=(10, 0))
            badge, color = ROLE_BADGE.get(m["role"], ROLE_BADGE["member"])
            ctk.CTkLabel(top, text=m["name"], font=(FONT, 14, "bold"), anchor="w").pack(side="left")
            ctk.CTkLabel(top, text=badge, font=(FONT, 11, "bold"), text_color=color).pack(side="left", padx=8)
            if self.my_role() == "owner":
                is_admin = m["role"] == "admin"

                def toggle(q=m):
                    if q["role"] == "admin":
                        self.req_admin(q["id"], False, {})
                    else:
                        perms = {k: q.get("perms", {}).get(k, False) for k in PERM_LABELS}
                        self.req_admin(q["id"], True, perms)
                self.btn(top, "Remove admin" if is_admin else "Make admin", toggle, CARD2, LINE,
                         h=30, width=110).pack(side="right")
            if m["role"] == "admin" and self.my_role() == "owner":
                prow = ctk.CTkFrame(card, fg_color="transparent")
                prow.pack(fill="x", padx=14, pady=(4, 10))
                boxes = {}
                for k, label in PERM_LABELS.items():
                    cb = ctk.CTkCheckBox(prow, text=label, font=(FONT, 12), fg_color=ACC,
                                         hover_color=ACC_H, checkmark_color=BG)
                    if m.get("perms", {}).get(k):
                        cb.select()
                    cb.pack(side="left", padx=(0, 12))
                    boxes[k] = cb

                def apply_perms(q=m, bx=boxes):
                    self.req_admin(q["id"], True, {k: bool(bx[k].get()) for k in PERM_LABELS})
                self.btn(prow, "Apply", apply_perms, CARD2, LINE, h=28, width=70).pack(side="right")

    def req_admin(self, uid, admin, perms):
        rid = self.node.rid if self.node else None
        if rid is None:
            return

        def work():
            r = self.link.req("set_admin", room=rid, user=uid, admin=admin, perms=perms)
            if not r.get("ok"):
                self.q.put(f"Admin update failed: {r.get('err')}")
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ ban panel
    def show_bans(self):
        if self.bwin and self.bwin.winfo_exists():
            self.bwin.deiconify()
            return
        w = self.bwin = ctk.CTkToplevel(self)
        w.geometry("520x400")
        w.configure(fg_color=BG)
        self.brand(w, "Bans")
        self.panel_head(w, "Banned from this room")
        self.ban_body = ctk.CTkScrollableFrame(w, fg_color="transparent")
        self.ban_body.pack(fill="both", expand=True, padx=12, pady=12)
        rid = self.node.rid if self.node else None
        if rid is None:
            return

        def work():
            r = self.link.req("ban_list", room=rid)
            if r.get("ok"):
                self.uq.put({"t": "ban_list", "bans": r["bans"]})
            else:
                self.q.put(f"Ban list failed: {r.get('err')}")
        threading.Thread(target=work, daemon=True).start()

    def rebuild_bans(self, bans):
        if not (self.bwin and self.bwin.winfo_exists()):
            return
        body = self.ban_body
        for c in body.winfo_children():
            c.destroy()
        if not bans:
            ctk.CTkLabel(body, text="No banned users in this room.", font=(FONT, 13),
                         text_color=MUTED).pack(pady=30)
            return
        for b in bans:
            r = ctk.CTkFrame(body, fg_color=CARD, corner_radius=10, border_width=1, border_color=LINE)
            r.pack(fill="x", pady=4)
            ctk.CTkLabel(r, text=b["name"], font=(FONT, 14, "bold"), anchor="w").pack(side="left", padx=14)
            ctk.CTkLabel(r, text=f"by {b['by']}  ·  {b['reason'] or 'no reason'}",
                         font=(FONT, 11), text_color=MUTED, anchor="w").pack(side="left", padx=6)

            def unban(q=b["id"]):

                def work():
                    rr = self.link.req("unban", room=self.node.rid, user=q)
                    if rr.get("ok"):
                        self.q.put(f"User {q} unbanned")
                        r2 = self.link.req("ban_list", room=self.node.rid)
                        if r2.get("ok"):
                            self.uq.put({"t": "ban_list", "bans": r2["bans"]})
                    else:
                        self.q.put(f"Unban failed: {rr.get('err')}")
                threading.Thread(target=work, daemon=True).start()
            can = self.my_role() == "owner" or self.my_perms().get("unban")
            if can:
                self.btn(r, "Unban", unban, CARD2, LINE, h=30, width=80).pack(side="right", padx=12, pady=8)

    # ------------------------------------------------------------ friends
    def build_friends(self):
        self.pg_friends = ctk.CTkFrame(self.body, fg_color=BG, corner_radius=0)
        self.panel_head(self.pg_friends, "Friends & Chat")
        cols = ctk.CTkFrame(self.pg_friends, fg_color="transparent")
        cols.pack(fill="both", expand=True, padx=16, pady=(10, 14))
        cols.grid_columnconfigure(0, minsize=330)
        cols.grid_columnconfigure(1, weight=1)
        cols.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(cols, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        li = ctk.CTkFrame(left, fg_color="transparent")
        li.pack(fill="both", expand=True, padx=12, pady=12)
        sr = ctk.CTkFrame(li, fg_color="transparent")
        sr.pack(fill="x")
        self.fr_search = self.entry(sr, "Search username...")
        self.fr_search.pack(side="left", fill="x", expand=True)
        self.fr_search.bind("<Return>", lambda e: self.do_search())
        self.btn(sr, "Search", self.do_search, CARD2, LINE, h=40, width=76).pack(side="left", padx=(8, 0))
        self.fr_results = ctk.CTkFrame(li, fg_color="transparent")
        self.fr_results.pack(fill="x", pady=(4, 0))
        self.fr_body = ctk.CTkScrollableFrame(li, fg_color="transparent")
        self.fr_body.pack(fill="both", expand=True, pady=(4, 0))

        right = ctk.CTkFrame(cols, fg_color=CARD, corner_radius=14, border_width=1, border_color=LINE)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        hh = ctk.CTkFrame(right, fg_color="transparent")
        hh.pack(fill="x", padx=16, pady=(12, 4))
        self.pm_title = ctk.CTkLabel(hh, text="No chat open", font=(FONT, 15, "bold"))
        self.pm_title.pack(side="left")
        self.pm_state = ctk.CTkLabel(hh, text="", font=(FONT, 12), text_color=MUTED)
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
        crow = ctk.CTkFrame(right, fg_color="transparent")
        crow.pack(fill="x", padx=14, pady=12)
        self.pm_in = TextLine(crow, "Type a message...", on_enter=self.send_pm)
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
            ctk.CTkLabel(self.fr_results, text="No users found.", font=(FONT, 12),
                         text_color=MUTED).pack(pady=8)
            return
        for u in users[:8]:
            r = ctk.CTkFrame(self.fr_results, fg_color=CARD, corner_radius=8)
            r.pack(fill="x", pady=2)
            ctk.CTkLabel(r, text=u["name"], font=(FONT, 13), anchor="w").pack(side="left", padx=12, pady=6)

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
                self.q_put(f"{cmd.replace('_', ' ')} failed: {r.get('err')}")
                return
            self.friend_apply(r)
            if cmd == "add_friend" and r.get("accepted"):
                self.q_put(f"{name} is now your friend")
        threading.Thread(target=work, daemon=True).start()

    def rebuild_friends(self):
        if not (self.fr_body and self.fr_body.winfo_exists()):
            return
        for c in self.fr_body.winfo_children():
            c.destroy()
        fdata = self.friends
        if fdata.get("requests"):
            self.cap(self.fr_body, f"Friend requests ({len(fdata['requests'])})")
            for rq in fdata["requests"]:
                r = ctk.CTkFrame(self.fr_body, fg_color=CARD, corner_radius=10,
                                 border_width=1, border_color=YELLOW)
                r.pack(fill="x", pady=3)
                ctk.CTkLabel(r, text=rq["name"], font=(FONT, 13, "bold"), anchor="w").pack(side="left", padx=12)
                self.btn(r, "✕", lambda q=rq["name"]: self.friend_req(q, "friend_resp", accept=False),
                         CARD2, LINE, h=28, width=40).pack(side="right", padx=4)
                self.btn(r, "Accept", lambda q=rq["name"]: self.friend_req(q, "friend_resp", accept=True),
                         h=28, width=80).pack(side="right", padx=4)
        self.cap(self.fr_body, f"Friends ({len(fdata.get('friends', []))})")
        if not fdata.get("friends"):
            ctk.CTkLabel(self.fr_body, text="No friends yet - search a username above.", font=(FONT, 12),
                         text_color=MUTED).pack(pady=8)
        for f in fdata.get("friends", []):
            picked = f["name"] == self.sel_friend
            r = ctk.CTkFrame(self.fr_body, fg_color=CARD, corner_radius=10,
                             border_width=1, border_color=(ACC if picked else LINE))
            r.pack(fill="x", pady=3)
            ctk.CTkLabel(r, text="●", text_color=(GREEN if f.get("online") else GRAY),
                         font=(FONT, 12)).pack(side="left", padx=(12, 4))
            ctk.CTkLabel(r, text=f["name"] + ("  (online)" if f.get("online") else ""),
                         font=(FONT, 13), anchor="w").pack(side="left", padx=2)
            self.btn(r, "✕", lambda q=f["name"]: self.friend_req(q, "remove_friend"), CARD2, LINE,
                     h=28, width=40).pack(side="right", padx=4)
            if self.node:
                self.btn(r, "Invite", lambda q=f["name"]: self.invite_friend(q), CARD2, LINE,
                         h=28, width=70).pack(side="right", padx=4)
            unread = self.pm_unread.get(f["name"], 0)
            self.btn(r, f"Chat ({unread})" if unread else "Chat",
                     lambda q=f["name"]: self.open_pm(q), CARD2, LINE, h=28, width=76
                     ).pack(side="right", padx=4)
        self.update_badges()

    # ------------------------------------------------------------ friend to friend chat
    def open_pm(self, name):
        self.sel_friend = name
        self.pm_unread.pop(name, None)
        self.rebuild_friends()
        self.pm_show()

    def pm_show(self):
        if not (self.pm_box and self.pm_box.winfo_exists()):
            return
        name = self.sel_friend
        self.pm_box.configure(state="normal")
        self.pm_box.delete("1.0", "end")
        if not name:
            setw(self.pm_title, text="No chat open")
            setw(self.pm_state, text="pick a friend on the left")
            self.pm_box.configure(state="disabled")
            return
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
            return
        if not mine:            # nobody is looking at it: count it on the tab and on the row
            self.pm_unread[name] = self.pm_unread.get(name, 0) + 1
            self.rebuild_friends()
            self.beep()

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

    def beep(self):
        if winsound:
            try:
                winsound.MessageBeep(-1)
            except Exception:
                pass

    def invite_friend(self, name):
        if not self.node:
            return

        def work():
            r = self.link.req("invite", user=name, room=self.node.rid)
            if r.get("ok"):
                self.q_put(f"Invite sent to {name}")
            else:
                self.q.put(f"Invite failed: {r.get('err')}")
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ chat
    def chat_clear(self):
        self.chatbox.configure(state="normal")
        self.chatbox.delete("1.0", "end")
        self.chatbox.configure(state="disabled")

    def chat_add(self, who, text, tag, ts=None, box=None):
        box = box or self.chatbox
        stamp = time.strftime("%H:%M", time.localtime(ts or time.time()))
        rtl = has_rtl(text)
        j = "rtl" if rtl else "ltr"
        box.configure(state="normal")
        box.insert("end", f"{who}  {stamp}\n", (tag, j))
        box.insert("end", (f"\u200f{text}\u200f" if rtl else text) + "\n\n", ("body", j))
        box.see("end")
        box.configure(state="disabled")

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
        else:
            self.chat_add("system", "Could not send - check the connection to the server", "sys")

    # ------------------------------------------------------------ logs
    def copy_log(self):
        self.clipboard_clear()
        self.clipboard_append(self.logbox.get("1.0", "end"))
        self.q.put("Log copied to clipboard")

    def save_log(self):
        p = os.path.join(APP_DIR, "vlan42_log.txt")
        open(p, "w", encoding="utf-8").write(self.logbox.get("1.0", "end"))
        self.q.put(f"Log saved: {p}")

    def run_diag(self):
        self.q.put(self.node.diag() if self.node else "Not connected")

    def export_zip(self):
        log_text = self.logbox.get("1.0", "end")
        diag = self.node.diag() if self.node else "Not connected"
        self.q.put("Collecting diagnostics (a few seconds)...")

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
                self.q.put(f"Diagnostics ZIP saved: {path}")
                subprocess.Popen(f'explorer /select,"{path}"')
            except Exception:
                self.q.put(f"ZIP export failed:\n{traceback.format_exc()}")
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ periodic UI update
    def write_log_file(self, text):
        if self.logf is None:
            try:
                p = os.path.join(APP_DIR, "vlan42.log")
                mode = "w" if os.path.exists(p) and os.path.getsize(p) > 1_000_000 else "a"
                self.logf = open(p, mode, encoding="utf-8", buffering=1)
            except OSError:
                self.logf = False
        if self.logf:
            try:
                self.logf.write(text)
            except OSError:
                pass

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
                self.q.put("UI error (the app keeps running):\n" + traceback.format_exc())
        finally:
            if not self.closing:
                try:
                    idle = self.state() == "iconic"
                except Exception:
                    idle = False
                self.after(2500 if idle else 1000, self.refresh)

    def report_callback_exception(self, exc, val, tb):
        self.q.put("UI callback error:\n" + "".join(traceback.format_exception(exc, val, tb)))

    def tick(self):
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
                lines.append(time.strftime("%H:%M:%S ") + self.q.get_nowait() + "\n")
            except queue.Empty:
                break
        if lines:
            text = "".join(lines)
            self.last_log = lines[-1][9:].split("\n", 1)[0][:90]
            self.logbox.configure(state="normal")
            self.logbox.insert("end", text)
            n = int(self.logbox.index("end-1c").split(".")[0])
            if n > 1500:
                self.logbox.delete("1.0", f"{n - 1200}.0")
            self.logbox.see("end")
            self.logbox.configure(state="disabled")
            self.write_log_file(text)
        while not self.cq.empty():
            nm, tx, ts = self.cq.get()
            self.chat_add(nm, tx, "them", ts)
            self.beep()
        while not self.uq.empty():
            self.on_event(self.uq.get_nowait())
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
                self.update_room_rows()
                if self.awin and self.awin.winfo_exists():
                    self.rebuild_admin()
            for i, r in enumerate(self.my_rooms):
                # a member who never entered the room must still see the roster change now
                if r.get("id") == room["id"]:
                    self.my_rooms[i] = room
                    self.on_my_rooms(self.my_rooms)
                    break
        elif t == "chat":
            if self.node and ev.get("room") == self.node.rid \
                    and ev.get("from") != self.my_name:
                self.cq.put((ev.get("from", "?"), ev.get("text", ""), ev.get("ts")))
        elif t == "kicked":
            if self.node and ev.get("room") == self.node.rid:
                self.q_put(f"You were kicked from the room by {ev.get('by')}")
                self.chat_add("system", f"You were kicked by {ev.get('by')}.", "sys")
                self.tab = "start"
                self.leave()
                self.refresh_rooms()
        elif t == "banned":
            if self.node and ev.get("room") == self.node.rid:
                self.q_put(f"You were banned from the room by {ev.get('by')} "
                           f"({ev.get('reason') or 'no reason'})")
                self.chat_add("system", f"You were banned by {ev.get('by')} ({ev.get('reason') or 'no reason'}).", "sys")
                self.tab = "start"
                self.leave()
                self.refresh_rooms()
        elif t == "member_offline":
            why = ev.get("reason") or "timeout"
            self.q_put(f"{ev.get('name', '?')} went offline: {why}")
        elif t == "peer_timeout":
            why = ev.get("reason") or "timeout"
            self.chat_add("system", f"{ev.get('name', '?')} - {why}", "sys")
        elif t == "friend_upd":
            self.friends = {"friends": ev.get("friends", []), "requests": ev.get("requests", [])}
            self.rebuild_friends()
            if self.page == "friends":
                self.pm_show()
        elif t == "friend_req":
            self.q_put(f"{ev.get('from')} sent you a friend request")
            self.refresh_friends()
        elif t == "pm":
            self.pm_add(ev.get("from", "?"), ev.get("from", "?"), ev.get("text", ""), ev.get("ts"))
        elif t == "pm_own":
            self.pm_add(ev["to"], "You", ev["text"], ev.get("ts"), mine=True)
            if not ev.get("delivered"):
                self.q_put(f"{ev['to']} is not online - your message was not delivered")
        elif t == "pm_err":
            self.q_put(f"Chat failed: {ev.get('err')}")
        elif t == "search":
            self.show_search_results(ev.get("users", []))
        elif t == "ban_list":
            self.rebuild_bans(ev.get("bans", []))
        elif t == "invite":
            self.set_invite(ev)
            self.q_put(f"{ev.get('from')} invited you to the room '{ev.get('room')}'")
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
            self.q_put(f"Connection to the server lost: {ev.get('why', '')}")
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
            setw(row["enter"], text="Entering…" if rid == self.entering_rid else "Enter")
        if self.node:
            setw(self.lbl_acct, text=f"entering '{self.room_name}' - preparing the virtual adapter...",
                 text_color=YELLOW)
        elif self.err:
            setw(self.lbl_acct, text=self.err, text_color=RED)
        else:
            setw(self.lbl_acct, text=f"signed in as {self.my_name}\n{APP_NAME} network online",
                 text_color=MUTED)
        for b, t, in ((self.b_create, "Create room"), (self.b_join, "Join room")):
            setw(b, text=t, state="normal")

    # ------------------------------------------------------------ room UI
    def update_room_rows(self):
        """(Re)build the player rows when the roster or my permissions change."""
        if not self.node:
            return
        room = self.node.room
        key = (tuple(sorted(m["id"] for m in room.get("members", []))),
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
        for m in room.get("members", []):
            pid = m["id"]
            if pid == self.link.user["id"]:
                continue
            r = ctk.CTkFrame(self.plist, fg_color=CARD2, corner_radius=10)
            r.pack(fill="x", pady=3, padx=4)
            r.grid_columnconfigure(1, weight=1)
            role = m.get("role", "member")
            badge, color = ROLE_BADGE.get(role, ROLE_BADGE["member"])
            ctk.CTkLabel(r, text=badge.split(" ", 1)[0], font=(FONT, 18), text_color=color
                         ).grid(row=0, column=0, rowspan=2, padx=(12, 8), pady=8)
            name = ctk.CTkLabel(r, text=m.get("name", "?"), font=(FONT, 14, "bold"), anchor="w")
            name.grid(row=0, column=1, sticky="w", pady=(8, 0))
            info = ctk.CTkLabel(r, text=m.get("vip", ""), font=(FONT, 11), text_color=MUTED, anchor="w")
            info.grid(row=1, column=1, sticky="w", pady=(0, 8))
            ping = ctk.CTkLabel(r, text="...", font=(FONT, 15, "bold"))
            ping.grid(row=0, column=2, rowspan=2, padx=(8, 6))
            btns = ctk.CTkFrame(r, fg_color="transparent")
            btns.grid(row=0, column=3, rowspan=2, padx=(0, 12))
            cp = ctk.CTkButton(btns, text="Copy IP", width=64, height=26, font=(FONT, 11), corner_radius=8,
                               fg_color=CARD, hover_color=LINE, command=lambda q=pid: self.copy_peer_ip(q))
            cp.pack(side="left", padx=2)
            can_mod = role == "member" and (self.my_role() == "owner" or perms.get("kick"))
            kb = ctk.CTkButton(btns, text="Kick", width=54, height=26, font=(FONT, 11), corner_radius=8,
                               fg_color=CARD, hover_color=LINE, text_color=YELLOW,
                               command=lambda q=pid: self.kick_user(q))
            kb.pack(side="left", padx=2)
            if not can_mod:
                kb.pack_forget()
            bb = ctk.CTkButton(btns, text="Ban", width=54, height=26, font=(FONT, 11), corner_radius=8,
                               fg_color=CARD, hover_color=LINE, text_color=RED,
                               command=lambda q=pid: self.ban_user(q))
            bb.pack(side="left", padx=2)
            if not (role == "member" and (self.my_role() == "owner" or perms.get("ban"))):
                bb.pack_forget()
            self.rows[pid] = (r, name, info, ping)

    def copy_peer_ip(self, pid):
        p = self.node.peers.get(pid) if self.node else None
        if p and p.get("vip"):
            self.clipboard_clear()
            self.clipboard_append(p["vip"])

    def update_room(self, n):
        setw(self.lbl_you, text=f"{self.my_name}   ·   {n.vip}   ·   role: "
                                f"{ROLE_BADGE.get(self.my_role(), ROLE_BADGE['member'])[0]}")
        self.update_room_rows()
        online = 0
        for pid, row in self.rows.items():
            p = n.peers.get(pid)
            if not p:
                continue
            r, name, info, ping = row
            setw(name, text=p.get("name", "?"))
            if p.get("timed_out"):
                setw(ping, text="timeout", text_color=RED)
                setw(info, text=f"{p.get('vip', '')}  ·  no answer (timed out)")
            elif not p.get("online"):
                setw(ping, text="offline", text_color=GRAY)
                setw(info, text=f"{p.get('vip', '')}  ·  offline")
            else:
                rtt = p.get("rtt")
                if rtt is None:
                    setw(ping, text="...", text_color=YELLOW)
                else:
                    setw(ping, text=f"{rtt:.0f} ms",
                         text_color=GREEN if rtt < 60 else YELLOW if rtt < 120 else RED)
                setw(info, text=f"{p.get('vip', '')}  ·  via VPS")
            if p.get("online") and not p.get("timed_out"):
                online += 1
        peers_online = sum(1 for p in n.peers.values() if p.get("online"))
        if peers_online:
            setw(self.lbl_status, text="● Online", text_color=GREEN)
        else:
            setw(self.lbl_status, text="● Waiting", text_color=YELLOW)
        setw(self.lbl_count, text=f"{peers_online} online")
        now = time.time()
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
            setw(self.empty, text="Waiting for your friends...\nSend them the invite link.")
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
            if self.logf:
                self.logf.close()
            if self.hangf:
                self.hangf.close()
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
