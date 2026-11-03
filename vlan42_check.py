#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""V.Lan.42 connection self-check.

    python vlan42_check.py                     # uses vlan42_servers.txt
    python vlan42_check.py 203.0.113.10        # one address
    python vlan42_check.py 203.0.113.10:4242

TCP 4242 carries logins, rooms and chat. UDP 4242 carries the game traffic.
Both must be open on the VPS: the firewall inside Windows/Linux *and* the
security group / firewall panel of the hosting company.
"""
import json
import os
import socket
import sys
import time

APP_NAME = "V.Lan.42"
PORT = 4242
HERE = os.path.dirname(os.path.abspath(__file__))


def targets():
    """Addresses to test: command line wins, then vlan42_servers.txt next to this file."""
    out = []
    for arg in sys.argv[1:]:
        arg = arg.strip()
        if arg.startswith(f"{APP_NAME.lower()}://join/"):
            continue
        host, sep, port = arg.rpartition(":")
        out.append((host, int(port)) if sep and port.isdigit() else (arg, PORT))
    if out:
        return out
    for name in ("vlan42_servers.txt",):
        try:
            with open(os.path.join(HERE, name), "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and line != "0.0.0.0":
                        host, sep, port = line.rpartition(":")
                        out.append((host, int(port)) if sep and port.isdigit() else (line, PORT))
        except OSError:
            pass
    return out


def check_tcp(host, port):
    """The server greets every new control connection with a plain 'hello' line."""
    try:
        s = socket.create_connection((host, port), timeout=6)
    except ConnectionRefusedError:
        return False, "refused - nothing is listening (server not running, or the port is closed)"
    except socket.timeout:
        return False, "timed out - the packets are being dropped by a firewall"
    except OSError as ex:
        return False, f"unreachable ({ex})"
    try:
        s.settimeout(6)
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        hello = json.loads(buf.split(b"\n", 1)[0].decode())
    except Exception as ex:
        s.close()
        if not buf:
            return False, ("connected, then closed without a word - a port forward with no live "
                           "server behind it, or a second server stole the port")
        return False, f"connected but did not greet us ({ex})"
    s.close()
    if hello.get("t") != "hello":
        return False, f"connected but this is not a {APP_NAME} server: {hello}"
    return True, "ok - the server greets us"


def check_udp(host, port):
    """V42PING needs no login: an answer proves the relay port is really open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    tries = []
    try:
        for _ in range(3):
            try:
                s.sendto(b"V42PING", (host, port))
            except OSError as ex:
                return False, f"our own firewall stopped the send ({ex})"
            try:
                data, _ = s.recvfrom(2048)
            except socket.timeout:
                tries.append("silence")
                continue
            except ConnectionResetError:
                # the host itself told us nobody is listening on that UDP port
                tries.append("port unreachable")
                continue
            if data == b"V42PONG":
                return True, f"ok - relay answered ({len(tries)} failed attempt(s) before)"
            tries.append(repr(data[:8]))
        if "silence" not in tries and tries:
            return False, (f"{', '.join(tries)} - nothing is listening on UDP {port} "
                           f"(the server is not running, or its UDP port was taken by a second instance)")
        return False, (f"no V42PONG ({', '.join(tries)}) - the packets never reached a "
                       f"relay: open UDP {port} inbound on the VPS")
    finally:
        s.close()


def main():
    print(f"{APP_NAME} connection self-check - {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("coded by Hossein & Erfan - https://github.com/mhbanaei\n")
    todo = targets()
    if not todo:
        print(f"No address to test. Put one IP per line into vlan42_servers.txt next to this")
        print(f"file, or pass it on the command line:  python vlan42_check.py <ip>")
        return 2
    bad = 0
    for host, port in todo:
        print(f"=== {host}:{port} ===")
        tcp_ok, tcp_why = check_tcp(host, port)
        udp_ok, udp_why = check_udp(host, port)
        print(f"  TCP {port}  {'OK  ' if tcp_ok else 'FAIL'} {tcp_why}")
        print(f"  UDP {port}  {'OK  ' if udp_ok else 'FAIL'} {udp_why}")
        if not (tcp_ok and udp_ok):
            bad += 1
            if not udp_ok and tcp_ok:
                print(f"  -> The server is up but the relay port is blocked. Open UDP {port}")
                print(f"     inbound on the VPS (Windows firewall / hosting panel), then try again.")
            if not tcp_ok:
                print(f"  -> Start the server on the VPS (start_server.bat) and keep its window open,")
                print(f"     and make sure TCP {port} and UDP {port} are open inbound.")
        else:
            print(f"  -> Both channels answer: joining a room should work from this machine.")
        print()
    print("RESULT:", "all good" if not bad else f"{bad} address(es) not usable")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
