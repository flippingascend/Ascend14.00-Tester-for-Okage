#!/usr/bin/env python3
"""
send_elf.py - send a payload to the mast1c0re PS2 network ELF loader.

Wire protocol expected by the loader (src/main.cpp):
    uint32 LE   0x0000EA6E   magic
    uint64 LE   filesize     size of the ELF that follows (ELF size only)
    bytes       the ELF itself

Listening port is LISTEN_PORT in src/main.cpp, i.e. 9045 by default.

There is no acknowledgement: the loader executes the payload as soon as the
last byte lands, so "sent" means "delivered", not "ran".

Usage:
    python send_elf.py scan
    python send_elf.py 192.168.0.117 payload.elf
    python send_elf.py 192.168.0.117 payload.elf --port 9045
"""
import argparse
import os
import socket
import struct
import sys
import threading

MAGIC = 0x0000EA6E
ELF_MAGIC = b"\x7fELF"
DEFAULT_PORT = 9045

# The loader reads 4096 at a time and stops on ANY short read, so a writer that
# dribbles 4096-byte chunks can starve it mid-transfer and get rejected with
# "different size than expected". Writing in large blocks keeps the console's
# receive buffer full; only the final short read is meant to end the loop.
CHUNK = 65536


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def scan(port, timeout):
    ip = local_ip()
    prefix = ".".join(ip.split(".")[:3])
    print(f"[*] Local IP: {ip}")
    print(f"[*] Scanning {prefix}.1-254 on TCP {port} (loader only listens while Okage is running)...")
    found = []
    lock = threading.Lock()

    def check(n):
        host = f"{prefix}.{n}"
        try:
            c = socket.socket()
            c.settimeout(timeout)
            if c.connect_ex((host, port)) == 0:
                with lock:
                    found.append(host)
                print(f"[+] LOADER FOUND: {host}:{port}")
            c.close()
        except OSError:
            pass

    threads = [threading.Thread(target=check, args=(n,), daemon=True) for n in range(1, 255)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout + 0.5)
    return sorted(found, key=lambda h: int(h.split(".")[-1]))


def recv_exact(sock, count):
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def send(ip, port, path, timeout):
    if not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        return 1
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(4)
    if head != ELF_MAGIC:
        print(f"[!] Not a MIPS ELF (magic is {head!r}, expected {ELF_MAGIC!r})")
        print("    Build payloads with the mast1c0re samples, e.g.")
        print("    cd ~/mast1c0re/samples/ps-blank && ./build.sh")
        return 1
    if size == 0:
        print("[!] File is empty")
        return 1

    print(f"[*] Connecting to {ip}:{port} ...")
    try:
        sock = socket.create_connection((ip, port), timeout)
    except OSError as exc:
        print(f"[!] Connect failed: {exc}")
        print("    - Is the Okage exploit save loaded and restored on the console?")
        print("      (the loader only listens after the game 'crashes' back to the home screen)")
        print("    - Same subnet? PC and console on the same LAN, no client isolation")
        print("    - Windows Firewall blocking Python outbound? allow it")
        return 1

    sock.settimeout(timeout)
    with sock, open(path, "rb") as f:
        sock.sendall(struct.pack("<I", MAGIC))
        sock.sendall(struct.pack("<Q", size))
        sent = 0
        while sent < size:
            data = f.read(CHUNK)
            if not data:
                break
            sock.sendall(data)
            sent += len(data)
            pct = sent * 100 // size
            sys.stdout.write(f"\r[*] {sent}/{size} bytes ({pct}%)")
            sys.stdout.flush()
    print(f"\r[*] {sent}/{size} bytes (100%)")
    print("[+] Delivered. The console runs it now - there is no reply to wait for.")
    return 0


def main():
    p = argparse.ArgumentParser(description="Send a payload to the mast1c0re PS2 network ELF loader.")
    p.add_argument("target", nargs="?", help="console IP address")
    p.add_argument("file", nargs="?", help="payload .elf to send")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"loader port (default {DEFAULT_PORT})")
    p.add_argument("--timeout", type=float, default=30.0, help="socket timeout in seconds")
    args = p.parse_args()

    if args.target is None or args.target == "scan":
        found = scan(args.port, min(args.timeout, 2.0))
        if found:
            print(f"[+] Run: python send_elf.py {found[0]} payload.elf")
        else:
            print("[!] Loader not found. Load and restore the Okage exploit save first.")
        return 0 if found else 1

    if args.file is None:
        p.error("a payload file is required when an IP is given")
    return send(args.target, args.port, args.file, args.timeout)


if __name__ == "__main__":
    sys.exit(main())