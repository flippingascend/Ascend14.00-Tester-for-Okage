#!/usr/bin/env python3
"""
psn_block_dns.py - a small forward-only DNS server that blocks PlayStation / PSN
hostnames while leaving normal internet access untouched.

- stdlib only, no pip install needed
- listens on UDP + TCP
- blocks a domain *and* all of its subdomains
- per-domain allowlist always wins over the blocklist
- caches upstream answers and honours TTLs
- logs every blocked lookup so you can see what the console tried to reach

Usage:
    python psn_block_dns.py
    python psn_block_dns.py --port 53 --listen 0.0.0.0 --blocklist blocklist.txt
    python psn_block_dns.py --query cdn.playstation.net        # test from a shell
    python psn_block_dns.py --selftest                        # verify the rules
    python psn_block_dns.py --dump-ips                        # list blocked A/AAAA
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import random
import signal
import socket
import struct
import sys
import threading
import time

# ---------------------------------------------------------------- DNS constants

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_OPT = 41
TYPE_SVCB = 64
TYPE_HTTPS = 65
TYPE_ANY = 255

CLASS_IN = 1

HEADER_LEN = 12
RECV_SIZE = 4096

UPSTREAM_TIMEOUT = 4.0

STATS_LOCK = threading.Lock()
STATS = {"queries": 0, "blocked": 0, "forwarded": 0, "cached": 0, "errors": 0}


# ---------------------------------------------------------------- wire helpers


def encode_name(name: str) -> bytes:
    out = bytearray()
    if name and name != ".":
        for label in name.rstrip(".").split("."):
            raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii", "replace")
            if not 0 < len(raw) <= 63:
                raw = b"x"
            out.append(len(raw))
            out += raw
    out.append(0)
    return bytes(out)


def read_name(msg: bytes, off: int):
    """Return (lowercase dotted name, offset just past the name)."""
    labels = []
    end = None
    jumped = False
    while True:
        if off >= len(msg):
            raise ValueError("truncated name")
        ln = msg[off]
        if ln == 0:
            off += 1
            if not jumped:
                end = off
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", msg[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            if len(labels) > 128:
                raise ValueError("name loop")
            continue
        off += 1
        labels.append(msg[off:off + ln].decode("ascii", "replace").lower())
        off += ln
    return ".".join(labels), end if end is not None else off


def skip_name(msg: bytes, off: int) -> int:
    return read_name(msg, off)[1]


def parse_question(msg: bytes):
    """-> (qname, qtype, qclass, qend) or None if the packet is malformed."""
    if len(msg) < HEADER_LEN:
        return None
    qdcount = struct.unpack("!H", msg[4:6])[0]
    if qdcount < 1:
        return None
    try:
        qname, off = read_name(msg, HEADER_LEN)
        qtype, qclass = struct.unpack("!HH", msg[off:off + 4])
        off += 4
    except (ValueError, struct.error):
        return None
    return qname.lower(), qtype, qclass, off


def walk_ttls(msg: bytes, qend: int):
    """Collect the byte offset of every TTL field in a response.

    Offsets (rather than re-encoded records) are used so that the message keeps
    its own name compression pointers intact.
    """
    an, ns, ar = struct.unpack("!HHH", msg[6:12])
    out = []
    off = qend
    for count in (an, ns, ar):
        for _ in range(count):
            if off >= len(msg):
                return out
            try:
                off = skip_name(msg, off)
            except ValueError:
                return out
            if off + 10 > len(msg):
                return out
            rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
            out.append((off + 4, ttl))
            if rtype == TYPE_OPT:
                rdlen = 0
            off += 10 + rdlen
    return out


def build_response(req: bytes, qend: int, qtype: int, answers, rcode: int = 0, ra: bool = True):
    """answers: list of (name, type, cls, ttl, rdata_bytes) - rdata must be raw."""
    flags = 0x8000                      # QR
    flags |= req[2] & 0x0100             # copy RD
    flags |= 0x0080 if ra else 0         # RA
    flags |= rcode & 0x000F
    arcount = 1 if struct.unpack("!H", req[10:12])[0] else 0
    header = struct.pack(
        "!HHHHHH",
        struct.unpack("!H", req[0:2])[0],
        flags,
        1,
        len(answers),
        0,
        arcount,
    )
    question = req[HEADER_LEN:qend]

    body = bytearray()
    for name, rtype, rclass, ttl, rdata in answers:
        ttl = max(0, min(int(ttl), 0x7FFFFFFF))
        body += encode_name(name)
        body += struct.pack("!HHIH", rtype, rclass, ttl, len(rdata))
        body += rdata

    if arcount:
        # empty OPT record: advertise nothing, but mirror the client's EDNS request
        body += b"\x00" + struct.pack("!HHIH", TYPE_OPT, 0x1000, 0, 0)
    return header + question + bytes(body)


def sinkhole_answers(qtype: int, v4: str, v6: str):
    if qtype == TYPE_A:
        return [(".", TYPE_A, CLASS_IN, 60, socket.inet_pton(socket.AF_INET, v4))]
    if qtype == TYPE_AAAA:
        return [(".", TYPE_AAAA, CLASS_IN, 60, socket.inet_pton(socket.AF_INET6, v6))]
    if qtype == TYPE_ANY:
        return [
            (".", TYPE_A, CLASS_IN, 60, socket.inet_pton(socket.AF_INET, v4)),
            (".", TYPE_AAAA, CLASS_IN, 60, socket.inet_pton(socket.AF_INET6, v6)),
        ]
    return []


# ---------------------------------------------------------------- upstream


class Resolver:
    def __init__(self, servers, tcp_only=False):
        self.servers = servers
        self.tcp_only = tcp_only
        self.lock = threading.Lock()
        self.healthy = list(servers)

    def _mark(self, server, ok):
        with self.lock:
            if ok and server not in self.healthy:
                self.healthy.append(server)
            elif not ok and server in self.healthy and len(self.healthy) > 1:
                self.healthy.remove(server)

    def _wire_query(self, qname, qtype, qclass):
        return (
            struct.pack("!HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
            + encode_name(qname)
            + struct.pack("!HH", qtype, qclass)
        )

    def resolve(self, qname, qtype, qclass=CLASS_IN):
        """-> (response_bytes, qend, [(ttl_off, ttl), ...]) or None."""
        wire = self._wire_query(qname, qtype, qclass)
        order = list(self.healthy)
        random.shuffle(order)
        for server in order:
            for use_tcp in ((False, True) if not self.tcp_only else (True,)):
                try:
                    resp = self._ask(server, wire, use_tcp)
                except OSError:
                    self._mark(server, False)
                    continue
                if resp is None:
                    continue
                qid = struct.unpack("!H", resp[0:2])[0]
                if qid != struct.unpack("!H", wire[0:2])[0]:
                    continue
                rcode = resp[3] & 0x0F
                if rcode == 2:                       # SERVFAIL -> try next server
                    continue
                if (resp[2] & 0x02) and not use_tcp:  # TC -> retry over TCP
                    continue
                qp = parse_question(resp)
                if qp is None:
                    continue
                self._mark(server, True)
                return resp, qp[3], walk_ttls(resp, qp[3])
        return None

    def _ask(self, server, wire, use_tcp):
        if use_tcp:
            with socket.create_connection((server, 53), UPSTREAM_TIMEOUT) as sock:
                sock.settimeout(UPSTREAM_TIMEOUT)
                sock.sendall(struct.pack("!H", len(wire)) + wire)
                head = self._recv_exact(sock, 2)
                if not head:
                    return None
                ln = struct.unpack("!H", head)[0]
                return self._recv_exact(sock, ln)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(UPSTREAM_TIMEOUT)
            sock.sendto(wire, (server, 53))
            resp, _ = sock.recvfrom(RECV_SIZE)
            return resp

    @staticmethod
    def _recv_exact(sock, count):
        buf = b""
        while len(buf) < count:
            chunk = sock.recv(count - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


# ---------------------------------------------------------------- cache


class Cache:
    def __init__(self, max_ttl, max_entries=20000):
        self.data = {}
        self.max_ttl = max_ttl
        self.max_entries = max_entries
        self.lock = threading.Lock()

    def get(self, key):
        with self.lock:
            item = self.data.get(key)
            if item is None:
                return None
            resp, ttl_offs, expires = item
            if expires <= time.time():
                self.data.pop(key, None)
                return None
            return resp, ttl_offs, expires

    def put(self, key, resp, ttl_offs):
        now = time.time()
        lowest = 86400
        kept = []
        for off, ttl in ttl_offs:
            ttl = min(ttl, self.max_ttl)
            lowest = min(lowest, ttl)
            if off + 4 <= len(resp):
                resp = resp[:off] + struct.pack("!I", ttl) + resp[off + 4:]
                kept.append((off, ttl))
        if not kept:
            return
        with self.lock:
            if len(self.data) >= self.max_entries:
                for k in sorted(self.data, key=lambda k: self.data[k][2])[: len(self.data) // 4]:
                    self.data.pop(k, None)
            self.data[key] = (resp, kept, now + lowest)


# ---------------------------------------------------------------- rule sets


def load_rules(path, allow=False):
    rules = set()
    if not path or not os.path.isfile(path):
        return rules
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].split("!", 1)[0].strip().lower()
            if not line:
                continue
            if line.startswith("*."):
                line = line[2:]
            line = line.rstrip(".")
            if line:
                try:
                    ipaddress.ip_address(line)
                    continue
                except ValueError:
                    pass
                rules.add(line)
    return rules


def is_blocked(qname, blocklist, allowlist):
    if not qname:
        return False
    labels = qname.rstrip(".").split(".")
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in allowlist:          # allowlist always wins
            return False
        if cand in blocklist:
            return True
    return False


# ---------------------------------------------------------------- core handler


class Server:
    def __init__(self, args):
        self.args = args
        self.resolver = Resolver([s.strip() for s in args.upstream.split(",") if s.strip()])
        self.cache = Cache(args.max_ttl)
        self.blocklist = load_rules(args.blocklist) | load_rules(args.extra_blocklist)
        self.allowlist = load_rules(args.allowlist)
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        if not self.blocklist:
            print("! blocklist is empty - nothing will be blocked", file=sys.stderr)

    # -- logging -------------------------------------------------------
    def log_blocked(self, qname, qtype, client):
        if self.args.quiet:
            return
        name = type_name(qtype)
        src = client[0] if isinstance(client, tuple) else client
        print(f"BLOCK  {src:>15}  {qname} ({name})", flush=True)

    def log_query(self, qname, qtype, client, tag):
        if self.args.verbose:
            src = client[0] if isinstance(client, tuple) else client
            print(f"{tag:>7} {src:>15}  {qname} ({type_name(qtype)})", flush=True)

    # -- request handling ---------------------------------------------
    def handle(self, req, client):
        with STATS_LOCK:
            STATS["queries"] += 1
        qp = parse_question(req)
        if qp is None:
            return None
        qname, qtype, qclass, qend = qp
        if qname in ("", "."):
            return None

        if is_blocked(qname, self.blocklist, self.allowlist):
            with STATS_LOCK:
                STATS["blocked"] += 1
            self.log_blocked(qname, qtype, client)
            if self.args.nxdomain:
                return build_response(req, qend, qtype, [], rcode=3)
            answers = sinkhole_answers(qtype, self.args.sinkhole, self.args.sinkhole6)
            return build_response(req, qend, qtype, answers)

        self.log_query(qname, qtype, client, "PASS")
        key = (qname, qtype)
        cached = self.cache.get(key)
        if cached is not None:
            with STATS_LOCK:
                STATS["cached"] += 1
            resp, ttl_offs, expires = cached
            now = time.time()
            patched = resp
            for off, ttl in ttl_offs:
                left = int(max(0, expires - now))
                patched = patched[:off] + struct.pack("!I", left) + patched[off + 4:]
            return patched

        result = self.resolver.resolve(qname, qtype, qclass)
        if result is None:
            with STATS_LOCK:
                STATS["errors"] += 1
            print(f"! upstream failure for {qname}", file=sys.stderr, flush=True)
            return build_response(req, qend, qtype, [], rcode=2)
        resp, _qend, ttl_offs = result
        with STATS_LOCK:
            STATS["forwarded"] += 1
        self.cache.put(key, resp, ttl_offs)
        return resp


def type_name(qtype):
    for name, val in vars(sys.modules[__name__]).items():
        if name.startswith("TYPE_") and val == qtype:
            return name[5:]
    return str(qtype)


# ---------------------------------------------------------------- transports


def udp_worker(server, sock):
    sock.settimeout(1.0)
    while not server.stopping.is_set():
        try:
            data, client = sock.recvfrom(RECV_SIZE)
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=udp_reply, args=(server, sock, data, client), daemon=True).start()


def udp_reply(server, sock, req, client):
    try:
        resp = server.handle(req, client)
    except Exception as exc:                      # never kill the listener
        print(f"! handler error: {exc!r}", file=sys.stderr, flush=True)
        return
    if resp:
        try:
            sock.sendto(resp, client)
        except OSError:
            pass


def tcp_worker(server, sock):
    sock.settimeout(5.0)
    while not server.stopping.is_set():
        try:
            conn, client = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=tcp_session, args=(server, conn, client), daemon=True).start()


def tcp_session(server, conn, client):
    try:
        with conn:
            conn.settimeout(10.0)
            while True:
                head = Resolver._recv_exact(conn, 2)
                if not head:
                    return
                ln = struct.unpack("!H", head)[0]
                if ln == 0:
                    return
                req = Resolver._recv_exact(conn, ln)
                if req is None:
                    return
                resp = server.handle(req, client)
                if resp is None:
                    return
                conn.sendall(struct.pack("!H", len(resp)) + resp)
    except OSError:
        pass
    except Exception as exc:
        print(f"! tcp session error: {exc!r}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------- extras


def system_resolvers():
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            )
            val, _ = winreg.QueryValueEx(key, "NameServer")
            out = [s.strip() for s in str(val).split(",") if s.strip() and s.strip() != "0.0.0.0"]
            if out:
                return out
        except OSError:
            pass
    try:
        return [info[4][0] for info in socket.getaddrinfo(socket.gethostname(), 53, socket.AF_INET)]
    except OSError:
        return ["1.1.1.1"]


def do_query(args):
    """Client mode: ask a server one question and print the answer."""
    port = args.port
    host = args.query_server
    qname, qtype = args.query, TYPE_A
    if ":" in qname and "." not in qname.rstrip("."):
        qtype = TYPE_AAAA
    wire = (
        struct.pack("!HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
        + encode_name(qname)
        + struct.pack("!HH", qtype, CLASS_IN)
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    sock.sendto(wire, (host, port))
    resp, _ = sock.recvfrom(RECV_SIZE)
    rcode = resp[3] & 0x0F
    an = struct.unpack("!H", resp[6:8])[0]
    print(f"{qname} type={type_name(qtype)} rcode={rcode} answers={an} "
          f"flags={' '.join(f for f, b in (('QR', 0x80), ('TC', 0x02), ('NX', 0x0F)) if resp[2] & b)}")
    off = parse_question(resp)[3]
    for _ in range(an):
        name, off = read_name(resp, off)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", resp[off:off + 10])
        off += 10
        rdata = resp[off:off + rdlen]
        off += rdlen
        if rtype == TYPE_A:
            value = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == TYPE_AAAA:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (TYPE_CNAME, TYPE_PTR, TYPE_NS):
            value = read_name(resp, off - rdlen)[0]
        else:
            value = rdata.hex()
        print(f"  {name or '.'} {ttl}s {type_name(rtype)} {value}")


def dump_ips(args, server):
    names = sorted(server.blocklist)
    out = {"v4": set(), "v6": set()}
    for name in names:
        for qtype in (TYPE_A, TYPE_AAAA):
            res = server.resolver.resolve(name, qtype)
            if not res:
                continue
            resp, _qe, _ttls = res
            off = parse_question(resp)[3]
            an = struct.unpack("!H", resp[6:8])[0]
            for _ in range(an):
                _n, off = read_name(resp, off)
                rtype, _rc, _ttl, rdlen = struct.unpack("!HHIH", resp[off:off + 10])
                off += 10
                rdata = resp[off:off + rdlen]
                off += rdlen
                if rtype == TYPE_A and rdlen == 4:
                    out["v4"].add(socket.inet_ntop(socket.AF_INET, rdata))
                elif rtype == TYPE_AAAA and rdlen == 16:
                    out["v6"].add(socket.inet_ntop(socket.AF_INET6, rdata))
    for key, label in (("v4", "IPv4"), ("v6", "IPv6")):
        print(f"# {label} ({len(out[key])})")
        for ip in sorted(out[key]):
            print(ip)
    with open(args.ips_out, "w", encoding="utf-8") as fh:
        for ip in sorted(out["v4"]):
            fh.write(ip + "\n")
        for ip in sorted(out["v6"]):
            fh.write(ip + "\n")
    print(f"# written to {args.ips_out}", file=sys.stderr)


# ---------------------------------------------------------------- main


def lan_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def do_selftest(args):
    """Verify the rules without needing a second machine."""
    server = Server(args)
    checks = [
        ("google.com", TYPE_A, False, "normal domain resolves"),
        ("www.youtube.com", TYPE_A, False, "streaming CDN resolves"),
        ("cdn.playstation.net", TYPE_A, True, "PSN CDN blocked"),
        ("np.playstation.com", TYPE_A, True, "PSN login blocked"),
        ("something.scei.co.jp", TYPE_A, True, "regional Sony host blocked"),
        ("store.playstation.com", TYPE_HTTPS, True, "HTTPS type query blocked"),
    ]
    failed = 0
    for name, qtype, want_block, label in checks:
        req = (
            struct.pack("!HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
            + encode_name(name)
            + struct.pack("!HH", qtype, CLASS_IN)
        )
        qp = parse_question(req)
        blocked = is_blocked(name, server.blocklist, server.allowlist)
        resp = server.handle(req, ("127.0.0.1", 0))
        an = struct.unpack("!H", resp[6:8])[0] if resp else 0
        sinked = resp is not None and qtype in (TYPE_A, TYPE_AAAA, TYPE_ANY) and resp.endswith(
            socket.inet_pton(socket.AF_INET, args.sinkhole)
        )
        if want_block:
            if args.nxdomain:
                ok = blocked and an == 0 and (resp[3] & 0x0F) == 3
            elif qtype in (TYPE_A, TYPE_AAAA, TYPE_ANY):
                # A/AAAA/ANY get a sinkhole address
                ok = blocked and an > 0
            else:
                # every other type gets NOERROR with no data
                ok = blocked and an == 0
        else:
            ok = not blocked and an > 0
        failed += not ok
        detail = "sinkholed" if sinked else f"answers={an}"
        print(f"[{'ok' if ok else 'FAIL'}] {label:32} {name:28} {detail}")

    # allowlist must win over the blocklist
    server.allowlist.add("playstation.net")
    over = is_blocked("cdn.playstation.net", server.blocklist, server.allowlist)
    failed += over
    print(f"[{'ok' if not over else 'FAIL'}] {'allowlist overrides blocklist':32} cdn.playstation.net")
    print(f"[{'ok' if failed == 0 else 'FAIL'}] {len(server.blocklist)} rules loaded, "
          f"{failed} failure(s)")
    return 1 if failed else 0


def build_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--listen", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    p.add_argument("--port", type=int, default=5300,
                   help="listen port (default 5300; port 53 needs an elevated shell)")
    p.add_argument("--upstream", default="1.1.1.1,8.8.8.8,9.9.9.9",
                   help="comma separated upstream resolvers, or 'system' (default 1.1.1.1,8.8.8.8,9.9.9.9)")
    here = os.path.dirname(os.path.abspath(__file__))
    p.add_argument("--blocklist", default=os.path.join(here, "blocklist.txt"))
    p.add_argument("--extra-blocklist", default=None, help="second blocklist file to merge in")
    p.add_argument("--allowlist", default=os.path.join(here, "allowlist.txt"),
                   help="domains that override the blocklist (default allowlist.txt)")
    p.add_argument("--sinkhole", default="0.0.0.0", help="A record returned for blocked names")
    p.add_argument("--sinkhole6", default="::", help="AAAA record returned for blocked names")
    p.add_argument("--nxdomain", action="store_true", help="answer NXDOMAIN instead of a sinkhole IP")
    p.add_argument("--max-ttl", type=int, default=600, help="clamp upstream TTLs to this many seconds")
    p.add_argument("--stats-interval", type=int, default=0, help="print counters every N seconds (0 = off)")
    p.add_argument("--verbose", action="store_true", help="log allowed queries too")
    p.add_argument("--quiet", action="store_true", help="do not log blocked queries")
    p.add_argument("--query", metavar="NAME", help="client mode: resolve NAME and exit")
    p.add_argument("--query-server", default="127.0.0.1")
    p.add_argument("--selftest", action="store_true", help="check the rules locally and exit")
    p.add_argument("--dump-ips", action="store_true", help="resolve the blocklist and print the IPs")
    p.add_argument("--ips-out", default=os.path.join(here, "psn-ips.txt"))
    return p


def main():
    args = build_parser().parse_args()
    if args.upstream.strip().lower() == "system":
        found = system_resolvers()
        print(f"upstream (system): {', '.join(found)}")
        args.upstream = ",".join(found)

    if args.query:
        do_query(args)
        return 0

    if args.selftest:
        return do_selftest(args)

    if args.dump_ips:
        srv = Server(args)
        dump_ips(args, srv)
        return 0

    server = Server(args)
    try:
        usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        usock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        usock.bind((args.listen, args.port))
    except OSError as exc:
        print(f"! cannot bind UDP {args.listen}:{args.port} - {exc}", file=sys.stderr)
        print("  ports below 1024 need an elevated (admin) shell on Windows", file=sys.stderr)
        return 1
    try:
        tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tsock.bind((args.listen, args.port))
        tsock.listen(64)
    except OSError as exc:
        print(f"! cannot bind TCP {args.listen}:{args.port} - {exc}", file=sys.stderr)
        usock.close()
        return 1

    print(f"psn_block_dns listening on {args.listen}:{args.port} (udp+tcp)")
    print(f"upstream: {args.upstream}")
    print(f"blocked domains: {len(server.blocklist)}   allowlisted: {len(server.allowlist)}")
    print(f"set the console's manual DNS to: {lan_ip()}")
    print("Ctrl+C to stop", flush=True)

    threading.Thread(target=udp_worker, args=(server, usock), daemon=True).start()
    threading.Thread(target=tcp_worker, args=(server, tsock), daemon=True).start()

    def shutdown(signum, _frame):
        server.stopping.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, shutdown)
        except (ValueError, OSError):
            pass

    last = time.time()
    try:
        while not server.stopping.is_set():
            time.sleep(0.5)
            if args.stats_interval and time.time() - last >= args.stats_interval:
                last = time.time()
                with STATS_LOCK:
                    print(f"stats: {STATS}", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        server.stopping.set()
        usock.close()
        tsock.close()
        with STATS_LOCK:
            print(f"final: {STATS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
