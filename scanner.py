"""Network scanning utilities: ping sweep, ARP lookup, hostname resolution, port scan."""
from __future__ import annotations

import ipaddress
import locale
import platform
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Callable, Iterable, Iterator

IS_WINDOWS = platform.system().lower() == "windows"
# System encoding used to decode output of system utilities (ping, arp).
# On Russian Windows this is typically cp866 for console apps.
_SYS_ENCODING = locale.getpreferredencoding(False) or "utf-8"
if IS_WINDOWS:
    try:
        import ctypes

        cp = ctypes.windll.kernel32.GetConsoleOutputCP()
        if cp:
            _SYS_ENCODING = f"cp{cp}"
    except Exception:
        pass


def _run(cmd: list[str], timeout: float) -> tuple[int, str]:
    """Run a system command and return (returncode, decoded_stdout)."""
    creationflags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            creationflags=creationflags,
        )
    except subprocess.TimeoutExpired:
        return 1, ""
    except Exception:
        return 1, ""
    text = result.stdout.decode(_SYS_ENCODING, errors="replace")
    return result.returncode, text

# Common ports shown by default (name -> port)
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


# Top 100 most-frequently-open TCP ports across the public internet
# (derived from nmap-services statistics). Used by the ``--top-ports``
# flag in the GUI to provide quick reduced-port-set scans.
TOP_PORTS: tuple[int, ...] = (
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110,
    111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444,
    445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
    990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
    1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306,
    3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432,
    5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009,
    8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153,
    49154, 49155, 49156, 49157,
)


@dataclass
class Host:
    ip: str
    alive: bool = False
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    open_ports: list[int] = field(default_factory=list)
    response_ms: float | None = None
    port_scan_done: int = 0
    port_scan_total: int = 0
    scan_complete: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["open_ports"] = ",".join(str(p) for p in self.open_ports)
        for k in ("port_scan_done", "port_scan_total", "scan_complete"):
            d.pop(k, None)
        return d


def expand_target(target: str) -> list[str]:
    """Expand a target string into a list of IP addresses.

    Supports: "192.168.1.0/24", "192.168.1.1-50", "192.168.1.1", "192.168.1.1,192.168.1.5".
    """
    target = target.strip()
    if not target:
        return []

    ips: list[str] = []
    for chunk in (c.strip() for c in target.split(",") if c.strip()):
        if "/" in chunk:
            net = ipaddress.ip_network(chunk, strict=False)
            ips.extend(str(h) for h in net.hosts())
        elif "-" in chunk:
            base, _, end = chunk.rpartition(".")
            start_str, _, end_str = end.partition("-")
            if "." in end_str:
                # full IP range like 192.168.1.1-192.168.2.50
                start_ip = int(ipaddress.IPv4Address(chunk.split("-")[0]))
                end_ip = int(ipaddress.IPv4Address(chunk.split("-")[1]))
                ips.extend(str(ipaddress.IPv4Address(i)) for i in range(start_ip, end_ip + 1))
            else:
                start = int(start_str)
                stop = int(end_str)
                ips.extend(f"{base}.{i}" for i in range(start, stop + 1))
        else:
            ips.append(str(ipaddress.ip_address(chunk)))
    # dedupe preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


def ping(ip: str, timeout_ms: int = 700) -> tuple[bool, float | None]:
    """Send a single ICMP echo request. Returns (alive, response_ms)."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]

    rc, out = _run(cmd, timeout=(timeout_ms / 1000) + 1.5)
    if rc != 0:
        return False, None

    # On Windows `ping` may return 0 even when the host is unreachable
    # (e.g. "Destination host unreachable" message). A real reply always
    # contains "TTL=" — both English and localized output keep this token.
    if IS_WINDOWS and "TTL=" not in out.upper().replace(" ", ""):
        return False, None

    # Parse response time. Handles English ("time=12ms", "time<1ms") and
    # localized ("время=12мс", "время<1мс") output by looking for an
    # equals/less sign followed by a number followed by "ms"/"мс".
    match = re.search(r"[=<]\s*([\d.]+)\s*(?:ms|мс)", out, re.IGNORECASE)
    rtt = float(match.group(1)) if match else None
    return True, rtt


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _parse_arp_table() -> dict[str, str]:
    """Return a {ip: mac} mapping from the system ARP cache."""
    mapping: dict[str, str] = {}
    try:
        if IS_WINDOWS:
            _, out = _run(["arp", "-a"], timeout=5)
            for line in out.splitlines():
                m = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})",
                    line,
                )
                if m:
                    mapping[m.group(1)] = m.group(2).replace("-", ":").lower()
        else:
            _, out = _run(["ip", "neigh"], timeout=5)
            if not out.strip():
                _, out = _run(["arp", "-an"], timeout=5)
            for line in out.splitlines():
                m = re.search(
                    r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})",
                    line,
                )
                if m:
                    mapping[m.group(1)] = m.group(2).lower()
    except Exception:
        pass
    return mapping


def get_mac(ip: str, arp_cache: dict[str, str] | None = None) -> str:
    if arp_cache is None:
        arp_cache = _parse_arp_table()
    return arp_cache.get(ip, "")


_vendor_lookup = None


def _get_vendor_lookup():
    global _vendor_lookup
    if _vendor_lookup is None:
        try:
            from mac_vendor_lookup import MacLookup

            ml = MacLookup()
            _vendor_lookup = ml
        except Exception:
            _vendor_lookup = False
    return _vendor_lookup


def lookup_vendor(mac: str) -> str:
    if not mac:
        return ""
    ml = _get_vendor_lookup()
    if not ml:
        return ""
    try:
        return ml.lookup(mac)
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float = 0.6) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def scan_ports(
    ip: str,
    ports: Iterable[int],
    timeout: float = 0.6,
    workers: int = 64,
    progress_cb: Callable[[int, int], None] | None = None,
) -> list[int]:
    ports = list(ports)
    if not ports:
        return []
    open_ports: list[int] = []
    total = len(ports)
    # Throttle progress reports to roughly 1% increments.
    step = max(1, total // 100)
    done = 0
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ports)))) as pool:
        futures = {pool.submit(scan_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            if fut.result():
                open_ports.append(futures[fut])
            done += 1
            if progress_cb and (done == total or done % step == 0):
                progress_cb(done, total)
    open_ports.sort()
    return open_ports


def scan_network(
    targets: list[str],
    ping_timeout_ms: int = 700,
    workers: int = 100,
    resolve_hostnames: bool = True,
    detect_mac: bool = True,
    ports: Iterable[int] | None = None,
    port_timeout: float = 0.6,
    port_workers: int = 64,
    cancel_event=None,
    on_host_update: Callable[[Host], None] | None = None,
    port_progress_cb: Callable[[str, int, int], None] | None = None,
    skip_ping: bool = False,
    ping_retries: int = 1,
) -> Iterator[Host]:
    """Yield Host objects as they are discovered.

    Phase 1 is a ping sweep that yields every IP — alive (with
    ``scan_complete=False``) and dead (``scan_complete=True``) — as soon
    as its status is known, so the UI can show active hosts immediately.
    Phase 2 enriches each alive host with hostname, MAC, vendor and open
    ports; an intermediate snapshot (hostname/MAC ready, ports pending)
    is delivered through ``on_host_update`` and per-port progress through
    ``port_progress_cb`` (``ip``, ``done``, ``total``). The fully-scanned
    Host with ``scan_complete=True`` is then yielded by the iterator.
    """
    ports = list(ports or [])
    total_ports = len(ports)

    # Phase 1: ping sweep in parallel (skipped if --skip_ping was requested,
    # in which case every target is treated as alive and forwarded to phase 2).
    def _check(ip: str) -> Host:
        if skip_ping:
            return Host(
                ip=ip,
                alive=True,
                response_ms=None,
                port_scan_total=total_ports,
                scan_complete=False,
            )
        attempts = max(1, ping_retries)
        for _ in range(attempts):
            alive, rtt = ping(ip, timeout_ms=ping_timeout_ms)
            if alive:
                return Host(
                    ip=ip,
                    alive=True,
                    response_ms=rtt,
                    port_scan_total=total_ports,
                    scan_complete=False,
                )
        return Host(
            ip=ip,
            alive=False,
            response_ms=None,
            port_scan_total=total_ports,
            scan_complete=True,
        )

    alive_hosts: list[Host] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_check, ip): ip for ip in targets}
        for fut in as_completed(futures):
            if cancel_event is not None and cancel_event.is_set():
                break
            host = fut.result()
            yield host
            if host.alive:
                alive_hosts.append(host)

    if cancel_event is not None and cancel_event.is_set():
        return

    # Refresh ARP cache after the sweep so it's populated.
    arp_cache = _parse_arp_table() if detect_mac else {}

    # Phase 2: enrich alive hosts (hostname, MAC, vendor, ports)
    def _enrich(host: Host) -> Host:
        if cancel_event is not None and cancel_event.is_set():
            host.scan_complete = True
            return host
        if resolve_hostnames:
            host.hostname = resolve_hostname(host.ip)
        if detect_mac:
            host.mac = get_mac(host.ip, arp_cache)
            if host.mac:
                host.vendor = lookup_vendor(host.mac)
        if on_host_update:
            on_host_update(Host(
                ip=host.ip, alive=host.alive, hostname=host.hostname,
                mac=host.mac, vendor=host.vendor, response_ms=host.response_ms,
                port_scan_done=0, port_scan_total=total_ports,
                scan_complete=False,
            ))
        if ports and not (cancel_event is not None and cancel_event.is_set()):
            def _cb(d: int, t: int) -> None:
                host.port_scan_done = d
                host.port_scan_total = t
                if port_progress_cb:
                    port_progress_cb(host.ip, d, t)
            host.open_ports = scan_ports(
                host.ip, ports,
                timeout=port_timeout,
                workers=port_workers,
                progress_cb=_cb,
            )
        host.port_scan_done = total_ports
        host.port_scan_total = total_ports
        host.scan_complete = True
        return host

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(alive_hosts)))) as pool:
        futures = {pool.submit(_enrich, h): h for h in alive_hosts}
        for fut in as_completed(futures):
            if cancel_event is not None and cancel_event.is_set():
                break
            yield fut.result()


def detect_local_subnet() -> str:
    """Try to determine the local /24 subnet for the default interface."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except OSError:
        return "192.168.1.0/24"


def get_default_gateway() -> str:
    """Return the IPv4 default gateway address or empty string."""
    if IS_WINDOWS:
        _, out = _run(["ipconfig"], timeout=5)
        # English: "Default Gateway . . . . . . . : 192.168.1.1"
        # Russian: "Основной шлюз . . . . . . . . : 192.168.1.1"
        for line in out.splitlines():
            m = re.search(
                r"(?:Default Gateway|Основной шлюз)[^:]*:\s*"
                r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
                line,
            )
            if m and m.group(1) != "0.0.0.0":
                return m.group(1)
        return ""
    _, out = _run(["ip", "route", "show", "default"], timeout=5)
    m = re.search(r"default\s+via\s+([0-9.]+)", out)
    if m:
        return m.group(1)
    _, out = _run(["route", "-n"], timeout=5)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "0.0.0.0":
            return parts[1]
    return ""


def get_wifi_info() -> dict[str, str]:
    """Return a dict of ``netsh wlan show interfaces`` keys (Windows).

    Returns an empty dict on non-Windows systems or when no Wi-Fi
    interface is present / connected.
    """
    if not IS_WINDOWS:
        return {}
    _, out = _run(["netsh", "wlan", "show", "interfaces"], timeout=5)
    info: dict[str, str] = {}
    for raw in out.splitlines():
        line = raw.strip()
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip()
        v = v.strip()
        if k and v and not k.startswith("-"):
            info[k] = v
    return info


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else detect_local_subnet()
    print(f"Scanning {target} ...")
    for h in scan_network(expand_target(target), ports=list(COMMON_PORTS.keys())):
        if h.alive and h.scan_complete:
            print(
                f"{h.ip:15s}  {h.hostname or '-':30s}  {h.mac or '-':17s}  "
                f"{h.vendor or '-':25s}  ports={h.open_ports}"
            )
