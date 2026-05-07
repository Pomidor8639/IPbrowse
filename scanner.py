"""Network scanning utilities: ping sweep, ARP lookup, hostname resolution, port scan."""
from __future__ import annotations

import csv
import ipaddress
import locale
import platform
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
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


# Curated mapping ``port -> typical software``. Used by the "Порты"
# tab to enrich the IANA service registry with information that IANA
# itself doesn't carry (vendor / OSS implementations, well-known
# default ports of products that aren't formally registered, etc.).
#
# Multiple comma-separated entries are intentional: many ports are
# shared by several implementations (e.g. 80 by Apache / nginx / IIS),
# and seeing them together is more informative than just the protocol
# name. Where a port is famously used by malware as well, that's
# called out so a user reviewing scan output isn't surprised by an
# "RDP" hit on a workstation that shouldn't have RDP exposed.
PORT_SOFTWARE: dict[int, str] = {
    20:    "FTP-данные — vsftpd, ProFTPD, Pure-FTPd, IIS",
    21:    "FTP — vsftpd, ProFTPD, Pure-FTPd, FileZilla Server, IIS FTP",
    22:    "SSH / SFTP — OpenSSH, Dropbear, libssh, Bitvise SSH",
    23:    "Telnet — telnetd; маршрутизаторы и IoT (опасно открытым)",
    25:    "SMTP — Postfix, Exim, Sendmail, Microsoft Exchange",
    37:    "Time protocol",
    43:    "WHOIS",
    53:    "DNS — BIND, Unbound, dnsmasq, PowerDNS, systemd-resolved",
    67:    "DHCP-сервер — ISC DHCP, dnsmasq, Kea, Windows DHCP",
    68:    "DHCP-клиент",
    69:    "TFTP — tftpd-hpa, atftp, SolarWinds TFTP",
    79:    "Finger",
    80:    "HTTP — Apache httpd, nginx, IIS, Caddy, lighttpd, Tomcat",
    81:    "HTTP-Alt — веб-админки роутеров, Tor",
    88:    "Kerberos KDC — MIT Kerberos, Heimdal, Active Directory",
    102:   "Siemens S7 PLC",
    110:   "POP3 — Dovecot, Cyrus IMAP, Courier, Microsoft Exchange",
    111:   "RPCbind / portmap (NFS, NIS)",
    113:   "Ident",
    119:   "NNTP — INN, leafnode",
    123:   "NTP — ntpd, chrony, Windows w32time",
    135:   "Microsoft RPC Endpoint Mapper (DCE/RPC)",
    137:   "NetBIOS Name — Samba nmbd, Windows",
    138:   "NetBIOS Datagram — Samba nmbd, Windows",
    139:   "NetBIOS Session — Samba smbd, Windows File Sharing",
    143:   "IMAP — Dovecot, Cyrus, Courier, Microsoft Exchange",
    161:   "SNMP — Net-SNMP, оборудование Cisco / Juniper / MikroTik",
    162:   "SNMP-trap — Net-SNMP, Zabbix, Nagios, PRTG",
    179:   "BGP — FRRouting, Quagga, BIRD, Cisco IOS, Juniper",
    194:   "IRC — UnrealIRCd, InspIRCd, ircd-hybrid",
    389:   "LDAP — OpenLDAP, Active Directory, 389 Directory Server",
    427:   "SLP — OpenSLP",
    443:   "HTTPS — Apache, nginx, IIS, Caddy + TLS, HTTP/2, HTTP/3",
    445:   "SMB — Samba smbd, Windows File Sharing (атаки EternalBlue)",
    465:   "SMTPS — Postfix, Exim, Sendmail",
    500:   "IKE/IPsec — strongSwan, Libreswan, Windows IKE",
    502:   "Modbus TCP — промышленные ПЛК",
    513:   "rlogin",
    514:   "Syslog / rsh — rsyslog, syslog-ng",
    515:   "LPD — CUPS, lpd",
    520:   "RIP — FRRouting, gated",
    523:   "IBM DB2",
    546:   "DHCPv6 client",
    547:   "DHCPv6 server — ISC DHCP, Kea",
    548:   "AFP — netatalk (Apple File Sharing)",
    554:   "RTSP — Live555, GStreamer; IP-камеры (Hikvision, Dahua)",
    587:   "SMTP submission — Postfix, Exim, Sendmail",
    593:   "RPC over HTTP — Microsoft Exchange (Outlook Anywhere)",
    623:   "IPMI — BMC: Dell iDRAC, HPE iLO, Supermicro",
    631:   "IPP / CUPS — печать",
    636:   "LDAPS — OpenLDAP, Active Directory + TLS",
    873:   "rsync (демон)",
    902:   "VMware ESXi authd / vCenter",
    989:   "FTPS-данные",
    990:   "FTPS-управление — vsftpd, FileZilla Server, IIS",
    993:   "IMAPS — Dovecot, Microsoft Exchange",
    995:   "POP3S — Dovecot, Microsoft Exchange",
    1025:  "Windows RPC dynamic / Microsoft network blackjack",
    1080:  "SOCKS-прокси — Dante, 3proxy",
    1194:  "OpenVPN",
    1352:  "Lotus Notes / Domino",
    1433:  "Microsoft SQL Server",
    1434:  "Microsoft SQL Server browser (UDP)",
    1521:  "Oracle DB listener",
    1701:  "L2TP — strongSwan, xl2tpd",
    1723:  "PPTP",
    1812:  "RADIUS auth — FreeRADIUS, Cisco ACS, Microsoft NPS",
    1813:  "RADIUS accounting — FreeRADIUS, Microsoft NPS",
    1883:  "MQTT — Mosquitto, EMQX, HiveMQ",
    1900:  "SSDP / UPnP — miniupnpd, Windows SSDP",
    2000:  "Cisco SCCP / IOS HTTP",
    2049:  "NFS — nfsd, Linux/FreeBSD NFS, Windows Services for NFS",
    2082:  "cPanel HTTP",
    2083:  "cPanel HTTPS",
    2086:  "WHM HTTP",
    2087:  "WHM HTTPS",
    2095:  "cPanel Webmail",
    2096:  "cPanel Webmail (TLS)",
    2181:  "Apache ZooKeeper",
    2222:  "DirectAdmin / SSH alt",
    2375:  "Docker daemon (без TLS — опасно открытым!)",
    2376:  "Docker daemon (TLS)",
    2483:  "Oracle DB (без TLS)",
    2484:  "Oracle DB (TLS)",
    3000:  "Grafana, Node.js dev, Ruby on Rails",
    3128:  "Squid proxy",
    3260:  "iSCSI",
    3268:  "Active Directory Global Catalog",
    3269:  "Active Directory Global Catalog (TLS)",
    3306:  "MySQL / MariaDB",
    3389:  "RDP — Windows Remote Desktop, xrdp, FreeRDP",
    3478:  "STUN/TURN — coturn, Janus",
    3690:  "Subversion (svnserve)",
    4369:  "EPMD — Erlang Port Mapper (RabbitMQ, CouchDB, ejabberd)",
    4444:  "Metasploit Meterpreter (по умолчанию) — подозрительно",
    4500:  "IPsec NAT-T",
    4567:  "Galera replication",
    4789:  "VXLAN",
    4848:  "GlassFish admin",
    5000:  "UPnP / Flask dev / Docker registry / Synology DSM",
    5001:  "Synology DSM HTTPS",
    5060:  "SIP — Asterisk, FreeSWITCH, Kamailio, OpenSIPS",
    5061:  "SIP-TLS",
    5222:  "XMPP-клиент — ejabberd, Prosody, Openfire",
    5269:  "XMPP server-to-server",
    5353:  "mDNS — Avahi, Apple Bonjour, systemd-resolved",
    5355:  "LLMNR — Windows",
    5432:  "PostgreSQL",
    5601:  "Kibana",
    5672:  "AMQP — RabbitMQ, Qpid, ActiveMQ",
    5800:  "VNC over HTTP — RealVNC, TightVNC",
    5900:  "VNC — TigerVNC, RealVNC, TightVNC, x11vnc",
    5938:  "TeamViewer",
    5984:  "Apache CouchDB",
    5985:  "WinRM HTTP",
    5986:  "WinRM HTTPS",
    6000:  "X11-сервер",
    6379:  "Redis",
    6443:  "Kubernetes API server",
    6660:  "IRC",
    6667:  "IRC — UnrealIRCd, InspIRCd",
    6697:  "IRC TLS",
    6881:  "BitTorrent",
    7000:  "Cassandra inter-node / Apple AirPlay",
    7001:  "Oracle WebLogic",
    7077:  "Apache Spark master",
    7547:  "TR-069 / CWMP — модемы провайдеров (атака Mirai)",
    7777:  "iChat / различные игровые серверы",
    8000:  "HTTP-Alt — Django dev, python -m http.server",
    8008:  "HTTP-Alt — IBM HTTP, Matrix homeserver",
    8009:  "AJP — Apache Tomcat (CVE-2020-1938 Ghostcat)",
    8080:  "HTTP-Alt — Tomcat, Jenkins, прокси, веб-админки роутеров",
    8086:  "InfluxDB",
    8088:  "Hadoop YARN ResourceManager UI",
    8089:  "Splunkd",
    8123:  "Home Assistant",
    8200:  "HashiCorp Vault",
    8333:  "Bitcoin core",
    8443:  "HTTPS-Alt — Tomcat, веб-админки, Plesk",
    8530:  "WSUS HTTP",
    8531:  "WSUS HTTPS",
    8649:  "Ganglia",
    8888:  "HTTP-Alt — Jupyter, JIRA, GNU Health",
    9000:  "PHP-FPM, SonarQube, Portainer, MinIO, ClickHouse",
    9042:  "Apache Cassandra CQL",
    9090:  "Prometheus, Cockpit",
    9092:  "Apache Kafka",
    9100:  "Сетевой принтер (HP JetDirect), Prometheus node_exporter",
    9200:  "Elasticsearch HTTP",
    9300:  "Elasticsearch transport",
    9418:  "Git daemon",
    9999:  "Urchin / cPanel WHM",
    10000: "Webmin / Virtualmin / NDMP",
    10050: "Zabbix agent",
    10051: "Zabbix server",
    11211: "Memcached",
    15672: "RabbitMQ management UI",
    16992: "Intel AMT HTTP",
    16993: "Intel AMT HTTPS",
    19132: "Minecraft Bedrock Edition",
    25565: "Minecraft Java Edition",
    27015: "Source-движок (CS, TF2, Garry's Mod)",
    27017: "MongoDB",
    27018: "MongoDB shard",
    27019: "MongoDB config server",
    32400: "Plex Media Server",
    49152: "Windows RPC dynamic / UPnP",
}


# ---------------------------------------------------------------------------
# IANA registry loader
# ---------------------------------------------------------------------------

# ``ports.csv`` is a cleaned-up snapshot of the official IANA Service
# Names and Port Numbers registry — see the project README for the
# build steps. Keeping it as a sibling file (rather than a giant
# Python literal) keeps ``scanner.py`` reasonable to read and lets
# users update the registry without touching code.
PORTS_CSV_PATH: Path = Path(__file__).resolve().parent / "ports.csv"


_PORTS_CACHE: list[tuple[str, str, str, str, str]] | None = None


def load_ports_registry(
    path: Path | str = PORTS_CSV_PATH,
) -> list[tuple[str, str, str, str, str]]:
    """Return the IANA registry rows + curated software annotation.

    Each tuple is ``(port, protocol, service, software, description)``,
    where ``software`` comes from :data:`PORT_SOFTWARE` for known
    ports (and is empty otherwise). ``port`` is kept as a string
    because IANA occasionally registers ranges (e.g. ``"1024-1027"``).
    Result is cached so the GUI can rebuild filters cheaply on every
    keystroke.

    Returns an empty list if the file is missing — the dialog falls
    back to the small built-in :data:`COMMON_PORTS` table in that
    case, so the app stays usable on a stripped-down deployment.
    """
    global _PORTS_CACHE
    if _PORTS_CACHE is not None:
        return _PORTS_CACHE

    p = Path(path)
    rows: list[tuple[str, str, str, str, str]] = []
    if not p.is_file():
        _PORTS_CACHE = rows
        return rows

    try:
        with p.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                port = (r.get("port") or "").strip()
                proto = (r.get("protocol") or "").strip()
                service = (r.get("service") or "").strip()
                desc = (r.get("description") or "").strip()
                if not port:
                    continue
                # Software annotation is only meaningful for a single
                # numeric port — don't try to split ranges across the
                # curated map. The vast majority of ranges in the
                # registry are tiny vendor blocks anyway.
                software = ""
                if port.isdigit():
                    software = PORT_SOFTWARE.get(int(port), "")
                rows.append((port, proto, service, software, desc))
    except OSError:
        # File races / permission issues shouldn't crash the GUI;
        # an empty registry is a survivable fallback.
        rows = []

    # Top up the registry with synthetic rows for ports we have a
    # software note for but which IANA has never formally registered
    # (port 81, Bitcoin/Minecraft/etc.). Without this, searching the
    # tab for "minecraft" or "TeamViewer" comes up empty even though
    # the curated annotation exists.
    have_ports: set[int] = set()
    for r in rows:
        port_str = r[0]
        if port_str.isdigit():
            have_ports.add(int(port_str))

    # Per-port protocol overrides for synthetic entries — defaults to
    # ("tcp",) which covers the majority. UDP-only or dual-protocol
    # cases are listed explicitly so the protocol filter stays honest.
    _SYNTH_PROTOS: dict[int, tuple[str, ...]] = {
        8649:  ("udp",),
        19132: ("udp",),
        27015: ("tcp", "udp"),
        49152: ("tcp", "udp"),
    }
    for port_num, software in PORT_SOFTWARE.items():
        if port_num in have_ports:
            continue
        for proto in _SYNTH_PROTOS.get(port_num, ("tcp",)):
            rows.append((str(port_num), proto, "", software, ""))

    _PORTS_CACHE = rows
    return rows


# Lazy lookup indices over the IANA registry. Held separately from
# ``_PORTS_CACHE`` so the CLI / non-GUI callers don't pay the cost of
# building them, and split into ``(port, proto)`` exact and
# ``port`` any-proto fallback maps so we don't have to mix key types.
_SERVICE_BY_PORT_PROTO: dict[tuple[int, str], str] | None = None
_SERVICE_BY_PORT: dict[int, str] | None = None


def _build_service_indices() -> None:
    global _SERVICE_BY_PORT_PROTO, _SERVICE_BY_PORT
    by_pp: dict[tuple[int, str], str] = {}
    by_p: dict[int, str] = {}
    for p_str, p_proto, service, _sw, _desc in load_ports_registry():
        if not service or not p_str.isdigit():
            continue
        n = int(p_str)
        key = (n, p_proto.lower())
        by_pp.setdefault(key, service)
        # First service we encounter for the port wins as the
        # any-proto fallback. ``ports.csv`` is sorted such that the
        # canonical entry usually appears first.
        by_p.setdefault(n, service)
    _SERVICE_BY_PORT_PROTO = by_pp
    _SERVICE_BY_PORT = by_p


def service_for_port(port: int, proto: str = "tcp") -> str:
    """Return a human-readable service name for ``port``.

    Lookup order:

    1. The built-in :data:`COMMON_PORTS` table — short, capitalised
       Russian-friendly labels (``"SSH"``, ``"HTTP"``, …) that match
       what the rest of the GUI already shows.
    2. The IANA registry loaded from ``ports.csv``. If both ``port``
       and ``proto`` match, that entry wins; otherwise we fall back
       to the first registered service for ``port`` regardless of
       transport.

    Returns ``""`` when the port isn't known. ``proto`` is matched
    case-insensitively against the protocol column of the registry.
    """
    if not (0 <= port <= 65535):
        return ""

    # 1. Curated short labels first — these are what the user sees in
    # the main scan-result table, so showing the same string in the
    # ports dialog keeps the experience consistent.
    common = COMMON_PORTS.get(port)
    if common:
        return common

    # 2. IANA registry, exact (port, proto) match preferred.
    if _SERVICE_BY_PORT_PROTO is None or _SERVICE_BY_PORT is None:
        _build_service_indices()
    assert _SERVICE_BY_PORT_PROTO is not None and _SERVICE_BY_PORT is not None
    exact = _SERVICE_BY_PORT_PROTO.get((port, proto.lower()))
    if exact:
        return exact
    return _SERVICE_BY_PORT.get(port, "")


@dataclass
class Host:
    ip: str
    alive: bool = False
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    open_ports: list[int] = field(default_factory=list)
    response_ms: float | None = None
    ttl: int | None = None                              # raw TTL from ping reply
    os_guess: str = ""                                  # -O: family from TTL
    banners: dict[int, str] = field(default_factory=dict)  # -sV: per-port banner
    port_scan_done: int = 0
    port_scan_total: int = 0
    scan_complete: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["open_ports"] = ",".join(str(p) for p in self.open_ports)
        # Banners are kept as a dict for JSON; flatten to "port=banner;..."
        # for CSV-friendly export. JSON callers can re-parse.
        d["banners"] = ";".join(
            f"{p}={b}" for p, b in sorted(self.banners.items())
        )
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


def ping(
    ip: str, timeout_ms: int = 700
) -> tuple[bool, float | None, int | None]:
    """Send a single ICMP echo request.

    Returns ``(alive, response_ms, ttl)``. ``ttl`` is the value reported
    in the reply line ("TTL=64" / "ttl=64") and is used by ``guess_os_from_ttl``
    when ``-O`` is enabled.
    """
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]

    rc, out = _run(cmd, timeout=(timeout_ms / 1000) + 1.5)
    if rc != 0:
        return False, None, None

    # On Windows `ping` may return 0 even when the host is unreachable
    # (e.g. "Destination host unreachable" message). A real reply always
    # contains "TTL=" — both English and localized output keep this token.
    if IS_WINDOWS and "TTL=" not in out.upper().replace(" ", ""):
        return False, None, None

    # Parse response time. Handles English ("time=12ms", "time<1ms") and
    # localized ("время=12мс", "время<1мс") output by looking for an
    # equals/less sign followed by a number followed by "ms"/"мс".
    match = re.search(r"[=<]\s*([\d.]+)\s*(?:ms|мс)", out, re.IGNORECASE)
    rtt = float(match.group(1)) if match else None

    # TTL is reported as "TTL=64" on Windows (English / Russian) and
    # "ttl=64" on Linux/macOS. Tolerate either case + optional whitespace.
    ttl_match = re.search(r"TTL\s*=\s*(\d+)", out, re.IGNORECASE)
    ttl = int(ttl_match.group(1)) if ttl_match else None
    return True, rtt, ttl


def guess_os_from_ttl(ttl: int | None) -> str:
    """Crude OS family guess from a single TTL value.

    Routers / OSes pick a starting TTL (typically 64, 128 or 255) and
    decrement it by one per hop. On a local LAN scan (1 hop) the value
    seen in the reply is essentially the start value, which gives a
    reliable family hint:

        TTL <= 64   → Linux / macOS / *BSD
        TTL <= 128  → Windows
        TTL <= 255  → Network device (Cisco IOS, routers, printers, ...)

    For multi-hop / Internet scans this is much less reliable and only
    indicates the *family* of the OS that produced the reply.
    """
    if not ttl or ttl <= 0:
        return ""
    if ttl <= 64:
        return "Linux/macOS"
    if ttl <= 128:
        return "Windows"
    return "Сетевое устройство"


# Ports for which a service typically sends a banner immediately on
# connect (no client probe needed). Used by ``grab_banner`` for the
# ``-sV`` flag.
_BANNER_FIRST_PORTS: frozenset[int] = frozenset({
    21, 22, 23, 25, 110, 143, 220, 465, 587, 993, 995, 5900, 6667,
})


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """Return a one-line service banner for ``ip:port``, or "".

    The function is best-effort and never raises. It tries two probes:

    1. Wait briefly for an immediately-pushed banner (works for SSH,
       FTP, SMTP, IMAP, POP3, IRC, VNC and a few more — see
       ``_BANNER_FIRST_PORTS``).
    2. Fall back to a minimal HTTP ``HEAD`` request for everything else;
       this picks up the ``Server:`` header from web servers / HTTP-like
       services running on arbitrary ports.

    The first non-empty line of the response is returned, with control
    characters stripped and length capped at 120 chars so the banner
    fits inline in the GUI.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.connect((ip, port))
            except OSError:
                return ""

            data: bytes = b""
            if port in _BANNER_FIRST_PORTS:
                try:
                    sock.settimeout(timeout)
                    data = sock.recv(2048)
                except (socket.timeout, OSError):
                    data = b""

            if not data:
                # Generic HTTP-style probe; harmless against most other
                # text-protocol services because they just close.
                try:
                    sock.sendall(
                        b"HEAD / HTTP/1.0\r\n"
                        b"Host: " + ip.encode("ascii", "replace") + b"\r\n"
                        b"User-Agent: IPbrowse\r\n\r\n"
                    )
                    sock.settimeout(timeout)
                    chunks: list[bytes] = []
                    deadline_left = timeout
                    while deadline_left > 0:
                        try:
                            chunk = sock.recv(2048)
                        except (socket.timeout, OSError):
                            break
                        if not chunk:
                            break
                        chunks.append(chunk)
                        if sum(len(c) for c in chunks) >= 4096:
                            break
                    data = b"".join(chunks)
                except OSError:
                    return ""
    except OSError:
        return ""

    if not data:
        return ""

    text = data.decode("utf-8", errors="replace")

    # Prefer "Server:" header for HTTP responses.
    server_match = re.search(
        r"^Server:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE
    )
    if server_match:
        line = server_match.group(1)
    else:
        line = next(
            (ln for ln in text.splitlines() if ln.strip()),
            "",
        )

    # Strip control chars and clamp.
    line = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", line).strip()
    if len(line) > 120:
        line = line[:117] + "..."
    return line


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
    arp_discovery: bool = False,
    os_detect: bool = False,
    version_detect: bool = False,
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

    Optional flags:
      ``arp_discovery``   (-PR) — also mark hosts visible in the system
                                  ARP cache as alive (catches ICMP-blocking
                                  devices that still answer ARP).
      ``os_detect``       (-O)  — set ``host.os_guess`` from the ping TTL.
      ``version_detect``  (-sV) — best-effort banner grab on every open
                                  port, stored in ``host.banners``.
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
        last_ttl: int | None = None
        for _ in range(attempts):
            alive, rtt, ttl = ping(ip, timeout_ms=ping_timeout_ms)
            if alive:
                return Host(
                    ip=ip,
                    alive=True,
                    response_ms=rtt,
                    ttl=ttl,
                    os_guess=guess_os_from_ttl(ttl) if os_detect else "",
                    port_scan_total=total_ports,
                    scan_complete=False,
                )
            last_ttl = ttl  # almost always None, kept for completeness
        return Host(
            ip=ip,
            alive=False,
            response_ms=None,
            ttl=last_ttl,
            port_scan_total=total_ports,
            scan_complete=True,
        )

    alive_hosts: list[Host] = []
    dead_hosts: list[Host] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_check, ip): ip for ip in targets}
        for fut in as_completed(futures):
            if cancel_event is not None and cancel_event.is_set():
                break
            host = fut.result()
            if host.alive:
                yield host
                alive_hosts.append(host)
            else:
                # With -PR we may resurrect dead hosts below, so defer
                # yielding them until after the ARP cache check. Without
                # -PR they are yielded immediately to keep the historical
                # phase-1 streaming behaviour intact.
                if arp_discovery:
                    dead_hosts.append(host)
                else:
                    yield host

    if cancel_event is not None and cancel_event.is_set():
        return

    # -PR: re-check the ICMP-dead hosts against the system ARP cache.
    # An entry there means a device with that IP recently answered ARP
    # on this LAN, even if it silently drops ICMP echo requests.
    arp_cache: dict[str, str] = {}
    if arp_discovery or detect_mac:
        arp_cache = _parse_arp_table()
    if arp_discovery:
        for host in dead_hosts:
            if host.ip in arp_cache:
                host.alive = True
                host.scan_complete = False
                host.port_scan_total = total_ports
                host.mac = arp_cache[host.ip]
                if host.mac and detect_mac:
                    host.vendor = lookup_vendor(host.mac)
                yield host
                alive_hosts.append(host)
            else:
                yield host

    # Phase 2: enrich alive hosts (hostname, MAC, vendor, ports)
    def _enrich(host: Host) -> Host:
        if cancel_event is not None and cancel_event.is_set():
            host.scan_complete = True
            return host
        if resolve_hostnames:
            host.hostname = resolve_hostname(host.ip)
        if detect_mac:
            # Don't clobber a MAC already set by the ARP-discovery step.
            if not host.mac:
                host.mac = get_mac(host.ip, arp_cache)
            if host.mac and not host.vendor:
                host.vendor = lookup_vendor(host.mac)
        if on_host_update:
            on_host_update(Host(
                ip=host.ip, alive=host.alive, hostname=host.hostname,
                mac=host.mac, vendor=host.vendor, response_ms=host.response_ms,
                ttl=host.ttl, os_guess=host.os_guess,
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
            # -sV: per-port banner grab on whatever came back open.
            if version_detect and host.open_ports and not (
                cancel_event is not None and cancel_event.is_set()
            ):
                bw = min(port_workers, max(1, len(host.open_ports)))
                with ThreadPoolExecutor(max_workers=bw) as bpool:
                    bfutures = {
                        bpool.submit(grab_banner, host.ip, p, port_timeout * 2): p
                        for p in host.open_ports
                    }
                    for bf in as_completed(bfutures):
                        banner = bf.result()
                        if banner:
                            host.banners[bfutures[bf]] = banner
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
