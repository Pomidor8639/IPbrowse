package com.ipbrowse.scanner

import android.content.Context
import com.ipbrowse.R
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets

/**
 * Реестр портов: COMMON_PORTS (короткие имена), TOP_PORTS (top-100 nmap) и
 * PORT_SOFTWARE (типичный софт), плюс ленивая загрузка IANA-реестра из
 * `res/raw/ports.csv`. Один-в-один с `scanner.py`, только переписано на
 * Kotlin и адаптировано под ресурсы Android.
 */
object Ports {

    val COMMON_PORTS: Map<Int, String> = linkedMapOf(
        21 to "FTP",
        22 to "SSH",
        23 to "Telnet",
        25 to "SMTP",
        53 to "DNS",
        80 to "HTTP",
        110 to "POP3",
        139 to "NetBIOS",
        143 to "IMAP",
        443 to "HTTPS",
        445 to "SMB",
        3306 to "MySQL",
        3389 to "RDP",
        5432 to "PostgreSQL",
        5900 to "VNC",
        8080 to "HTTP-Alt",
        8443 to "HTTPS-Alt",
    )

    val TOP_PORTS: IntArray = intArrayOf(
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

    /** Курированная карта port -> типичный софт (см. PORT_SOFTWARE в scanner.py). */
    val PORT_SOFTWARE: Map<Int, String> = linkedMapOf(
        20 to "FTP-данные — vsftpd, ProFTPD, Pure-FTPd, IIS",
        21 to "FTP — vsftpd, ProFTPD, Pure-FTPd, FileZilla Server, IIS FTP",
        22 to "SSH / SFTP — OpenSSH, Dropbear, libssh, Bitvise SSH",
        23 to "Telnet — telnetd; маршрутизаторы и IoT (опасно открытым)",
        25 to "SMTP — Postfix, Exim, Sendmail, Microsoft Exchange",
        37 to "Time protocol",
        43 to "WHOIS",
        53 to "DNS — BIND, Unbound, dnsmasq, PowerDNS, systemd-resolved",
        67 to "DHCP-сервер — ISC DHCP, dnsmasq, Kea, Windows DHCP",
        68 to "DHCP-клиент",
        69 to "TFTP — tftpd-hpa, atftp, SolarWinds TFTP",
        79 to "Finger",
        80 to "HTTP — Apache httpd, nginx, IIS, Caddy, lighttpd, Tomcat",
        81 to "HTTP-Alt — веб-админки роутеров, Tor",
        88 to "Kerberos KDC — MIT Kerberos, Heimdal, Active Directory",
        102 to "Siemens S7 PLC",
        110 to "POP3 — Dovecot, Cyrus IMAP, Courier, Microsoft Exchange",
        111 to "RPCbind / portmap (NFS, NIS)",
        113 to "Ident",
        119 to "NNTP — INN, leafnode",
        123 to "NTP — ntpd, chrony, Windows w32time",
        135 to "Microsoft RPC Endpoint Mapper (DCE/RPC)",
        137 to "NetBIOS Name — Samba nmbd, Windows",
        138 to "NetBIOS Datagram — Samba nmbd, Windows",
        139 to "NetBIOS Session — Samba smbd, Windows File Sharing",
        143 to "IMAP — Dovecot, Cyrus, Courier, Microsoft Exchange",
        161 to "SNMP — Net-SNMP, оборудование Cisco / Juniper / MikroTik",
        162 to "SNMP-trap — Net-SNMP, Zabbix, Nagios, PRTG",
        179 to "BGP — FRRouting, Quagga, BIRD, Cisco IOS, Juniper",
        194 to "IRC — UnrealIRCd, InspIRCd, ircd-hybrid",
        389 to "LDAP — OpenLDAP, Active Directory, 389 Directory Server",
        427 to "SLP — OpenSLP",
        443 to "HTTPS — Apache, nginx, IIS, Caddy + TLS, HTTP/2, HTTP/3",
        445 to "SMB — Samba smbd, Windows File Sharing (атаки EternalBlue)",
        465 to "SMTPS — Postfix, Exim, Sendmail",
        500 to "IKE/IPsec — strongSwan, Libreswan, Windows IKE",
        502 to "Modbus TCP — промышленные ПЛК",
        513 to "rlogin",
        514 to "Syslog / rsh — rsyslog, syslog-ng",
        515 to "LPD — CUPS, lpd",
        520 to "RIP — FRRouting, gated",
        523 to "IBM DB2",
        546 to "DHCPv6 client",
        547 to "DHCPv6 server — ISC DHCP, Kea",
        548 to "AFP — netatalk (Apple File Sharing)",
        554 to "RTSP — Live555, GStreamer; IP-камеры (Hikvision, Dahua)",
        587 to "SMTP submission — Postfix, Exim, Sendmail",
        593 to "RPC over HTTP — Microsoft Exchange (Outlook Anywhere)",
        623 to "IPMI — BMC: Dell iDRAC, HPE iLO, Supermicro",
        631 to "IPP / CUPS — печать",
        636 to "LDAPS — OpenLDAP, Active Directory + TLS",
        873 to "rsync (демон)",
        902 to "VMware ESXi authd / vCenter",
        989 to "FTPS-данные",
        990 to "FTPS-управление — vsftpd, FileZilla Server, IIS",
        993 to "IMAPS — Dovecot, Microsoft Exchange",
        995 to "POP3S — Dovecot, Microsoft Exchange",
        1025 to "Windows RPC dynamic / Microsoft network blackjack",
        1080 to "SOCKS-прокси — Dante, 3proxy",
        1194 to "OpenVPN",
        1352 to "Lotus Notes / Domino",
        1433 to "Microsoft SQL Server",
        1434 to "Microsoft SQL Server browser (UDP)",
        1521 to "Oracle DB listener",
        1701 to "L2TP — strongSwan, xl2tpd",
        1723 to "PPTP",
        1812 to "RADIUS auth — FreeRADIUS, Cisco ACS, Microsoft NPS",
        1813 to "RADIUS accounting — FreeRADIUS, Microsoft NPS",
        1883 to "MQTT — Mosquitto, EMQX, HiveMQ",
        1900 to "SSDP / UPnP — miniupnpd, Windows SSDP",
        2000 to "Cisco SCCP / IOS HTTP",
        2049 to "NFS — nfsd, Linux/FreeBSD NFS, Windows Services for NFS",
        2082 to "cPanel HTTP",
        2083 to "cPanel HTTPS",
        2086 to "WHM HTTP",
        2087 to "WHM HTTPS",
        2095 to "cPanel Webmail",
        2096 to "cPanel Webmail (TLS)",
        2181 to "Apache ZooKeeper",
        2222 to "DirectAdmin / SSH alt",
        2375 to "Docker daemon (без TLS — опасно открытым!)",
        2376 to "Docker daemon (TLS)",
        2483 to "Oracle DB (без TLS)",
        2484 to "Oracle DB (TLS)",
        3000 to "Grafana, Node.js dev, Ruby on Rails",
        3128 to "Squid proxy",
        3260 to "iSCSI",
        3268 to "Active Directory Global Catalog",
        3269 to "Active Directory Global Catalog (TLS)",
        3306 to "MySQL / MariaDB",
        3389 to "RDP — Windows Remote Desktop, xrdp, FreeRDP",
        3478 to "STUN/TURN — coturn, Janus",
        3690 to "Subversion (svnserve)",
        4369 to "EPMD — Erlang Port Mapper (RabbitMQ, CouchDB, ejabberd)",
        4444 to "Metasploit Meterpreter (по умолчанию) — подозрительно",
        4500 to "IPsec NAT-T",
        4567 to "Galera replication",
        4789 to "VXLAN",
        4848 to "GlassFish admin",
        5000 to "UPnP / Flask dev / Docker registry / Synology DSM",
        5001 to "Synology DSM HTTPS",
        5060 to "SIP — Asterisk, FreeSWITCH, Kamailio, OpenSIPS",
        5061 to "SIP-TLS",
        5222 to "XMPP-клиент — ejabberd, Prosody, Openfire",
        5269 to "XMPP server-to-server",
        5353 to "mDNS — Avahi, Apple Bonjour, systemd-resolved",
        5355 to "LLMNR — Windows",
        5432 to "PostgreSQL",
        5601 to "Kibana",
        5672 to "AMQP — RabbitMQ, Qpid, ActiveMQ",
        5800 to "VNC over HTTP — RealVNC, TightVNC",
        5900 to "VNC — TigerVNC, RealVNC, TightVNC, x11vnc",
        5938 to "TeamViewer",
        5984 to "Apache CouchDB",
        5985 to "WinRM HTTP",
        5986 to "WinRM HTTPS",
        6000 to "X11-сервер",
        6379 to "Redis",
        6443 to "Kubernetes API server",
        6660 to "IRC",
        6667 to "IRC — UnrealIRCd, InspIRCd",
        6697 to "IRC TLS",
        6881 to "BitTorrent",
        7000 to "Cassandra inter-node / Apple AirPlay",
        7001 to "Oracle WebLogic",
        7077 to "Apache Spark master",
        7547 to "TR-069 / CWMP — модемы провайдеров (атака Mirai)",
        7777 to "iChat / различные игровые серверы",
        8000 to "HTTP-Alt — Django dev, python -m http.server",
        8008 to "HTTP-Alt — IBM HTTP, Matrix homeserver",
        8009 to "AJP — Apache Tomcat (CVE-2020-1938 Ghostcat)",
        8080 to "HTTP-Alt — Tomcat, Jenkins, прокси, веб-админки роутеров",
        8086 to "InfluxDB",
        8088 to "Hadoop YARN ResourceManager UI",
        8089 to "Splunkd",
        8123 to "Home Assistant",
        8200 to "HashiCorp Vault",
        8333 to "Bitcoin core",
        8443 to "HTTPS-Alt — Tomcat, веб-админки, Plesk",
        8530 to "WSUS HTTP",
        8531 to "WSUS HTTPS",
        8649 to "Ganglia",
        8888 to "HTTP-Alt — Jupyter, JIRA, GNU Health",
        9000 to "PHP-FPM, SonarQube, Portainer, MinIO, ClickHouse",
        9042 to "Apache Cassandra CQL",
        9090 to "Prometheus, Cockpit",
        9092 to "Apache Kafka",
        9100 to "Сетевой принтер (HP JetDirect), Prometheus node_exporter",
        9200 to "Elasticsearch HTTP",
        9300 to "Elasticsearch transport",
        9418 to "Git daemon",
        9999 to "Urchin / cPanel WHM",
        10000 to "Webmin / Virtualmin / NDMP",
        10050 to "Zabbix agent",
        10051 to "Zabbix server",
        11211 to "Memcached",
        15672 to "RabbitMQ management UI",
        16992 to "Intel AMT HTTP",
        16993 to "Intel AMT HTTPS",
        19132 to "Minecraft Bedrock Edition",
        25565 to "Minecraft Java Edition",
        27015 to "Source-движок (CS, TF2, Garry's Mod)",
        27017 to "MongoDB",
        27018 to "MongoDB shard",
        27019 to "MongoDB config server",
        32400 to "Plex Media Server",
        49152 to "Windows RPC dynamic / UPnP",
    )

    /** Строка реестра IANA + курированная аннотация по софту. */
    data class Entry(
        val portString: String,
        val protocol: String,
        val service: String,
        val software: String,
        val description: String,
    )

    @Volatile
    private var registryCache: List<Entry>? = null

    @Volatile
    private var serviceByPortProto: Map<Pair<Int, String>, String>? = null

    @Volatile
    private var serviceByPort: Map<Int, String>? = null

    /**
     * Загрузка `res/raw/ports.csv`. Кешируется в памяти процесса.
     */
    fun loadRegistry(context: Context): List<Entry> {
        registryCache?.let { return it }
        synchronized(this) {
            registryCache?.let { return it }
            val rows = ArrayList<Entry>(12000)
            val have = HashSet<Int>(12000)
            try {
                context.resources.openRawResource(R.raw.ports).use { raw ->
                    BufferedReader(InputStreamReader(raw, StandardCharsets.UTF_8)).use { br ->
                        val header = br.readLine() ?: return@use
                        val cols = header.split(",").map { it.trim() }
                        val idxPort = cols.indexOf("port")
                        val idxProto = cols.indexOf("protocol")
                        val idxService = cols.indexOf("service")
                        val idxDesc = cols.indexOf("description")
                        while (true) {
                            val line = br.readLine() ?: break
                            val parts = parseCsvLine(line)
                            if (parts.size <= idxPort) continue
                            val port = parts.getOrNull(idxPort)?.trim().orEmpty()
                            if (port.isEmpty()) continue
                            val proto = parts.getOrNull(idxProto)?.trim().orEmpty()
                            val service = parts.getOrNull(idxService)?.trim().orEmpty()
                            val desc = parts.getOrNull(idxDesc)?.trim().orEmpty()
                            val software = port.toIntOrNull()?.let { PORT_SOFTWARE[it] }.orEmpty()
                            rows.add(Entry(port, proto, service, software, desc))
                            port.toIntOrNull()?.let(have::add)
                        }
                    }
                }
            } catch (_: Throwable) {
                // Если ports.csv по какой-то причине не читается — UI деградирует
                // до COMMON_PORTS, как и десктоп.
            }
            // Синтетические записи для портов из PORT_SOFTWARE, которых нет в IANA.
            val synthProto = mapOf(
                8649 to listOf("udp"),
                19132 to listOf("udp"),
                27015 to listOf("tcp", "udp"),
                49152 to listOf("tcp", "udp"),
            )
            for ((port, software) in PORT_SOFTWARE) {
                if (port in have) continue
                val protos = synthProto[port] ?: listOf("tcp")
                for (p in protos) rows.add(Entry(port.toString(), p, "", software, ""))
            }
            registryCache = rows
            return rows
        }
    }

    private fun buildServiceIndices(context: Context) {
        val byPP = HashMap<Pair<Int, String>, String>()
        val byP = HashMap<Int, String>()
        for (e in loadRegistry(context)) {
            if (e.service.isEmpty()) continue
            val n = e.portString.toIntOrNull() ?: continue
            val key = n to e.protocol.lowercase()
            byPP.putIfAbsent(key, e.service)
            byP.putIfAbsent(n, e.service)
        }
        serviceByPortProto = byPP
        serviceByPort = byP
    }

    /**
     * Имя сервиса для порта — сначала ищется в COMMON_PORTS (короткие лейблы),
     * затем в IANA (точное (port, proto) совпадение, потом fallback на любой
     * протокол).
     */
    fun serviceForPort(context: Context, port: Int, proto: String = "tcp"): String {
        if (port !in 0..65535) return ""
        COMMON_PORTS[port]?.let { return it }
        if (serviceByPortProto == null || serviceByPort == null) buildServiceIndices(context)
        serviceByPortProto?.get(port to proto.lowercase())?.let { return it }
        return serviceByPort?.get(port).orEmpty()
    }

    /**
     * Минимальный CSV-парсер: обрабатывает кавычки и удвоенные кавычки внутри
     * полей. ports.csv — простой и нам этого достаточно.
     */
    private fun parseCsvLine(line: String): List<String> {
        val out = ArrayList<String>()
        val sb = StringBuilder()
        var inQuotes = false
        var i = 0
        while (i < line.length) {
            val c = line[i]
            when {
                inQuotes -> {
                    if (c == '"') {
                        if (i + 1 < line.length && line[i + 1] == '"') {
                            sb.append('"'); i++
                        } else inQuotes = false
                    } else sb.append(c)
                }
                c == ',' -> {
                    out.add(sb.toString()); sb.setLength(0)
                }
                c == '"' -> inQuotes = true
                else -> sb.append(c)
            }
            i++
        }
        out.add(sb.toString())
        return out
    }
}
