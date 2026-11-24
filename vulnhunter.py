#!/usr/bin/env python3
"""
vulnhunter - TCP service discovery with version-aware CVE correlation.

CVEs are matched against an extracted product AND version using the CPE ranges
in the NVD record, not against a bare service name. A service whose version
could not be determined is reported as such and is not given a CVE list, because
a CVE list for "ssh" is noise, not evidence.

Authorized use only. This tool sends traffic to its targets.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("requests is required: pip install -r requirements.txt", file=sys.stderr)
    raise

try:
    from rich.console import Console
    from rich.table import Table
    _console: Optional["Console"] = Console(stderr=True)
except ImportError:
    _console = None

VERSION = "2.0.0"
UA = "vulnhunter/2.0 (+authorized security assessment)"
CIRCL_API = "https://cve.circl.lu/api/search"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# nmap's actual top-100 TCP ports.
TOP_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157,
]

EXTENDED_EXTRA = [
    1, 3, 17, 19, 20, 24, 42, 49, 70, 85, 99, 109, 125, 146, 161, 163, 193,
    209, 256, 280, 301, 306, 311, 340, 366, 406, 416, 425, 458, 481, 497, 500,
    524, 541, 545, 555, 563, 593, 616, 625, 636, 666, 684, 700, 705, 711, 777,
    800, 808, 843, 880, 888, 898, 900, 901, 902, 903, 911, 981, 987, 992, 999,
    1000, 1002, 1030, 1050, 1080, 1100, 1105, 1111, 1123, 1200, 1234, 1311,
    1352, 1400, 1434, 1500, 1521, 1600, 1701, 1717, 1801, 1935, 1998, 2002,
    2005, 2030, 2103, 2105, 2107, 2222, 2301, 2381, 2383, 2525, 2601, 2604,
    2638, 2809, 3001, 3003, 3005, 3007, 3011, 3017, 3031, 3052, 3071, 3211,
    3260, 3261, 3268, 3269, 3283, 3300, 3301, 3333, 3351, 3367, 3404, 3476,
    3690, 3703, 3851, 3871, 3889, 3918, 3920, 3945, 3971, 4000, 4001, 4002,
    4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4279, 4444,
    4550, 4567, 4662, 4848, 4900, 5002, 5003, 5004, 5009, 5030, 5033, 5050,
    5054, 5080, 5087, 5100, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5269,
    5280, 5298, 5405, 5414, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566,
    5633, 5678, 5718, 5730, 5801, 5810, 5815, 5822, 5825, 5850, 5859, 5862,
    5877, 5901, 5902, 5903, 5910, 5915, 5922, 5925, 5950, 5952, 5959, 5960,
    5961, 5962, 5987, 5988, 5989, 5998, 5999, 6002, 6003, 6004, 6005, 6006,
    6007, 6009, 6025, 6059, 6100, 6106, 6112, 6123, 6129, 6156, 6346, 6389,
    6502, 6510, 6543, 6547, 6565, 6580, 6666, 6667, 6668, 6669, 6689, 6692,
    6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002,
    7004, 7007, 7019, 7025, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443,
    7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921,
    7937, 7938, 7999, 8001, 8002, 8007, 8010, 8011, 8021, 8022, 8031, 8042,
    8045, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099,
    8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292,
    8300, 8333, 8383, 8400, 8402, 8500, 8600, 8649, 8651, 8652, 8654, 8701,
    8800, 8873, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040,
    9050, 9071, 9080, 9081, 9090, 9091, 9099, 9101, 9102, 9103, 9110, 9111,
    9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575,
    9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929,
    9943, 9944, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025,
    10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628,
    11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782,
    14000, 14238, 14441, 15000, 15002, 15003, 15660, 16000, 16001, 16012,
    16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101,
    18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005,
    20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734,
    25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000,
    30718, 30951, 31038, 31337, 32769, 32770, 32771, 32772, 32773, 32774,
    32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784,
    32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911,
    41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49158, 49159,
    49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000,
    50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103,
    51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555,
    55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900,
    62078, 63331, 64623, 64680, 65000, 65129, 65389,
]

PORT_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "smtp-submission", 631: "ipp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 3000: "http-alt",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    5985: "winrm", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}

TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443, 44443, 60443, 50636}

# --------------------------------------------------------------------------
# Version fingerprints: banner regex -> (vendor, product, version)
# --------------------------------------------------------------------------

@dataclass
class Fingerprint:
    name: str
    rx: re.Pattern
    vendor: str
    product: str


FINGERPRINTS = [
    Fingerprint("OpenSSH", re.compile(r"OpenSSH[_ ]([0-9]+\.[0-9]+(?:p[0-9]+)?)", re.I),
                "openbsd", "openssh"),
    Fingerprint("Apache httpd", re.compile(r"Apache/([0-9]+\.[0-9]+\.[0-9]+)", re.I),
                "apache", "http_server"),
    Fingerprint("nginx", re.compile(r"nginx/([0-9]+\.[0-9]+\.[0-9]+)", re.I),
                "f5", "nginx"),
    Fingerprint("Microsoft IIS", re.compile(r"Microsoft-IIS/([0-9]+\.[0-9]+)", re.I),
                "microsoft", "internet_information_services"),
    Fingerprint("OpenSSL", re.compile(r"OpenSSL/([0-9]+\.[0-9]+\.[0-9]+[a-z]?)", re.I),
                "openssl", "openssl"),
    Fingerprint("ProFTPD", re.compile(r"ProFTPD\s+([0-9]+\.[0-9]+\.[0-9]+)", re.I),
                "proftpd", "proftpd"),
    Fingerprint("vsftpd", re.compile(r"vsftpd\s+([0-9]+\.[0-9]+\.[0-9]+)", re.I),
                "beasts", "vsftpd"),
    Fingerprint("Pure-FTPd", re.compile(r"Pure-FTPd\s+\[?([0-9]+\.[0-9]+\.[0-9]+)", re.I),
                "pureftpd", "pure-ftpd"),
    Fingerprint("Postfix", re.compile(r"Postfix.*?([0-9]+\.[0-9]+\.[0-9]+)", re.I),
                "postfix", "postfix"),
    Fingerprint("Exim", re.compile(r"Exim\s+([0-9]+\.[0-9]+)", re.I), "exim", "exim"),
    Fingerprint("Dovecot", re.compile(r"Dovecot[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)", re.I),
                "dovecot", "dovecot"),
    Fingerprint("MySQL", re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)[-\w]*MariaDB", re.I),
                "mariadb", "mariadb"),
    Fingerprint("MySQL", re.compile(r"\x00?([5-8]\.[0-9]+\.[0-9]+)"), "oracle", "mysql"),
    Fingerprint("PostgreSQL", re.compile(r"PostgreSQL\s+([0-9]+\.[0-9]+)", re.I),
                "postgresql", "postgresql"),
    Fingerprint("Redis", re.compile(r"redis_version:([0-9]+\.[0-9]+\.[0-9]+)", re.I),
                "redis", "redis"),
    Fingerprint("Elasticsearch", re.compile(r'"number"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'),
                "elastic", "elasticsearch"),
    Fingerprint("Jetty", re.compile(r"Jetty\(([0-9]+\.[0-9]+\.[0-9]+)", re.I),
                "eclipse", "jetty"),
    Fingerprint("Apache Tomcat", re.compile(r"Tomcat/([0-9]+\.[0-9]+\.[0-9]+)", re.I),
                "apache", "tomcat"),
    Fingerprint("PHP", re.compile(r"PHP/([0-9]+\.[0-9]+\.[0-9]+)", re.I), "php", "php"),
    Fingerprint("Lighttpd", re.compile(r"lighttpd/([0-9]+\.[0-9]+\.[0-9]+)", re.I),
                "lighttpd", "lighttpd"),
    Fingerprint("Samba", re.compile(r"Samba\s+([0-9]+\.[0-9]+\.[0-9]+)", re.I),
                "samba", "samba"),
]


def fingerprint(text: str) -> Optional[tuple[str, str, str, str]]:
    """Return (label, vendor, product, version) for the first fingerprint hit."""
    for fp in FINGERPRINTS:
        m = fp.rx.search(text)
        if m:
            return fp.name, fp.vendor, fp.product, m.group(1)
    return None


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

# Protocol-specific openers. A bare "\r\n" gets you nothing from HTTP or TLS.
PROBES: dict[int, bytes] = {
    80: b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: " + UA.encode() + b"\r\n\r\n",
    3306: b"",       # MySQL server greets first
    6379: b"INFO\r\n",
    11211: b"version\r\n",
    9200: b"GET / HTTP/1.0\r\n\r\n",
}
HTTP_LIKE = {80, 81, 591, 2080, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9080}


@dataclass
class Service:
    host: str
    port: int
    state: str = "closed"
    hint: Optional[str] = None
    banner: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    vendor: Optional[str] = None
    cpe: Optional[str] = None
    tls: bool = False
    tls_subject: Optional[str] = None
    tls_issuer: Optional[str] = None
    tls_expires: Optional[str] = None
    tls_sans: list[str] = field(default_factory=list)
    http_title: Optional[str] = None
    http_server: Optional[str] = None
    cves: list[dict] = field(default_factory=list)
    cve_confidence: str = "none"
    notes: list[str] = field(default_factory=list)


TITLE_RX = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def grab_tls(host: str, port: int, timeout: float) -> tuple[Optional[dict], Optional[str]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return ss.getpeercert(), ss.version()
    except (OSError, ssl.SSLError, ValueError):
        return None, None


def scan_port(host: str, port: int, timeout: float, banners: bool) -> Service:
    svc = Service(host=host, port=port, hint=PORT_HINTS.get(port))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        rc = sock.connect_ex((host, port))
    except OSError:
        return svc
    if rc != 0:
        try:
            sock.close()
        except OSError:
            pass
        return svc
    svc.state = "open"
    if not banners:
        sock.close()
        return svc

    # TLS first where it is expected - a plaintext read on 443 returns nothing.
    if port in TLS_PORTS:
        sock.close()
        cert, tlsver = grab_tls(host, port, timeout)
        svc.tls = cert is not None or tlsver is not None
        if tlsver:
            svc.notes.append(f"TLS {tlsver}")
        if cert:
            subj = {k: v for t in cert.get("subject", ()) for k, v in t}
            iss = {k: v for t in cert.get("issuer", ()) for k, v in t}
            svc.tls_subject = subj.get("commonName")
            svc.tls_issuer = iss.get("organizationName") or iss.get("commonName")
            svc.tls_expires = cert.get("notAfter")
            svc.tls_sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
        _http_probe(svc, host, port, timeout, tls=True)
        return svc

    try:
        probe = PROBES.get(port)
        if probe is None and port in HTTP_LIKE:
            probe = PROBES[80]
        if probe:
            sock.sendall(probe)
        data = sock.recv(4096)
        svc.banner = data.decode("utf-8", errors="replace").strip()[:1000] or None
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if svc.banner:
        _parse_http(svc, svc.banner)
    return svc


def _http_probe(svc: Service, host: str, port: int, timeout: float, tls: bool) -> None:
    scheme = "https" if tls else "http"
    try:
        r = requests.get(f"{scheme}://{host}:{port}/", timeout=timeout, verify=False,
                         headers={"User-Agent": UA}, allow_redirects=False)
    except requests.RequestException:
        return
    svc.http_server = r.headers.get("Server")
    hdr = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    svc.banner = (svc.banner or "") + hdr
    body = r.text[:20000] if r.text else ""
    m = TITLE_RX.search(body)
    if m:
        svc.http_title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
    _apply_fp(svc, hdr + "\n" + body[:2000])


def _parse_http(svc: Service, banner: str) -> None:
    m = re.search(r"^Server:\s*(.+)$", banner, re.I | re.M)
    if m:
        svc.http_server = m.group(1).strip()
    m = TITLE_RX.search(banner)
    if m:
        svc.http_title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
    _apply_fp(svc, banner)


def _apply_fp(svc: Service, text: str) -> None:
    got = fingerprint(text)
    if got:
        label, vendor, product, ver = got
        svc.vendor, svc.product, svc.version = vendor, product, ver
        svc.cpe = f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
        svc.notes.append(f"{label} {ver}")


# --------------------------------------------------------------------------
# CVE correlation
# --------------------------------------------------------------------------

_cve_cache: dict[str, list[dict]] = {}
_cve_total: dict[str, int] = {}
_cve_lock = threading.Lock()
_last_call = [0.0]


def _version_tuple(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0
                 for x in re.split(r"[._p\-]", v) if x != "")


def _cpe_applies(cpe_match: dict, version: str) -> bool:
    """Decide whether a CPE node covers the detected version."""
    crit = cpe_match.get("criteria", "")
    parts = crit.split(":")
    cpe_ver = parts[5] if len(parts) > 5 else "*"
    vt = _version_tuple(version)

    lo_i = cpe_match.get("versionStartIncluding")
    lo_e = cpe_match.get("versionStartExcluding")
    hi_i = cpe_match.get("versionEndIncluding")
    hi_e = cpe_match.get("versionEndExcluding")

    if any([lo_i, lo_e, hi_i, hi_e]):
        if lo_i and vt < _version_tuple(lo_i):
            return False
        if lo_e and vt <= _version_tuple(lo_e):
            return False
        if hi_i and vt > _version_tuple(hi_i):
            return False
        if hi_e and vt >= _version_tuple(hi_e):
            return False
        return True
    if cpe_ver in ("*", "-"):
        return False          # matches everything: too broad to be evidence
    return _version_tuple(cpe_ver) == vt


def _fetch_cve_pages(session: requests.Session, vendor: str, product: str,
                     pages: int, rate: float, timeout: float) -> tuple[list[dict], int]:
    """Fetch up to `pages` pages. The API caps page_size at 10 and ignores any
    larger value, so coverage is bounded on purpose rather than silently partial;
    the returned total lets the caller say how much of the set was examined."""
    items: list[dict] = []
    total = 0
    for page in range(1, max(1, pages) + 1):
        with _cve_lock:
            delta = time.monotonic() - _last_call[0]
            if delta < rate:
                time.sleep(rate - delta)
            _last_call[0] = time.monotonic()
        try:
            r = session.get(f"{CIRCL_API}/{vendor}/{product}",
                            params={"page": page}, timeout=timeout)
            if r.status_code != 200:
                break
            payload = r.json()
        except (requests.RequestException, json.JSONDecodeError):
            break
        total = payload.get("total_count", total) or total
        raw = payload.get("results", {})
        before = len(items)
        for _source, rows in (raw.items() if isinstance(raw, dict) else []):
            for row in rows or []:
                obj = row[1] if isinstance(row, list) and len(row) > 1 else row
                if isinstance(obj, dict) and obj.get("id"):
                    items.append(obj)
        if len(items) == before:
            break      # empty page: end of results
    return items, total


def _nvd_metrics(cve: dict) -> tuple[Optional[float], str]:
    metrics = cve.get("metrics", {}) or {}
    for mk in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(mk):
            entry = metrics[mk][0]
            cd = entry.get("cvssData", {})
            return cd.get("baseScore"), (cd.get("baseSeverity")
                                         or entry.get("baseSeverity") or "UNKNOWN").upper()
    return None, "UNKNOWN"


def lookup_cves_nvd(session: requests.Session, vendor: str, product: str, version: str,
                    limit: int, timeout: float, max_results: int = 200
                    ) -> tuple[list[dict], str]:
    """Query NVD with virtualMatchString so NVD performs the version match.

    This is far more accurate than fetching every CVE for a product and matching
    CPE ranges client-side: NVD applies the official configuration data and
    returns only the CVEs whose ranges actually cover this version.

    Set NVD_API_KEY to raise the rate limit from 5 to 50 requests per 30s.
    """
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}"
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    rate = 0.8 if api_key else 6.5          # stay inside NVD's published limits
    headers = {"apiKey": api_key} if api_key else {}

    out: list[dict] = []
    start, total = 0, None
    while True:
        with _cve_lock:
            delta = time.monotonic() - _last_call[0]
            if delta < rate:
                time.sleep(rate - delta)
            _last_call[0] = time.monotonic()
        try:
            r = session.get(
                NVD_API,
                params={"virtualMatchString": cpe, "resultsPerPage": 100,
                        "startIndex": start},
                headers=headers, timeout=timeout)
            if r.status_code == 403:
                return [], "nvd-rate-limited"
            if r.status_code != 200:
                return [], f"nvd-http-{r.status_code}"
            payload = r.json()
        except (requests.RequestException, json.JSONDecodeError):
            return [], "nvd-unreachable"

        total = payload.get("totalResults", 0) if total is None else total
        vulns = payload.get("vulnerabilities", []) or []
        if not vulns:
            break
        for v in vulns:
            cve = v.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            score, sev = _nvd_metrics(cve)
            desc = ""
            for d in cve.get("descriptions", []) or []:
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:220]
                    break
            out.append({"id": cid, "cvss": score, "severity": sev,
                        "summary": desc,
                        "status": cve.get("vulnStatus")})
        start += len(vulns)
        if start >= min(total or 0, max_results):
            break

    out.sort(key=lambda c: (-(c["cvss"] or 0), c["id"]))
    conf = (f"nvd-version-match ({len(out)} of {total} affecting {version})"
            if out else f"nvd-no-match (0 of {total or 0})")
    return out[:limit], conf


def lookup_cves(session: requests.Session, vendor: str, product: str, version: str,
                limit: int, rate: float, timeout: float,
                pages: int = 5) -> tuple[list[dict], str]:
    """CIRCL fallback: fetch pages for the product, then match CPE ranges locally.

    Used only when NVD is unavailable. Coverage is bounded by `pages` and CIRCL
    returns newest-first, so older CVEs may fall outside the window - the
    confidence string states how much of the set was examined.
    """
    key = f"{vendor}/{product}"
    with _cve_lock:
        cached = _cve_cache.get(key)
        cached_total = _cve_total.get(key, 0)
    if cached is None:
        items, total = _fetch_cve_pages(session, vendor, product, pages, rate, timeout)
        if not items and total == 0:
            return [], "lookup-failed"
        with _cve_lock:
            _cve_cache[key] = items
            _cve_total[key] = total
        cached, cached_total = items, total

    out = []
    for obj in cached:
        applies = False
        for cfg in obj.get("configurations", []) or []:
            for node in cfg.get("nodes", []) or []:
                for cm in node.get("cpeMatch", []) or []:
                    if not cm.get("vulnerable"):
                        continue
                    crit = cm.get("criteria", "")
                    if f":{vendor}:{product}:" not in crit:
                        continue
                    if _cpe_applies(cm, version):
                        applies = True
                        break
                if applies:
                    break
            if applies:
                break
        if not applies:
            continue
        score = sev = None
        metrics = obj.get("metrics", {}) or {}
        for mk in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(mk):
                cd = metrics[mk][0].get("cvssData", {})
                score = cd.get("baseScore")
                sev = cd.get("baseSeverity") or metrics[mk][0].get("baseSeverity")
                break
        desc = ""
        for d in obj.get("descriptions", []) or []:
            if d.get("lang") == "en":
                desc = d.get("value", "")[:220]
                break
        out.append({"id": obj.get("id"), "cvss": score,
                    "severity": (sev or "UNKNOWN").upper(), "summary": desc})

    out.sort(key=lambda c: (-(c["cvss"] or 0), c["id"]))
    scanned = len(cached)
    coverage = (f"{scanned}/{cached_total}" if cached_total else str(scanned))
    if out:
        conf = f"cpe-version-match ({coverage} CVEs examined)"
    else:
        conf = f"no-match ({coverage} CVEs examined)"
    return out[:limit], conf


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------

def expand_targets(raw: list[str]) -> list[str]:
    out: list[str] = []
    for item in raw:
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
            if net.num_addresses > 4096:
                log(f"Refusing to expand {item}: {net.num_addresses} addresses "
                    f"(split it or raise the limit in source)", "bold red")
                continue
            hosts = list(net.hosts()) or [net.network_address]
            out += [str(ip) for ip in hosts]
            continue
        except ValueError:
            pass
        out.append(item)
    return list(dict.fromkeys(out))


def parse_ports(spec: str) -> list[int]:
    if spec == "top100":
        return sorted(TOP_100)
    if spec == "extended":
        return sorted(set(TOP_100) | set(EXTENDED_EXTRA))
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(max(1, int(a)), min(65535, int(b)) + 1))
        else:
            n = int(part)
            if 1 <= n <= 65535:
                ports.add(n)
    return sorted(ports)


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def log(msg: str, style: str = "") -> None:
    if _console:
        _console.print(f"[{style}]{msg}[/{style}]" if style else msg)
    else:
        print(msg, file=sys.stderr)


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = UA
    retry = Retry(total=2, backoff_factor=1.5, status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["GET"]), raise_on_status=False)
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


def write_outputs(host: str, svcs: list[Service], outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    stem = host.replace("/", "_").replace(":", "_")
    rows = [asdict(s) for s in svcs]
    (outdir / f"{stem}.json").write_text(json.dumps(
        {"tool": "vulnhunter", "version": VERSION, "host": host,
         "open_ports": len(rows), "services": rows}, indent=2))

    cols = ["host", "port", "state", "hint", "product", "version", "cpe",
            "http_server", "http_title", "tls", "tls_subject", "tls_expires",
            "cve_confidence", "cves", "banner"]
    with (outdir / f"{stem}.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            r = dict(r)
            r["cves"] = ";".join(f"{c['id']}({c['cvss']})" for c in r["cves"])
            r["banner"] = (r["banner"] or "").replace("\n", " ")[:300]
            w.writerow(r)


def print_table(host: str, svcs: list[Service]) -> None:
    if _console is None:
        for s in svcs:
            print(f"{s.port:6} {s.hint or '':16} {s.product or '':14} "
                  f"{s.version or '':12} {len(s.cves)} CVE")
        return
    t = Table(title=f"{host} - {len(svcs)} open port(s)")
    t.add_column("Port", justify="right", style="cyan")
    t.add_column("Service", style="magenta", max_width=16)
    t.add_column("Product", style="white", max_width=22)
    t.add_column("Detail", style="green", max_width=30, overflow="ellipsis")
    t.add_column("CVEs", style="bold red", max_width=30, overflow="fold")
    for s in svcs:
        prod = f"{s.product} {s.version}" if s.product else ""
        detail = s.http_title or s.tls_subject or (s.banner or "").split("\n")[0][:30]
        if s.cves:
            worst = s.cves[0]
            cve_txt = f"{len(s.cves)} (worst {worst['id']} {worst['cvss']})"
        elif s.version:
            cve_txt = "none matched"
        else:
            cve_txt = "[dim]no version[/dim]"
        t.add_row(str(s.port), s.hint or "?", prod, detail or "", cve_txt)
    _console.print(t)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="vulnhunter",
        description="TCP service discovery with version-aware CVE correlation.",
        epilog="Authorized use only. This tool sends traffic to its targets.",
    )
    ap.add_argument("-t", "--target", help="Host, IP, or CIDR")
    ap.add_argument("-i", "--input", help="File with one target per line")
    ap.add_argument("-p", "--ports", default="top100",
                    help="top100 | extended | all | 22,80,443 | 1-1024 (default: top100). "
                         "top100 is nmap's top 100; extended adds a further ~540 common ports.")
    ap.add_argument("-o", "--output", default="output", help="Output directory")
    ap.add_argument("-T", "--threads", type=int, default=200, help="Concurrency (default: 200)")
    ap.add_argument("--timeout", type=float, default=2.0, help="Connect timeout (default: 2)")
    ap.add_argument("--no-banners", action="store_true",
                    help="Port state only: connect and close, no service probes")
    ap.add_argument("--no-cve", action="store_true", help="Skip CVE correlation")
    ap.add_argument("--cve-limit", type=int, default=10, help="Max CVEs per service (default: 10)")
    ap.add_argument("--cve-rate", type=float, default=1.0,
                    help="Min seconds between CVE API calls (default: 1.0)")
    ap.add_argument("--cve-source", choices=("auto", "nvd", "circl"), default="auto",
                    help="CVE data source. nvd does server-side version matching and is "
                         "far more accurate; set NVD_API_KEY to lift its rate limit. "
                         "auto uses NVD and falls back to CIRCL (default: auto)")
    ap.add_argument("--cve-pages", type=int, default=5,
                    help="CVE API pages to fetch per product; the API returns 10 per "
                         "page, so 5 examines the 50 most recent (default: 5)")
    ap.add_argument("--min-cvss", type=float, default=0.0, help="Hide CVEs below this score")
    ap.add_argument("--quiet", action="store_true", help="No console table")
    ap.add_argument("--version", action="version", version=f"vulnhunter {VERSION}")
    args = ap.parse_args()

    if not args.target and not args.input:
        ap.error("provide -t/--target or -i/--input")

    raw: list[str] = []
    if args.target:
        raw.append(args.target)
    if args.input:
        try:
            raw += Path(args.input).read_text().splitlines()
        except OSError as e:
            log(f"Cannot read {args.input}: {e}", "bold red")
            return 2

    targets = expand_targets(raw)
    try:
        ports = parse_ports(args.ports)
    except ValueError:
        log(f"Could not parse --ports {args.ports!r}", "bold red")
        return 2
    if not targets or not ports:
        log("Nothing to scan.", "bold red")
        return 2

    log(f"vulnhunter {VERSION}: {len(targets)} target(s) x {len(ports)} port(s)", "bold cyan")
    session = make_session()
    outdir = Path(args.output)
    grand_total = 0

    for host in targets:
        log(f"\n=== {host} ===", "bold cyan")
        try:
            socket.gethostbyname(host)
        except (socket.gaierror, UnicodeError):
            log("  does not resolve - skipped", "yellow")
            continue

        open_svcs: list[Service] = []
        with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = [ex.submit(scan_port, host, p, args.timeout, not args.no_banners)
                    for p in ports]
            for fut in cf.as_completed(futs):
                s = fut.result()
                if s.state == "open":
                    open_svcs.append(s)
        open_svcs.sort(key=lambda s: s.port)
        log(f"  {len(open_svcs)} open", "green")
        if not open_svcs:
            continue

        if not args.no_cve:
            versioned = [s for s in open_svcs if s.vendor and s.product and s.version]
            if versioned:
                log(f"  correlating CVEs for {len(versioned)} versioned service(s)...", "cyan")
            for s in versioned:
                if args.cve_source in ("nvd", "auto"):
                    cves, conf = lookup_cves_nvd(session, s.vendor, s.product,
                                                 s.version, args.cve_limit, 30.0)
                    if args.cve_source == "auto" and conf.startswith(
                            ("nvd-rate-limited", "nvd-unreachable", "nvd-http-")):
                        log(f"    NVD unavailable ({conf}); falling back to CIRCL", "yellow")
                        cves, conf = lookup_cves(session, s.vendor, s.product, s.version,
                                                 args.cve_limit, args.cve_rate, 20.0,
                                                 pages=args.cve_pages)
                else:
                    cves, conf = lookup_cves(session, s.vendor, s.product, s.version,
                                             args.cve_limit, args.cve_rate, 20.0,
                                             pages=args.cve_pages)
                if args.min_cvss:
                    cves = [c for c in cves if (c["cvss"] or 0) >= args.min_cvss]
                s.cves, s.cve_confidence = cves, conf
            for s in open_svcs:
                if not s.version:
                    s.cve_confidence = "no-version-detected"

        if not args.quiet:
            print_table(host, open_svcs)
        write_outputs(host, open_svcs, outdir)
        grand_total += len(open_svcs)

    log(f"\nDone. {grand_total} open port(s) total. Output in {outdir}/", "bold green")
    log("CVEs are CPE-version matched but still require manual confirmation: "
        "banners can be altered and distributions backport fixes.", "dim")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("\nInterrupted.", "yellow")
        sys.exit(130)
