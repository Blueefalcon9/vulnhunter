# VulnHunter

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

TCP service discovery with **version-aware CVE correlation**. CVEs are matched against an extracted
product *and version*, so the output is a triage list rather than noise.

> **Active scanner.** This sends traffic directly to its targets. Authorization first.

## Why v2

| Defect in v1 | Effect | Fix |
|---|---|---|
| CVE lookup hit `cve.circl.lu/api/search/<service>` | **that endpoint returns HTTP 404 and an HTML page — the headline feature was dead, failing silently inside a bare `except`** | NVD API 2.0 with `virtualMatchString` |
| Lookup keyed on a service *name* (`"ssh"`, `"http"`) | no version comparison; results were meaningless even when the API worked | Version extracted from the banner, matched server-side by NVD |
| `top100` was a list of **15** ports | scans silently missed 85% of the stated range | `top100` is nmap's real top 100; `extended` adds ~540 more |
| Banner probe sent a bare `\r\n` | wrong for HTTP, useless for TLS — **port 443 never produced a banner** | Per-protocol probes plus a real TLS handshake |
| No TLS support | no certificate data at all | Certificate subject, issuer, expiry and SANs |
| Bare `except: pass` throughout | every failure invisible | Typed handling; unresolvable hosts reported |

Verification of the fix: Apache **2.4.49** returns CVE-2021-41773 and CVE-2021-42013 (CVSS 9.8) at the
top of 88 matches; Apache **2.4.62** returns 57 different CVEs and correctly excludes them.

## What it does

1. Concurrent TCP connect scan
2. Protocol-aware probes — HTTP request, TLS handshake, or a passive banner read
3. Version fingerprinting across 22 products (OpenSSH, Apache, nginx, IIS, ProFTPD, Postfix, Dovecot, MySQL/MariaDB, PostgreSQL, Redis, Elasticsearch, Tomcat, Jetty, Samba, PHP, …)
4. CVE correlation via NVD, which applies the official CPE configuration data
5. JSON and CSV output

## Install

```bash
git clone https://github.com/Blueefalcon9/vulnhunter.git
cd vulnhunter
pip install -r requirements.txt
export NVD_API_KEY=...        # optional: lifts the rate limit from 5 to 50 req/30s
```

A free NVD key is worth getting — without it the tool must sleep ~6.5s between CVE lookups.

## Usage

```bash
python3 vulnhunter.py -t 203.0.113.10
python3 vulnhunter.py -t 203.0.113.0/24 -p top100
python3 vulnhunter.py -i hosts.txt -p extended --min-cvss 7.0
python3 vulnhunter.py -t host.example.com --no-cve        # inventory only
```

## Options

| Flag | Default | Description |
|---|---|---|
| `-t`, `--target` | — | Host, IP, or CIDR |
| `-i`, `--input` | — | File with one target per line |
| `-p`, `--ports` | `top100` | `top100` (100) \| `extended` (640) \| `all` \| `22,80,443` \| `1-1024` |
| `-o`, `--output` | `output` | Output directory |
| `-T`, `--threads` | `200` | Concurrency |
| `--timeout` | `2.0` | Connect timeout |
| `--no-banners` | off | Port state only, no service probes |
| `--no-cve` | off | Skip CVE correlation |
| `--cve-source` | `auto` | `nvd`, `circl`, or `auto` (NVD then CIRCL) |
| `--cve-limit` | `10` | Max CVEs reported per service |
| `--cve-pages` | `5` | CIRCL fallback pages (10 CVEs each) |
| `--min-cvss` | `0` | Hide CVEs below this score |

CIDRs larger than /20 are refused rather than silently expanded.

## Interpreting the CVE output

Each service carries a `cve_confidence` field, and it is the most important column:

| Value | Meaning |
|---|---|
| `nvd-version-match (N of M affecting X)` | NVD confirmed these CVEs cover the detected version |
| `no-version-detected` | **no version was extracted, so no CVEs are claimed** |
| `cpe-version-match (N/M examined)` | CIRCL fallback; coverage bounded, older CVEs may be outside the window |
| `nvd-rate-limited` / `nvd-unreachable` | lookup did not complete — absence of CVEs means nothing |

A version-matched CVE still is not a confirmed finding:

- **Banners lie.** They are trivially altered and often stripped.
- **Distributions backport fixes.** Debian's `2.4.49-1+deb11u1` may already carry the patch while still
  reporting 2.4.49. This is the single most common false positive in version-based scanning.
- **Reachability is not exploitability.** Confirm with a targeted check before anything goes in a report.

## Authorized use only

Use this only against systems you own or have **written** authorization to test. Unauthorized scanning
is illegal in most jurisdictions. You are responsible for staying inside your authorized scope.

## License

MIT — see [LICENSE](LICENSE).
