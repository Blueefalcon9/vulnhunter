# VulnHunter

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Port scan, banner grab, and CVE correlation in one pass. Gives you a first-look service inventory with
candidate CVEs attached, for triage rather than confirmation.

> **Active scanner.** Unlike `recon-scope-hunter`, this sends traffic directly to the target. Authorization
> first.

## What it does

1. **Scans** TCP ports (top 100 by default, or a custom list/range), concurrently
2. **Grabs banners** from anything open
3. **Guesses the service** from the port and banner
4. **Looks up CVEs** for the guessed service via the [CIRCL CVE API](https://cve.circl.lu)
5. **Writes** JSON and CSV

## Install

```bash
git clone https://github.com/Blueefalcon9/vulnhunter.git
cd vulnhunter
pip install -r requirements.txt
```

## Usage

```bash
python3 vulnhunter.py -t 203.0.113.10
python3 vulnhunter.py -i hosts.txt -p 20-1024
python3 vulnhunter.py -t 203.0.113.10 -p 22,80,443,8080 -o results
```

## Options

| Flag | Default | Description |
|---|---|---|
| `-t`, `--target` | — | Single host or IP |
| `-i`, `--input` | — | File with a list of hosts, one per line |
| `-p`, `--ports` | `top100` | `top100`, a comma list (`22,80,443`), or a range (`20-1024`) |
| `-o`, `--output` | `output` | Output folder |

Pass either `-t` or `-i`.

## Interpreting the CVE output

CVEs are matched on a **service name guessed from a banner**, not on a confirmed version. Treat every hit as
a lead to verify, not a finding:

- Banners are often absent, wrong, or deliberately altered.
- Backported security patches mean a vendor version string frequently does not reflect actual vulnerability.
- No version comparison is performed — a CVE for any version of the service may appear.

Confirm with a targeted check before it goes in a report.

## Authorized use only

Use this only against systems you own or have **written** authorization to test. Unauthorized scanning and
credential discovery are illegal in most jurisdictions. You are responsible for staying inside your
authorized scope.

## License

MIT — see [LICENSE](LICENSE).
