#!/usr/bin/env python3
"""
VulnHunter
Author: Your Name
Description: Port scanner + banner grabber + CVE lookup tool.
"""

import argparse
import socket
import concurrent.futures
import requests
import json
import csv
import os
from rich.console import Console
from rich.table import Table
from tqdm import tqdm

console = Console()
TIMEOUT = 2

# -----------------------------
# Port Scanning & Banner Grabbing
# -----------------------------
def scan_port(host, port):
    result = {"host": host, "port": port, "banner": None, "service": None, "cves": []}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        if sock.connect_ex((host, port)) == 0:
            try:
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()
                result["banner"] = banner
            except:
                pass
            result["service"] = guess_service(port, result["banner"])
        sock.close()
    except Exception as e:
        pass
    return result

def guess_service(port, banner):
    common = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        139: "netbios",
        143: "imap",
        443: "https",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        8080: "http-alt"
    }
    if port in common:
        return common[port]
    if banner:
        b = banner.lower()
        if "ssh" in b: return "ssh"
        if "http" in b: return "http"
        if "smtp" in b: return "smtp"
    return "unknown"

# -----------------------------
# CVE Lookup
# -----------------------------
def lookup_cves(service_name):
    """Use CIRCL CVE search API"""
    cves = []
    try:
        url = f"https://cve.circl.lu/api/search/{service_name}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            for entry in data[:3]:  # Limit top 3
                cves.append({
                    "id": entry.get("id"),
                    "summary": entry.get("summary", "")[:120]
                })
    except:
        pass
    return cves

# -----------------------------
# Main Logic
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="VulnHunter - Port Scan + CVE Lookup")
    parser.add_argument("-t", "--target", help="Single host/IP to scan")
    parser.add_argument("-i", "--input", help="File with list of hosts")
    parser.add_argument("-p", "--ports", default="top100", help="Ports to scan (comma, range, or 'top100')")
    parser.add_argument("-o", "--output", default="output", help="Output folder")
    args = parser.parse_args()

    if not args.target and not args.input:
        console.print("[red][!] Provide a target (-t) or file (-i)[/red]")
        return

    # Prepare targets
    targets = []
    if args.target:
        targets.append(args.target.strip())
    if args.input:
        with open(args.input) as f:
            targets.extend([line.strip() for line in f if line.strip()])

    # Port list
    if args.ports == "top100":
        ports = [21,22,23,25,53,80,110,139,143,443,445,3389,3306,8080,8443]
    else:
        ports = []
        for part in args.ports.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))

    os.makedirs(args.output, exist_ok=True)

    for host in targets:
        console.print(f"\n[bold cyan]=== Scanning {host} ===[/bold cyan]")
        results = []

        # Port scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            for result in tqdm(executor.map(lambda p: scan_port(host, p), ports),
                               total=len(ports), desc="Scanning"):
                if result.get("service"):
                    results.append(result)

        # CVE lookup per service
        unique_services = {r["service"] for r in results if r["service"] != "unknown"}
        service_cve_map = {}
        for svc in unique_services:
            cves = lookup_cves(svc)
            service_cve_map[svc] = cves

        for r in results:
            if r["service"] in service_cve_map:
                r["cves"] = service_cve_map[r["service"]]

        # Console output
        table = Table(title=f"Results for {host}")
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="magenta")
        table.add_column("Banner", style="yellow")
        table.add_column("CVE IDs", style="green")
        for r in results:
            cve_ids = ", ".join([c["id"] for c in r["cves"]]) if r["cves"] else "-"
            table.add_row(str(r["port"]), r["service"], str(r["banner"])[:40], cve_ids)
        console.print(table)

        # Save results
        json_path = f"{args.output}/{host}_vulnhunter.json"
        csv_path = f"{args.output}/{host}_vulnhunter.csv"
        with open(json_path, "w") as jf:
            json.dump(results, jf, indent=4)
        with open(csv_path, "w", newline="") as cf:
            writer = csv.DictWriter(cf, fieldnames=["host","port","service","banner","cves"])
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "host": r["host"],
                    "port": r["port"],
                    "service": r["service"],
                    "banner": r["banner"],
                    "cves": ", ".join([c["id"] for c in r["cves"]]) if r["cves"] else ""
                })
        console.print(f"[blue][*][/blue] Saved: {json_path}, {csv_path}")

if __name__ == "__main__":
    main()
