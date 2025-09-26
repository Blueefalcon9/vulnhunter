# VulnHunter
Lightweight vulnerability scanner — performs port scans, banner grabbing, and CVE correlation.

## Features
- TCP scan (top ports or custom)
- Banner grabbing
- Service guessing
- CVE mapping via CIRCL CVE API
- JSON/CSV output
- Beautiful Rich console output

## Usage
```bash
python3 vulnhunter.py -t 192.168.1.10
python3 vulnhunter.py -i hosts.txt -p 20-1024
