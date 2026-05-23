#!/usr/bin/env python3
import yaml
import requests
import ipaddress
import os
import json
from datetime import datetime, timezone

CONFIG_FILE = "sources.yaml"
OUTPUT_IP = "output/merged_ip.txt"
OUTPUT_DNS = "output/merged_dnsbl.txt"
REPORT_FILE = "output/last_run.json"

HEADERS = {"User-Agent": "blocklist-manager/1.0 (https://github.com/ngfblog/blocklist-manager)"}
TIMEOUT = 30

def load_config():
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)

def download_list(url, label):
    print(f"  Downloading: {label}")
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"  ERROR downloading {label}: {e}")
        return ""

def parse_ip_list(text):
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        parts = line.split()
        entry = parts[0] if parts else ""
        try:
            ipaddress.ip_network(entry, strict=False)
            ips.add(entry)
        except ValueError:
            pass
    return ips

def collapse_ips(ips):
    networks = []
    for ip in ips:
        try:
            networks.append(ipaddress.ip_network(ip, strict=False))
        except ValueError:
            pass
    v4 = sorted(set(ipaddress.collapse_addresses(
        [n for n in networks if n.version == 4]
    )), key=lambda x: x)
    v6 = sorted(set(ipaddress.collapse_addresses(
        [n for n in networks if n.version == 6]
    )), key=lambda x: x)
    return [str(n) for n in v4] + [str(n) for n in v6]

def parse_dnsbl(text):
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!") or line.startswith(";"):
            continue
        if line.startswith("0.0.0.0 ") or line.startswith("127.0.0.1 "):
            parts = line.split()
            if len(parts) >= 2:
                d = parts[1].strip().lower()
                if d and "." in d and d != "localhost":
                    domains.add(d)
        elif line.startswith("||") and line.endswith("^"):
            d = line[2:-1].strip().lower()
            if d:
                domains.add(d)
        elif "." in line and " " not in line:
            domains.add(line.lower())
    return domains

def main():
    print("=== Blocklist Manager ===")
    print(f"Run time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

    config = load_config()
    os.makedirs("output", exist_ok=True)

    print("\n[1] Processing IP lists...")
    all_ips = set()
    ip_stats = []
    for entry in config.get("ip_lists", []):
        text = download_list(entry["url"], entry["label"])
        parsed = parse_ip_list(text)
        all_ips.update(parsed)
        ip_stats.append({"label": entry["label"], "count": len(parsed)})
        print(f"     {entry['label']}: {len(parsed)} entries")

    merged_ips = collapse_ips(all_ips)
    print(f"  Merged & collapsed: {len(merged_ips)} unique networks")

    prev_ip_count = 0
    if os.path.exists(OUTPUT_IP):
        with open(OUTPUT_IP) as f:
            prev_ip_count = sum(1 for l in f if l.strip() and not l.startswith("#"))

    with open(OUTPUT_IP, "w") as f:
        f.write(f"# Blocklist Manager – merged IP list\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
        f.write(f"# Sources: {len(config.get('ip_lists', []))}\n")
        f.write(f"# Total entries: {len(merged_ips)}\n")
        f.write("#\n")
        for ip in merged_ips:
            f.write(ip + "\n")

    print("\n[2] Processing DNSBL lists...")
    all_domains = set()
    dns_stats = []
    for entry in config.get("dnsbl_lists", []):
        text = download_list(entry["url"], entry["label"])
        parsed = parse_dnsbl(text)
        all_domains.update(parsed)
        dns_stats.append({"label": entry["label"], "count": len(parsed)})
        print(f"     {entry['label']}: {len(parsed)} entries")

    merged_domains = sorted(all_domains)
    print(f"  Merged: {len(merged_domains)} unique domains")

    prev_dns_count = 0
    if os.path.exists(OUTPUT_DNS):
        with open(OUTPUT_DNS) as f:
            prev_dns_count = sum(1 for l in f if l.strip() and not l.startswith("#"))

    with open(OUTPUT_DNS, "w") as f:
        f.write(f"# Blocklist Manager – merged DNSBL list\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
        f.write(f"# Sources: {len(config.get('dnsbl_lists', []))}\n")
        f.write(f"# Total entries: {len(merged_domains)}\n")
        f.write("#\n")
        for domain in merged_domains:
            f.write(f"0.0.0.0 {domain}\n")

    ip_diff = len(merged_ips) - prev_ip_count
    dns_diff = len(merged_domains) - prev_dns_count
    ip_change = f"+{ip_diff}" if ip_diff >= 0 else str(ip_diff)
    dns_change = f"+{dns_diff}" if dns_diff >= 0 else str(dns_diff)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": {"total": len(merged_ips), "prev": prev_ip_count, "sources": ip_stats},
        "dnsbl": {"total": len(merged_domains), "prev": prev_dns_count, "sources": dns_stats}
    }
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n=== Done ===")
    print(f"  IP:    {len(merged_ips):,} entries  ({ip_change})")
    print(f"  DNSBL: {len(merged_domains):,} entries  ({dns_change})")

if __name__ == "__main__":
    main()
