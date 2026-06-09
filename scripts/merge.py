#!/usr/bin/env python3
"""
Blocklist Manager - Gap Finder
Downloads external sources, removes what you already have in pfBlockerNG,
and saves only the gaps to merged_ip.txt and merged_dnsbl.txt
"""

import requests
import ipaddress
import json
import os
from datetime import datetime, timezone

HEADERS = {"User-Agent": "blocklist-manager/1.0 (https://github.com/ngfblog/blocklist-manager)"}
TIMEOUT = 30

BOGON_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
]

# Fallback URLs: if the primary URL fails, try the alternatives in order
FALLBACKS = {
    "https://small.oisd.nl": [
        "https://small.oisd.nl",
        "https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild2_small.txt",
    ],
}


def is_bogon(net):
    return any(net.overlaps(b) for b in BOGON_RANGES)

# External IP sources to compare against
IP_SOURCES = [
    "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level2.netset",
]

# External DNSBL sources to compare against
DNSBL_SOURCES = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
]

MY_LISTS_FILE = "my_lists.json"
OUTPUT_IP     = "output/merged_ip.txt"
OUTPUT_DNS    = "output/merged_dnsbl.txt"


def download(url, label):
    print(f"  Downloading: {label}")
    urls = FALLBACKS.get(url, [url])
    last_error = None
    for attempt_url in urls:
        try:
            r = requests.get(attempt_url, headers=HEADERS, timeout=TIMEOUT)
            r.raise_for_status()
            if attempt_url != urls[0]:
                print(f"     (fallback used: {attempt_url})")
            return r.text
        except Exception as e:
            print(f"     Warning: {attempt_url} failed ({e}), trying next...")
            last_error = e
    raise RuntimeError(f"Failed to download {label}: {last_error}")


def parse_ips(text):
    nets = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        entry = line.split()[0]
        try:
            nets.add(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass
    return nets


def parse_domains(text):
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
        elif "." in line and " " not in line and not line.startswith("http"):
            domains.add(line.lower())
    return domains


def nets_overlap(net, existing):
    for e in existing:
        if net.overlaps(e):
            return True
    return False


def main():
    print("=== Blocklist Manager – Gap Finder ===")
    print(f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

    os.makedirs("output", exist_ok=True)

    # Load my current pfBlockerNG lists
    print("\n[1] Loading my pfBlockerNG lists...")
    with open(MY_LISTS_FILE) as f:
        my_lists = json.load(f)

    my_ip_urls    = [u for u in my_lists.get("ip_lists", []) if "ipverse" not in u and "blocklist-manager" not in u]
    my_dnsbl_urls = [u for u in my_lists.get("dnsbl_lists", []) if "blocklist-manager" not in u]

    # Download and parse my IP lists
    print("\n[2] Downloading my IP lists...")
    my_ip_nets = set()
    for url in my_ip_urls:
        text = download(url, url.split("/")[-1])
        nets = parse_ips(text)
        my_ip_nets.update(nets)
        print(f"     {url.split('/')[-1]}: {len(nets)} networks")
    print(f"  Total my IP networks: {len(my_ip_nets)}")

    # Download and parse my DNSBL lists
    print("\n[3] Downloading my DNSBL lists...")
    my_domains = set()
    for url in my_dnsbl_urls:
        text = download(url, url.split("/")[-1])
        domains = parse_domains(text)
        my_domains.update(domains)
        print(f"     {url.split('/')[-1]}: {len(domains)} domains")
    print(f"  Total my domains: {len(my_domains)}")

    # Download external IP sources and find gaps
    print("\n[4] Finding IP gaps...")
    gap_nets = set()
    for url in IP_SOURCES:
        text = download(url, url.split("/")[-1])
        source_nets = parse_ips(text)
        new_nets = [n for n in source_nets if not nets_overlap(n, my_ip_nets) and not is_bogon(n)]
        gap_nets.update(new_nets)
        print(f"     {url.split('/')[-1]}: {len(source_nets)} total, {len(new_nets)} new networks")

    gap_nets_collapsed = sorted(
        ipaddress.collapse_addresses(gap_nets),
        key=lambda x: x
    )
    print(f"  Total IP gaps: {len(gap_nets_collapsed)} networks")

    with open(OUTPUT_IP, "w") as f:
        f.write(f"# Blocklist Manager – IP gaps\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
        f.write(f"# Sources: firehol_level1 + firehol_level2\n")
        f.write(f"# Contains networks NOT covered by your pfBlockerNG lists\n")
        f.write(f"# Total entries: {len(gap_nets_collapsed)} networks\n#\n")
        for net in gap_nets_collapsed:
            f.write(str(net) + "\n")

    # Download external DNSBL sources and find gaps
    print("\n[5] Finding DNSBL gaps...")
    gap_domains = set()
    for url in DNSBL_SOURCES:
        text = download(url, url.split("/")[-1])
        source_domains = parse_domains(text)
        new_domains = source_domains - my_domains
        gap_domains.update(new_domains)
        print(f"     {url.split('/')[-1]}: {len(source_domains)} total, {len(new_domains)} new domains")

    gap_domains_sorted = sorted(gap_domains)
    print(f"  Total DNSBL gaps: {len(gap_domains_sorted)} domains")

    with open(OUTPUT_DNS, "w") as f:
        f.write(f"# Blocklist Manager – DNSBL gaps\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
        f.write(f"# Sources: Hagezi Pro\n")
        f.write(f"# Contains domains NOT covered by your pfBlockerNG DNSBL lists\n")
        f.write(f"# Total entries: {len(gap_domains_sorted)} domains\n#\n")
        for domain in gap_domains_sorted:
            f.write(domain + "\n")

    print(f"\n=== Done ===")
    print(f"  IP gaps:    {len(gap_nets_collapsed):,} networks → {OUTPUT_IP}")
    print(f"  DNSBL gaps: {len(gap_domains_sorted):,} domains  → {OUTPUT_DNS}")


if __name__ == "__main__":
    main()
