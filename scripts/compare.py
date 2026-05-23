#!/usr/bin/env python3
"""
Blocklist Comparison Script
Runs via GitHub Actions daily.
Compares firehol_level1 against your active pfBlockerNG lists
and produces recommendations.json
"""

import requests
import ipaddress
import json
import os
from datetime import datetime, timezone

HEADERS = {"User-Agent": "blocklist-manager/1.0"}
TIMEOUT = 30

COMPARE_SOURCES = {
    "firehol_level1": {
        "url": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
        "description": "FireHOL Level 1 – top consensus blocklist aggregating 10+ trusted sources",
        "type": "ip"
    },
    "firehol_level2": {
        "url": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level2.netset",
        "description": "FireHOL Level 2 – broader coverage, more aggressive blocking",
        "type": "ip"
    },
    "blocklist_de_all": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "description": "Blocklist.de – IPs that attacked SSH, FTP, web servers in last 48h",
        "type": "ip"
    }
}

MY_LISTS_FILE = "my_lists.json"
OUTPUT_FILE   = "output/recommendations.json"


def parse_ips(text):
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        parts = line.split()
        entry = parts[0] if parts else ""
        try:
            net = ipaddress.ip_network(entry, strict=False)
            ips.add(net)
        except ValueError:
            pass
    return ips


def download(url, label):
    print(f"  Downloading: {label}")
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"  ERROR: {e}")
        return ""


def nets_overlap(net, existing_nets):
    for existing in existing_nets:
        if net.overlaps(existing):
            return True
    return False


def count_new_ips(source_nets, existing_nets):
    new_nets = [n for n in source_nets if not nets_overlap(n, existing_nets)]
    total_new = sum(n.num_addresses for n in new_nets)
    return len(new_nets), total_new, new_nets[:20]


def main():
    print("=== Blocklist Comparison ===")
    print(f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

    print("\n[1] Loading my pfBlockerNG lists...")
    with open(MY_LISTS_FILE) as f:
        my_lists = json.load(f)

    my_ip_urls = my_lists.get("ip_lists", [])
    print(f"  My IP sources: {len(my_ip_urls)}")

    print("\n[2] Downloading my IP lists...")
    my_nets = set()
    for url in my_ip_urls:
        if "ipverse" in url:
            print(f"  Skipping GeoIP: {url}")
            continue
        label = url.split("/")[-1]
        text = download(url, label)
        nets = parse_ips(text)
        my_nets.update(nets)
        print(f"     {label}: {len(nets)} networks")

    print(f"  Total my networks: {len(my_nets)}")

    print("\n[3] Comparing against external sources...")
    recommendations = []

    for name, source in COMPARE_SOURCES.items():
        print(f"\n  Checking: {name}")
        text = download(source["url"], name)
        if not text:
            continue

        source_nets = parse_ips(text)
        print(f"    Total in source: {len(source_nets)}")

        new_net_count, new_ip_count, sample_nets = count_new_ips(source_nets, my_nets)
        coverage_pct = round((1 - new_net_count / max(len(source_nets), 1)) * 100, 1)

        print(f"    New networks not covered: {new_net_count}")
        print(f"    New IPs not covered: {new_ip_count:,}")
        print(f"    Your coverage: {coverage_pct}%")

        recommendations.append({
            "name": name,
            "description": source["description"],
            "url": source["url"],
            "type": source["type"],
            "total_entries": len(source_nets),
            "new_networks": new_net_count,
            "new_ips": new_ip_count,
            "your_coverage_pct": coverage_pct,
            "sample_new": [str(n) for n in sample_nets],
            "worth_adding": new_ip_count > 1000
        })

    recommendations.sort(key=lambda x: x["new_ips"], reverse=True)

    output = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "my_networks_count": len(my_nets),
        "recommendations": recommendations
    }

    os.makedirs("output", exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n=== Done ===")
    for r in recommendations:
        status = "Worth adding" if r["worth_adding"] else "Already covered"
        print(f"  {r['name']}: {r['new_ips']:,} new IPs – {status}")


if __name__ == "__main__":
    main()
