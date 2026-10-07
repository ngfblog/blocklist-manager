#!/usr/bin/env python3
"""
Blocklist Manager - Gap Finder
Downloads external sources, removes what you already have in pfBlockerNG,
and saves only the gaps to merged_ip.txt and merged_dnsbl.txt
"""

import ipaddress
import json
import os
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from netutil import (
    CoverageIndex,
    MIN_PREFIX_LEN,
    is_bogon,
    is_geoip_url,
    is_self_url,
    parse_domains,
    parse_ips,
)

HEADERS = {"User-Agent": "blocklist-manager/1.0 (+https://github.com/" +
           os.environ.get("GITHUB_REPOSITORY", "ngfblog/blocklist-manager") + ")"}
TIMEOUT = 30

# Fallback URLs: if the primary URL fails, try the alternatives in order
FALLBACKS = {
    "https://small.oisd.nl": [
        "https://small.oisd.nl",
        "https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild2_small.txt",
    ],
    "https://big.oisd.nl": [
        "https://big.oisd.nl",
        "https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild2_big.txt",
    ],
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt": [
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt",
    ],
}

# External IP sources to compare against
IP_SOURCES = [
    "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level2.netset",
    "https://lists.blocklist.de/lists/all.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
]

# External DNSBL sources to compare against
DNSBL_SOURCES = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
]

# Sanity limits. If a source returns fewer entries than this, the download is
# treated as broken (empty page, error page, truncated file) and the run fails
# instead of publishing wrong lists. Values are roughly 40% of the usual size.
MIN_ENTRIES = {
    "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset": 2000,
    "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level2.netset": 5000,
    "https://lists.blocklist.de/lists/all.txt": 1000,
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt": 5000,
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt": 100000,
}
MAX_SKIPPED_RATIO = 0.2          # fail if more than 20% of the lines are unparseable
MAX_MY_LISTS_AGE_HOURS = 72      # fail if my_lists.json (synced from pfSense) is older

MY_LISTS_FILE = "my_lists.json"
OUTPUT_IP = "output/merged_ip.txt"
OUTPUT_DNS = "output/merged_dnsbl.txt"
CACHE_FILE = "cache/ip_source_cache.json"


def make_session():
    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    return session


SESSION = make_session()


def download(url, label):
    print(f"  Downloading: {label}")
    urls = FALLBACKS.get(url, [url])
    # Prefer HTTPS: if a list is configured with http://, try https:// first
    # and fall back to the original URL only if HTTPS is not available.
    expanded = []
    for u in urls:
        if u.startswith("http://"):
            expanded.append("https://" + u[len("http://"):])
        expanded.append(u)
    last_error = None
    for attempt_url in expanded:
        try:
            r = SESSION.get(attempt_url, headers=HEADERS, timeout=TIMEOUT)
            r.raise_for_status()
            if attempt_url != expanded[0]:
                print(f"    (fallback used: {attempt_url})")
            if attempt_url.startswith("http://"):
                print(f"    Warning: {label} was downloaded over plain HTTP")
            return r.text
        except Exception as e:
            print(f"    Warning: {attempt_url} failed ({e}), trying next...")
            last_error = e
    raise RuntimeError(f"Failed to download {label}: {last_error}")


def check_source(label, count, skipped, minimum=1):
    """Fail loudly if a downloaded list looks broken."""
    total = count + skipped
    if count < minimum:
        raise RuntimeError(
            f"{label}: only {count} valid entries (expected at least {minimum}). "
            "The download is probably empty or broken - aborting without publishing."
        )
    if total and skipped / total > MAX_SKIPPED_RATIO:
        raise RuntimeError(
            f"{label}: {skipped} of {total} lines could not be parsed. "
            "The file format may have changed - aborting without publishing."
        )


def check_my_lists_age(my_lists):
    generated = my_lists.get("generated")
    if not generated:
        print("  Warning: my_lists.json has no 'generated' timestamp")
        return
    age = datetime.now(timezone.utc) - datetime.fromisoformat(generated)
    hours = age.total_seconds() / 3600
    print(f"  my_lists.json age: {hours:.1f} hours")
    if hours > MAX_MY_LISTS_AGE_HOURS:
        raise RuntimeError(
            f"my_lists.json is {hours:.0f} hours old. The pfSense sync has stopped "
            "(expired token or cron problem?). Check pfblockerng_sync.py on pfSense."
        )


def write_atomic(path, lines):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, path)


def main():
    print("=== Blocklist Manager – Gap Finder ===")
    now = datetime.now(timezone.utc)
    print(f"Time: {now.strftime('%Y-%m-%d %H:%M UTC')}")

    os.makedirs("output", exist_ok=True)

    # Load my current pfBlockerNG lists
    print("\n[1] Loading my pfBlockerNG lists...")
    with open(MY_LISTS_FILE) as f:
        my_lists = json.load(f)
    check_my_lists_age(my_lists)

    my_ip_urls = [u for u in my_lists.get("ip_lists", []) if not is_geoip_url(u) and not is_self_url(u)]
    my_dnsbl_urls = [u for u in my_lists.get("dnsbl_lists", []) if not is_self_url(u)]

    # Download and parse my IP lists
    print("\n[2] Downloading my IP lists...")
    my_ip_nets = set()
    for url in my_ip_urls:
        label = url.split("/")[-1] or url
        nets, skipped = parse_ips(download(url, label))
        check_source(label, len(nets), skipped)
        my_ip_nets.update(nets)
        print(f"    {label}: {len(nets)} networks")
    print(f"  Total my IP networks: {len(my_ip_nets)}")

    # Download and parse my DNSBL lists
    print("\n[3] Downloading my DNSBL lists...")
    my_domains = set()
    for url in my_dnsbl_urls:
        label = url.split("/")[-1] or url
        domains, skipped = parse_domains(download(url, label))
        check_source(label, len(domains), skipped)
        my_domains.update(domains)
        print(f"    {label}: {len(domains)} domains")
    print(f"  Total my domains: {len(my_domains)}")

    # Download external IP sources and find gaps
    print("\n[4] Finding IP gaps...")
    my_index = CoverageIndex(my_ip_nets)
    gap_nets = set()
    source_cache = {}
    dropped_short = 0
    for url in IP_SOURCES:
        label = url.split("/")[-1]
        source_nets, skipped = parse_ips(download(url, label))
        check_source(label, len(source_nets), skipped, MIN_ENTRIES.get(url, 1))

        # Cache the exact snapshot we just downloaded so compare.py can reuse
        # it instead of re-downloading - the upstream lists (especially
        # firehol_level2) update near-continuously, so a second independent
        # download minutes later would drift and never settle at 0 gaps.
        source_cache[url] = sorted(str(n) for n in source_nets)

        new_nets = []
        for n in source_nets:
            if my_index.overlaps(n) or is_bogon(n):
                continue
            if n.prefixlen < MIN_PREFIX_LEN:
                dropped_short += 1
                print(f"    Warning: dropped too-broad entry {n} from {label}")
                continue
            new_nets.append(n)
        gap_nets.update(new_nets)
        print(f"    {label}: {len(source_nets)} total, {len(new_nets)} new networks")

    os.makedirs("cache", exist_ok=True)
    cache_tmp = CACHE_FILE + ".tmp"
    with open(cache_tmp, "w") as f:
        json.dump({
            "generated": datetime.now(timezone.utc).isoformat(),
            "sources": source_cache,
            # Cache the base ("my") IP list snapshot too, not just the
            # compare-sources. Spamhaus/Emerging Threats/etc. churn
            # constantly, so if compare.py re-downloads these independently
            # a few minutes later, IPs that were "covered" here can appear
            # "uncovered" there purely from base-list drift. Sharing this
            # exact snapshot removes that drift.
            "my_ip_nets": sorted(str(n) for n in my_ip_nets),
        }, f)
    os.replace(cache_tmp, CACHE_FILE)
    print(f"  Cached {len(source_cache)} source snapshots + base list → {CACHE_FILE}")

    gap_nets_collapsed = sorted(ipaddress.collapse_addresses(gap_nets))
    print(f"  Total IP gaps: {len(gap_nets_collapsed)} networks")

    # Download external DNSBL sources and find gaps
    print("\n[5] Finding DNSBL gaps...")
    gap_domains = set()
    for url in DNSBL_SOURCES:
        label = url.split("/")[-1]
        source_domains, skipped = parse_domains(download(url, label))
        check_source(label, len(source_domains), skipped, MIN_ENTRIES.get(url, 1))
        new_domains = source_domains - my_domains
        gap_domains.update(new_domains)
        print(f"    {label}: {len(source_domains)} total, {len(new_domains)} new domains")

    gap_domains_sorted = sorted(gap_domains)
    print(f"  Total DNSBL gaps: {len(gap_domains_sorted)} domains")

    # Write both output files only now, after every download and check
    # succeeded, so a failure can never leave one file new and the other old.
    stamp = now.strftime('%Y-%m-%d %H:%M UTC')
    write_atomic(OUTPUT_IP, [
        "# Blocklist Manager – IP gaps",
        f"# Generated: {stamp}",
        "# Sources: firehol_level1 + firehol_level2 + blocklist_de_all + ipsum_level3",
        "# Contains networks NOT covered by your pfBlockerNG lists",
        f"# Total entries: {len(gap_nets_collapsed)} networks",
        "#",
        *[str(n) for n in gap_nets_collapsed],
    ])
    write_atomic(OUTPUT_DNS, [
        "# Blocklist Manager – DNSBL gaps",
        f"# Generated: {stamp}",
        "# Sources: Hagezi Pro",
        "# Contains domains NOT covered by your pfBlockerNG DNSBL lists",
        f"# Total entries: {len(gap_domains_sorted)} domains",
        "#",
        *gap_domains_sorted,
    ])

    print("\n=== Done ===")
    print(f"  IP gaps: {len(gap_nets_collapsed):,} networks → {OUTPUT_IP}")
    print(f"  DNSBL gaps: {len(gap_domains_sorted):,} domains → {OUTPUT_DNS}")
    if dropped_short:
        print(f"  Dropped {dropped_short} entries shorter than /{MIN_PREFIX_LEN}")


if __name__ == "__main__":
    main()
