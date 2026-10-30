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

# abuse.ch feeds need a personal Auth-Key inside the URL. my_lists.json must
# never contain the real key (the repo is public). The pfSense sync script
# writes the placeholder instead, and the real key comes from the GitHub
# secret ABUSECH_KEY at run time.
ABUSECH_KEY = os.environ.get("ABUSECH_KEY", "").strip()
KEY_PLACEHOLDER = "{ABUSECH_KEY}"

# A failed download from these hosts is skipped with a warning instead of
# failing the whole run (abuse.ch has retired several public feeds).
OPTIONAL_HOSTS = ("abuse.ch",)

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
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt": [
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
    ],
}

# External IP sources to compare against
IP_SOURCES = [
    "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level2.netset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
    "https://lists.blocklist.de/lists/all.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
]

# External DNSBL sources to compare against
DNSBL_SOURCES = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
]

# Sanity limits. If a source returns fewer entries than this, the download is
# treated as broken (empty page, error page, truncated file) and the run fails
# instead of publishing wrong lists. Values are roughly 40% of the usual size.
MIN_ENTRIES = {
    "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset": 2000,
    "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level2.netset": 5000,
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset": 4500,
    "https://lists.blocklist.de/lists/all.txt": 1000,
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt": 5000,
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt": 100000,
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt": 100000,
}
MAX_SKIPPED_RATIO = 0.2          # fail if more than 20% of the lines are unparseable
MAX_MY_LISTS_AGE_HOURS = 72      # fail if my_lists.json (synced from pfSense) is older

# DNSBL sources promoted automatically by discover.py (see README).
# A missing or unreadable file, or "auto_enabled": false, means no auto sources.
AUTO_SOURCES_FILE = "output/auto_sources.json"
AUTO_MIN_RATIO = 0.5             # an auto source must return at least 50% of its last size
MAX_DNSBL_DOMAINS = 600000       # fail if merged_dnsbl.txt would grow beyond this

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


def redact(text):
    """Hide the abuse.ch key in anything that gets printed."""
    text = str(text)
    if ABUSECH_KEY:
        text = text.replace(ABUSECH_KEY, "***")
    return text


def is_optional(url):
    return any(host in url for host in OPTIONAL_HOSTS)


def resolve_url(url):
    """Insert the real key into placeholder URLs. Returns None if the key is missing."""
    if KEY_PLACEHOLDER not in url:
        return url
    if not ABUSECH_KEY:
        return None
    return url.replace(KEY_PLACEHOLDER, ABUSECH_KEY)


def download(url, label):
    print(f"  Downloading: {redact(label)}")
    real_url = resolve_url(url)
    if real_url is None:
        raise RuntimeError(f"Failed to download {label}: ABUSECH_KEY secret is not set")
    urls = FALLBACKS.get(url, [real_url])
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
                print(f"    (fallback used: {redact(attempt_url)})")
            if attempt_url.startswith("http://"):
                print(f"    Warning: {label} was downloaded over plain HTTP")
            return r.text
        except Exception as e:
            print(f"    Warning: {redact(attempt_url)} failed ({redact(e)}), trying next...")
            last_error = e
    raise RuntimeError(f"Failed to download {redact(label)}: {redact(last_error)}")


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


def is_domain_covered(domain, covered):
    """
    True if the domain or one of its parent domains is in covered.
    pfBlockerNG has Wildcard Blocking (TLD) enabled, so blocking example.com
    also blocks every subdomain such as ads.example.com.
    """
    labels = domain.split(".")
    return any(".".join(labels[i:]) in covered for i in range(len(labels) - 1))


def load_auto_sources():
    """Enabled auto sources from discover.py. Never fails the run."""
    if not os.path.exists(AUTO_SOURCES_FILE):
        return []
    try:
        with open(AUTO_SOURCES_FILE) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  Warning: cannot read {AUTO_SOURCES_FILE} ({e}), ignoring auto sources")
        return []
    if not isinstance(data, dict) or data.get("auto_enabled") is not True:
        print("  Auto sources are switched off (auto_enabled is not true)")
        return []
    return [
        s for s in data.get("sources", [])
        if isinstance(s, dict) and s.get("enabled") is True and s.get("type") == "dnsbl"
        and str(s.get("url", "")).startswith("https://") and not is_self_url(s["url"])
    ]


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
        raw = f.read()
    if ABUSECH_KEY and ABUSECH_KEY in raw:
        raise RuntimeError(
            "The abuse.ch key is stored in plain text in my_lists.json (public repo). "
            "Fix the pfSense sync script to write the {ABUSECH_KEY} placeholder, "
            "then rotate the key on abuse.ch."
        )
    my_lists = json.loads(raw)
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
    skipped_sources = []
    for url in my_dnsbl_urls:
        label = redact(url.split("/")[-1] or url)
        try:
            domains, skipped = parse_domains(download(url, label))
            check_source(label, len(domains), skipped)
        except RuntimeError as e:
            if not is_optional(url):
                raise
            print(f"    Warning: skipping optional source {label}: {redact(e)}")
            skipped_sources.append(label)
            continue
        my_domains.update(domains)
        print(f"    {label}: {len(domains)} domains")
    print(f"  Total my domains: {len(my_domains)}")
    if skipped_sources:
        print(f"  Skipped optional sources: {', '.join(skipped_sources)}")

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
        new_domains = {d for d in source_domains if not is_domain_covered(d, my_domains)}
        gap_domains.update(new_domains)
        print(f"    {label}: {len(source_domains)} total, {len(new_domains)} new domains")

    # Auto sources promoted by discover.py. A broken one is skipped, never fatal.
    auto_names = []
    for src in load_auto_sources():
        label = str(src.get("name") or src["url"].split("/")[-1])
        try:
            minimum = max(1, int(int(src.get("last_total") or 0) * AUTO_MIN_RATIO))
            source_domains, skipped = parse_domains(download(src["url"], label))
            check_source(label, len(source_domains), skipped, minimum)
        except (RuntimeError, ValueError, TypeError) as e:
            print(f"    Warning: skipping auto source {label}: {redact(e)}")
            continue
        new_domains = {d for d in source_domains if not is_domain_covered(d, my_domains)}
        gap_domains.update(new_domains)
        auto_names.append(label)
        print(f"    {label} (auto): {len(source_domains)} total, {len(new_domains)} new domains")

    gap_domains_sorted = sorted(gap_domains)
    print(f"  Total DNSBL gaps: {len(gap_domains_sorted)} domains")
    if len(gap_domains_sorted) > MAX_DNSBL_DOMAINS:
        raise RuntimeError(
            f"merged_dnsbl.txt would have {len(gap_domains_sorted)} domains "
            f"(limit {MAX_DNSBL_DOMAINS}) - aborting without publishing. "
            "Disable an auto source or set auto_enabled to false in output/auto_sources.json."
        )

    # Write both output files only now, after every download and check
    # succeeded, so a failure can never leave one file new and the other old.
    stamp = now.strftime('%Y-%m-%d %H:%M UTC')
    write_atomic(OUTPUT_IP, [
        "# Blocklist Manager – IP gaps",
        f"# Generated: {stamp}",
        "# Sources: firehol_level1 + firehol_level2 + firehol_level3 + blocklist_de_all + ipsum_level3",
        "# Contains networks NOT covered by your pfBlockerNG lists",
        f"# Total entries: {len(gap_nets_collapsed)} networks",
        "#",
        *[str(n) for n in gap_nets_collapsed],
    ])
    write_atomic(OUTPUT_DNS, [
        "# Blocklist Manager – DNSBL gaps",
        f"# Generated: {stamp}",
        "# Sources: " + " + ".join(["Hagezi Pro", "Hagezi TIF Mini", *auto_names]),
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
