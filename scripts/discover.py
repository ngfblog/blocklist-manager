#!/usr/bin/env python3
"""
Blocklist Manager - Candidate Discovery
Measures how many new entries each candidate list would add on top of what
you already block (your pfBlockerNG lists + merged_*.txt), and saves the
results to output/candidates.json. Nothing here changes the merged lists.

Low-risk DNSBL candidates that stay worth considering are promoted to
output/auto_sources.json, which merge.py then uses as extra sources.
IP candidates are suggestions only.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import merge
from merge import check_source, download, is_domain_covered, redact
from netutil import (
    LIVE_METHODS,
    CoverageIndex,
    is_excluded,
    is_geoip_url,
    is_self_url,
    live_pct,
    parse_domains,
    parse_ips,
)

HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/{}-onlydomains.txt"
FIREHOL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/{}.netset"

# Candidate lists to measure. Edit freely: name, type ("dnsbl" or "ip"),
# url, category, risk ("low" = security list, "high" = may break sites).
CANDIDATES = [
    {"name": "hagezi_tif", "type": "dnsbl", "url": HAGEZI.format("tif"), "category": "threat intelligence", "risk": "low"},
    {"name": "hagezi_tif_medium", "type": "dnsbl", "url": HAGEZI.format("tif.medium"), "category": "threat intelligence", "risk": "low"},
    {"name": "hagezi_pro_plus", "type": "dnsbl", "url": HAGEZI.format("pro.plus"), "category": "ads / tracking", "risk": "high"},
    {"name": "hagezi_ultimate", "type": "dnsbl", "url": HAGEZI.format("ultimate"), "category": "ads / tracking", "risk": "high"},
    {"name": "hagezi_fake", "type": "dnsbl", "url": HAGEZI.format("fake"), "category": "scam / fake shops", "risk": "low"},
    {"name": "hagezi_hoster", "type": "dnsbl", "url": HAGEZI.format("hoster"), "category": "abused hosting", "risk": "low"},
    {"name": "hagezi_dyndns", "type": "dnsbl", "url": HAGEZI.format("dyndns"), "category": "dynamic DNS", "risk": "high"},
    {"name": "hagezi_doh_vpn_proxy_bypass", "type": "dnsbl", "url": HAGEZI.format("doh-vpn-proxy-bypass"), "category": "DoH / VPN / proxy bypass", "risk": "high"},
    {"name": "firehol_level4", "type": "ip", "url": FIREHOL.format("firehol_level4"), "category": "attacks / malware (aggressive)", "risk": "high"},
    {"name": "firehol_abusers_30d", "type": "ip", "url": FIREHOL.format("firehol_abusers_30d"), "category": "abusers (30 days)", "risk": "low"},
]

# Candidate catalog: extra DNSBL lists from the Blocklist-Checker project (data
# only, "name,url" per line). Lists you already have or that are already in
# CANDIDATES are skipped, and so are adult, ads, tracking and NRD lists.
# Discovered lists are "high" risk (never auto-enabled) unless listed in
# CATALOG_LOW_RISK.
CATALOG_URL = "https://raw.githubusercontent.com/jarelllama/Blocklist-Checker/main/data/blocklists_to_compare.txt"
CATALOG_MAX = 25                       # discovered lists per run
CATALOG_LOW_RISK = ("phishing army", "shadowwhisperer's malware")
CATALOG_SKIP = {
    "adult": r"\b(nsfw|adult|porn)\b",
    "ads": r"\b(ads|multi|dns filter)\b",
    "tracking": r"\b(tracking|trackers?)\b",
    "NRD": r"\bnrd\b",
}
MAX_LIST_BYTES = 40 * 1024 * 1024      # discovered lists larger than this are not downloaded

# Cap for automatic DNSBL sources: the last_new of all enabled sources together
# must stay within this. Written to auto_sources.json on every run.
MAX_NEW_DOMAINS = 250000

STALE_DAYS = 45               # Last-Modified older than this -> "stale"

# Prefilter: candidates below either limit are hidden in the web UI by default
# and get no liveness sampling. Display only - the promotion rules ignore it.
PREFILTER_MIN_PCT = 5
PREFILTER_MIN_NEW = 1000

# Auto promotion rules (DNSBL only)
PROMOTE_AFTER = 2             # eligible runs in a row before a source is enabled
FAIL_LIMIT = 2                # dead/stale runs in a row before an enabled source is removed
INELIGIBLE_LIMIT = 4          # ineligible runs in a row before an enabled source is removed
MAX_EVENTS = 20

OUTPUT_FILE = "output/candidates.json"
AUTO_FILE = merge.AUTO_SOURCES_FILE
MERGED_DNS = "output/merged_dnsbl.txt"
MERGED_IP = "output/merged_ip.txt"
IP_CACHE_FILE = "cache/ip_source_cache.json"


class AnyOf:
    """Read-only union of several sets, without copying them."""

    def __init__(self, *sets):
        self.sets = sets

    def __contains__(self, item):
        return any(item in s for s in self.sets)


def load_my_lists():
    with open(merge.MY_LISTS_FILE) as f:
        raw = f.read()
    if merge.ABUSECH_KEY and merge.ABUSECH_KEY in raw:
        raise RuntimeError("The abuse.ch key is stored in plain text in my_lists.json - aborting.")
    my_lists = json.loads(raw)
    merge.check_my_lists_age(my_lists)
    return my_lists


def load_my_domains(my_lists):
    """
    Same as step [3] of merge.main(). Returns (domains from my lists,
    domains from the local merged_dnsbl.txt) as two separate sets.
    """
    my_domains = set()
    for url in [u for u in my_lists.get("dnsbl_lists", []) if not is_self_url(u)]:
        label = redact(url.split("/")[-1] or url)
        try:
            domains, skipped = parse_domains(download(url, label))
            check_source(label, len(domains), skipped)
        except RuntimeError as e:
            if not merge.is_optional(url):
                raise
            print(f"    Warning: skipping optional source {label}: {redact(e)}")
            continue
        my_domains.update(domains)
        print(f"    {label}: {len(domains)} domains")
    merged = set()
    if os.path.exists(MERGED_DNS):
        with open(MERGED_DNS) as f:
            merged, _ = parse_domains(f.read())
        print(f"    merged_dnsbl.txt (local): {len(merged)} domains")
    print(f"  Total covered domains: {len(my_domains | merged)}")
    return my_domains, merged


def load_base_domains():
    """The fixed DNSBL sources of merge.py (Hagezi Pro, TIF Mini)."""
    base = set()
    for url in merge.DNSBL_SOURCES:
        label = url.split("/")[-1]
        domains, skipped = parse_domains(download(url, label))
        check_source(label, len(domains), skipped, merge.MIN_ENTRIES.get(url, 1))
        base.update(domains)
        print(f"    {label}: {len(domains)} domains")
    return base


def load_my_nets(my_lists):
    """Same as compare.py: merge.py's cached base snapshot if present, plus the local merged_ip.txt."""
    cached = None
    if os.path.exists(IP_CACHE_FILE):
        try:
            with open(IP_CACHE_FILE) as f:
                cached = json.load(f).get("my_ip_nets")
        except (json.JSONDecodeError, OSError):
            cached = None
    if cached is not None:
        print(f"    Using cached base-list snapshot ({len(cached)} networks)")
        my_nets, _ = parse_ips("\n".join(cached))
    else:
        print("    No cached base-list snapshot, downloading fresh...")
        my_nets = set()
        for url in my_lists.get("ip_lists", []):
            if is_geoip_url(url) or is_self_url(url):
                continue
            label = redact(url.split("/")[-1] or url)
            nets, skipped = parse_ips(download(url, label))
            check_source(label, len(nets), skipped)
            my_nets.update(nets)
            print(f"    {label}: {len(nets)} networks")
    if os.path.exists(MERGED_IP):
        with open(MERGED_IP) as f:
            merged, _ = parse_ips(f.read())
        my_nets.update(merged)
        print(f"    merged_ip.txt (local): {len(merged)} networks")
    print(f"  Total covered networks: {len(my_nets)}")
    return my_nets


def load_auto_state(path):
    """Read auto_sources.json, or start a fresh one. A corrupt file aborts the run."""
    if not os.path.exists(path):
        return {
            "generated": None,
            "auto_enabled": True,
            "max_new_domains": MAX_NEW_DOMAINS,
            "sources": [],
            "events": [],
        }
    try:
        with open(path) as f:
            state = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise RuntimeError(f"{path} is unreadable ({e}) - fix or delete it. Aborting.")
    if not isinstance(state, dict) or not isinstance(state.get("sources"), list):
        raise RuntimeError(f"{path} has an unexpected format - fix or delete it. Aborting.")
    state.setdefault("events", [])
    for s in state["sources"]:
        if not isinstance(s, dict) or "name" not in s:
            raise RuntimeError(f"{path} has a source without a name - fix or delete it. Aborting.")
        for key, value in (("type", "dnsbl"), ("url", ""), ("enabled", False), ("first_seen", ""),
                           ("consecutive_ok", 0), ("last_total", 0), ("last_new", 0),
                           ("fail_count", 0), ("ineligible_count", 0), ("reason", "")):
            s.setdefault(key, value)
    return state


def last_modified_age_days(url):
    """Age of the HTTP Last-Modified header in days, or None if the header is missing."""
    try:
        r = merge.SESSION.head(url, headers=merge.HEADERS, timeout=merge.TIMEOUT, allow_redirects=True)
        value = r.headers.get("Last-Modified")
        if not value:
            return None
        age = datetime.now(timezone.utc) - parsedate_to_datetime(value)
        return round(age.total_seconds() / 86400, 1)
    except Exception:
        return None


def url_key(url):
    """
    Comparable form of a list URL, so the same file is recognised behind
    different hosts: GitHub raw / github.com/raw / jsDelivr URLs map to
    owner/repo/path without the branch, *.oisd.nl lists to their host name.
    """
    u = re.sub(r"^[a-z]+://", "", url.strip().lower()).split("?")[0].split("#")[0].rstrip("/")
    host, _, path = u.partition("/")
    parts = path.split("/")
    if host.endswith("oisd.nl"):
        return host
    if host == "cdn.jsdelivr.net" and parts[0] == "gh" and len(parts) > 3:
        return "gh/" + "/".join([parts[1], parts[2].split("@")[0]] + parts[3:])
    if host == "raw.githubusercontent.com" and len(parts) > 3:
        rest = parts[5:] if parts[2:4] == ["refs", "heads"] else parts[3:]
        return "gh/" + "/".join(parts[:2] + rest)
    if host == "github.com" and len(parts) > 4 and parts[2] == "raw":
        rest = parts[6:] if parts[3:5] == ["refs", "heads"] else parts[4:]
        return "gh/" + "/".join(parts[:2] + rest)
    return u


def load_catalog(known_urls, known_names):
    """
    Candidates discovered in the catalog. Returns (candidates, info for
    candidates.json). A failed download just returns no candidates.
    """
    info = {"url": CATALOG_URL, "status": "ok", "added": [], "skipped": []}
    try:
        text = download(CATALOG_URL, "blocklists_to_compare.txt")
    except RuntimeError as e:
        print(f"    Warning: catalog download failed ({redact(e)}) - using CANDIDATES only")
        info.update(status="failed", error=redact(e))
        return [], info
    known = {url_key(u) for u in known_urls}
    found = []
    for line in text.splitlines():
        if "," not in line or line.startswith("#"):
            continue
        title, url = (part.strip() for part in line.rsplit(",", 1))
        if not url.lower().startswith(("https://", "http://")):
            continue  # header line or junk
        skip = next((cat for cat, pattern in CATALOG_SKIP.items() if re.search(pattern, title.lower())), None)
        if skip:
            info["skipped"].append({"name": title, "reason": f"{skip} list"})
            continue
        if url_key(url) in known:
            info["skipped"].append({"name": title, "reason": "already used or already a candidate"})
            continue
        if len(found) >= CATALOG_MAX:
            info["skipped"].append({"name": title, "reason": f"limit of {CATALOG_MAX} discovered lists per run"})
            continue
        name = re.sub(r"[^a-z0-9]+", "_", title.lower().replace("'s ", " ")).strip("_")
        while name in known_names:
            name += "_2"
        known.add(url_key(url))
        known_names.add(name)
        risk = "low" if any(k in title.lower() for k in CATALOG_LOW_RISK) else "high"
        found.append({"name": name, "type": "dnsbl", "url": url, "category": title,
                      "risk": risk, "discovered": True})
        info["added"].append(name)
    print(f"    Catalog: {len(found)} new lists, {len(info['skipped'])} skipped")
    return found, info


def too_large(url):
    """Size in MB if the server reports more than MAX_LIST_BYTES, else None."""
    try:
        r = merge.SESSION.head(url, headers=merge.HEADERS, timeout=merge.TIMEOUT, allow_redirects=True)
        size = int(r.headers.get("Content-Length") or 0)
    except Exception:
        return None
    return round(size / 1048576, 1) if size > MAX_LIST_BYTES else None


def fetch(candidate):
    """Download and parse one candidate. Returns (entries, None) or (None, error)."""
    try:
        if candidate.get("discovered"):
            size = too_large(candidate["url"])
            if size:
                raise RuntimeError(f"skipped: {size} MB is over the {MAX_LIST_BYTES // 1048576} MB limit")
        text = download(candidate["url"], candidate["name"])
        if candidate.get("discovered") and len(text) > MAX_LIST_BYTES:
            raise RuntimeError(f"skipped: over the {MAX_LIST_BYTES // 1048576} MB limit")
        parse = parse_domains if candidate["type"] == "dnsbl" else parse_ips
        entries, skipped = parse(text)
        check_source(candidate["name"], len(entries), skipped)
        return entries, None
    except Exception as e:
        return None, redact(e)


def measure(candidate, entries, error, covered_domains, my_index):
    result = dict(candidate)
    result.update(total=0, new=0, new_pct=0.0, live_pct=None, last_modified_age_days=None)
    if error is not None:
        print(f"    {candidate['name']}: DEAD ({error})")
        result.update(status="dead", error=error, worth_considering=False)
        return result

    if candidate["type"] == "dnsbl":
        new_domains = [d for d in entries if not is_domain_covered(d, covered_domains)]
        new = len(new_domains)
    else:
        new = sum(1 for n in entries if not my_index.overlaps(n) and not is_excluded(n))
    age = last_modified_age_days(candidate["url"])
    status = "stale" if age is not None and age > STALE_DAYS else "ok"
    result.update(
        total=len(entries),
        new=new,
        new_pct=round(new / len(entries) * 100, 1),
        last_modified_age_days=age,
        status=status,
        worth_considering=(
            candidate["risk"] == "low" and status == "ok"
            and (new >= 1000 if candidate["type"] == "dnsbl" else new > 100)
        ),
    )
    # Liveness of the domains this list would add, only for rows that pass the prefilter
    if (candidate["type"] == "dnsbl" and status == "ok"
            and result["new_pct"] >= PREFILTER_MIN_PCT and new >= PREFILTER_MIN_NEW):
        result["live_pct"] = live_pct(new_domains, candidate["url"])
    live = f", live {result['live_pct']}%" if result["live_pct"] is not None else ""
    print(f"    {candidate['name']}: {len(entries)} total, {new} new ({result['new_pct']}%{live}) - {status}")
    return result


def not_eligible_reason(result):
    if result is None:
        return "no longer in CANDIDATES"
    if result["risk"] != "low":
        return f"risk {result['risk']}"
    if result["status"] != "ok":
        return f"status {result['status']}"
    return f"only {result['new']} new domains (needs 1000)"


def update_auto_sources(state, results, now):
    """Apply the promotion rules to state in place."""
    today = now.strftime("%Y-%m-%d")
    stamp = now.isoformat()
    by_name = {r["name"]: r for r in results if r["type"] == "dnsbl"}
    known = {s["name"] for s in state["sources"]}

    # Every low-risk DNSBL candidate gets an entry. Entries are never deleted.
    for r in by_name.values():
        if r["risk"] == "low" and r["name"] not in known:
            state["sources"].append({
                "name": r["name"], "type": "dnsbl", "url": r["url"], "enabled": False,
                "first_seen": today, "consecutive_ok": 0, "last_total": 0, "last_new": 0,
                "fail_count": 0, "ineligible_count": 0, "reason": "",
            })

    def event(action, name, detail):
        state["events"].append({"time": stamp, "action": action, "name": name, "detail": detail})
        print(f"    {action.upper()}: {name} ({detail})")

    # Update counters
    for s in state["sources"]:
        r = by_name.get(s["name"])
        eligible = bool(r and r["risk"] == "low" and r["worth_considering"])
        if r:
            s["url"] = r["url"]
            if r["status"] != "dead":
                s["last_total"] = r["total"]
                s["last_new"] = r["new"]
        # fail_count = dead/stale runs in a row; ineligible_count = ineligible runs in a row
        s["consecutive_ok"] = s.get("consecutive_ok", 0) + 1 if eligible else 0
        s["fail_count"] = s.get("fail_count", 0) + 1 if r and r["status"] in ("dead", "stale") else 0
        s["ineligible_count"] = 0 if eligible else s.get("ineligible_count", 0) + 1
        s["reason"] = "" if eligible else not_eligible_reason(r)

    # Remove first, so the freed budget can be used below
    for s in state["sources"]:
        if not s["enabled"]:
            continue
        if s["fail_count"] >= FAIL_LIMIT:
            s["enabled"] = False
            s["reason"] = f"dead/stale in {s['fail_count']} runs in a row ({s['reason']})"
            event("removed", s["name"], s["reason"])
        elif s["ineligible_count"] >= INELIGIBLE_LIMIT:
            s["enabled"] = False
            s["reason"] = f"not eligible in {s['ineligible_count']} runs in a row ({s['reason']})"
            event("removed", s["name"], s["reason"])
        elif s["reason"]:
            s["reason"] = f"still enabled, not eligible {s['ineligible_count']}/{INELIGIBLE_LIMIT}: {s['reason']}"

    # Then add, while the total stays within max_new_domains
    state["max_new_domains"] = MAX_NEW_DOMAINS
    limit = MAX_NEW_DOMAINS
    used = sum(s["last_new"] for s in state["sources"] if s["enabled"])
    for s in state["sources"]:
        if s["enabled"] or s["reason"]:
            continue
        if s["consecutive_ok"] < PROMOTE_AFTER:
            s["reason"] = f"eligible {s['consecutive_ok']}/{PROMOTE_AFTER} runs in a row"
        elif used + s["last_new"] > limit:
            s["reason"] = (f"would exceed max_new_domains "
                           f"({used:,} in use + {s['last_new']:,} new > {limit:,})")
        else:
            s["enabled"] = True
            used += s["last_new"]
            event("added", s["name"], f"{s['last_new']:,} new domains, eligible "
                                      f"{s['consecutive_ok']} runs in a row")

    state["events"] = state["events"][-MAX_EVENTS:]
    state["generated"] = stamp


def write_json(path, data):
    text = json.dumps(data, indent=2)
    if merge.ABUSECH_KEY and merge.ABUSECH_KEY in text:
        raise RuntimeError(f"{path} would contain the abuse.ch key - aborting without publishing.")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text + "\n")
    os.replace(tmp, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=("dnsbl", "ip"), help="measure only one candidate type")
    parser.add_argument("--output", default=OUTPUT_FILE, help=f"output file (default {OUTPUT_FILE})")
    parser.add_argument("--auto-file", default=AUTO_FILE, help=f"auto sources file (default {AUTO_FILE})")
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    print("=== Blocklist Manager – Candidate Discovery ===")
    print(f"Time: {now.strftime('%Y-%m-%d %H:%M UTC')}")
    candidates = [c for c in CANDIDATES if not args.only or c["type"] == args.only]
    has_dnsbl = any(c["type"] == "dnsbl" for c in candidates)

    print("\n[1] Loading my pfBlockerNG lists...")
    my_lists = load_my_lists()
    catalog = None
    if has_dnsbl:
        # Skip what is already a candidate or already blocked (pfBlockerNG lists and
        # merge.py's fixed sources). Auto sources are not skipped: a discovered list
        # that was auto-enabled must keep being measured to stay enabled.
        known_urls = ([c["url"] for c in CANDIDATES] + merge.DNSBL_SOURCES + merge.IP_SOURCES
                      + my_lists.get("dnsbl_lists", []) + my_lists.get("ip_lists", []))
        discovered, catalog = load_catalog(known_urls, {c["name"] for c in CANDIDATES})
        candidates += discovered
    # Read the auto state before writing anything, so a corrupt file aborts cleanly
    auto = load_auto_state(args.auto_file) if has_dnsbl else None
    auto_on = bool(auto and auto.get("auto_enabled") is True)
    if auto and not auto_on:
        print("  Auto mode is OFF (auto_enabled is false) - auto_sources.json stays unchanged")

    lists_domains, merged_domains, my_index = set(), set(), None
    if has_dnsbl:
        print("\n[2] Loading what I already block (DNSBL)...")
        lists_domains, merged_domains = load_my_domains(my_lists)
    if any(c["type"] == "ip" for c in candidates):
        print("\n[3] Loading what I already block (IP)...")
        my_index = CoverageIndex(load_my_nets(my_lists))

    print("\n[4] Downloading candidates...")
    fetched = {c["name"]: fetch(c) for c in candidates}

    # An enabled auto source is already part of merged_dnsbl.txt, so measuring it
    # against that file would make it look useless. Measure it against my lists,
    # the fixed merge.py sources and the other enabled auto sources instead.
    enabled = {s["name"] for s in auto["sources"] if s.get("enabled")} if auto_on else set()
    enabled_ok = {n for n in enabled if fetched.get(n, (None,))[0] is not None}
    base_domains = set()
    if enabled_ok:
        print("\n    Loading merge.py base sources for enabled auto sources...")
        base_domains = load_base_domains()

    print("\n[5] Measuring candidates...")
    default_covered = AnyOf(lists_domains, merged_domains)
    results = []
    for c in candidates:
        entries, error = fetched[c["name"]]
        covered = default_covered
        if c["name"] in enabled_ok:
            others = [fetched[n][0] for n in enabled_ok if n != c["name"]]
            covered = AnyOf(lists_domains, base_domains, *others)
        results.append(measure(c, entries, error, covered, my_index))
    results.sort(key=lambda r: r["new"], reverse=True)

    output = {"generated": now.isoformat(), "candidates": results, "live_check": dict(LIVE_METHODS)}
    if catalog:
        output["catalog"] = catalog
    write_json(args.output, output)

    if auto_on:
        print("\n[6] Updating auto sources...")
        update_auto_sources(auto, results, now)
        write_json(args.auto_file, auto)

    print("\n=== Done ===")
    for r in results:
        flag = "worth considering" if r["worth_considering"] else ""
        print(f"  {r['name']}: {r['new']:,} new – {r['status']} {flag}")
    print(f"  → {args.output}")
    if auto_on:
        active = [s["name"] for s in auto["sources"] if s["enabled"]]
        print(f"  Auto sources enabled: {', '.join(active) or 'none'} → {args.auto_file}")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print(f"ERROR: {redact(e)}", file=sys.stderr)
        sys.exit(1)
