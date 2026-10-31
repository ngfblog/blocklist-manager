#!/usr/bin/env python3
"""
Blocklist Manager - Existing List Analysis
For every list in my_lists.json: how many entries it has, how many no other
active list covers (unique), and for DNSBL lists how many sampled domains still
are alive. Writes output/existing_lists.json. Report only - nothing is removed.

It also builds a stepwise prune plan per type: remove the weakest list, recount
what is unique among the rest, repeat. Two lists that only cover each other are
therefore never both suggested for removal at the same time.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone

import merge
from merge import download, is_domain_covered, redact
from netutil import (
    CoverageIndex,
    LINTER,
    LIVE_METHODS,
    dns_works,
    is_excluded,
    is_geoip_url,
    is_self_url,
    linter_available,
    live_pct,
    parse_domains,
    parse_ips,
)

OUTPUT_FILE = "output/existing_lists.json"

# A list is flagged "maybe redundant" when it adds fewer than this many
# unique entries AND less than this share of its own size.
REDUNDANT_MAX_UNIQUE = 100
REDUNDANT_MAX_PCT = 5

# Prune plan: a list is a prune candidate when it has no unique entries or
# less than this share unique (recomputed after every simulated removal).
PRUNE_MAX_PCT = 5

# pfBlockerNG ASN entries such as "AS13335" (used for Permit ASN lists)
ASN_RE = re.compile(r"(^|[^a-z0-9])as\d{1,10}($|[^0-9])", re.IGNORECASE)


def skip_reason(url):
    if is_self_url(url):
        return "own output file"
    if is_geoip_url(url):
        return "GeoIP list"
    if not url.lower().startswith(("http://", "https://")) or "/asn/" in url.lower() or ASN_RE.search(url):
        return "ASN list"
    return None


class OtherListsCover:
    """'domain in x' is True if a list other than `own` contains the domain."""

    def __init__(self, owner, own):
        self.owner = owner
        self.own = own

    def __contains__(self, domain):
        o = self.owner.get(domain)
        return o is not None and o != self.own


def unique_domains(dns_lists):
    """Unique count per DNSBL list; parent domains in other lists count as cover."""
    owner = {}  # domain -> index of the only list that has it, or -1 if several do
    for i, entry in enumerate(dns_lists):
        for d in entry["entries"]:
            o = owner.get(d)
            owner[d] = i if o is None or o == i else -1
    return [
        sum(1 for d in entry["entries"] if not is_domain_covered(d, OtherListsCover(owner, i)))
        for i, entry in enumerate(dns_lists)
    ]


def unique_nets(ip_lists):
    """Unique count per IP list, with the same overlap rules as compare.py."""
    counts = []
    for i, entry in enumerate(ip_lists):
        others = set()
        for j, other in enumerate(ip_lists):
            if j != i:
                others.update(other["entries"])
        index = CoverageIndex(others)
        counts.append(sum(1 for n in entry["entries"] if not index.overlaps(n) and not is_excluded(n)))
    return counts


def list_name(url):
    return redact(url.split("/")[-1] or url)


def count_unique(kind, group):
    return (unique_domains if kind == "dnsbl" else unique_nets)(group)


def build_prune_plan(kind, group):
    """
    Simulate removing the weakest list (lowest unique, ties: smallest total),
    recount unique for the rest and repeat until no candidate is left.
    Returns [(entry, unique_at_that_step), ...] in removal order.
    """
    remaining, plan = list(group), []
    while len(remaining) > 1:
        uniques = count_unique(kind, remaining)
        candidates = [
            (unique, len(e["entries"]), i)
            for i, (e, unique) in enumerate(zip(remaining, uniques))
            if unique == 0 or unique / len(e["entries"]) * 100 < PRUNE_MAX_PCT
        ]
        if not candidates:
            break
        unique, _, i = min(candidates)
        plan.append((remaining.pop(i), unique))
    return plan


def cover_ok(kind, entry, group, plan_entries):
    """False if some entries are covered only by other lists that are also in the plan."""
    in_plan = {id(e) for e in plan_entries}
    others_in_plan = [e for e in plan_entries if e is not entry]
    if not others_in_plan:
        return True
    kept = [e for e in group if id(e) not in in_plan]
    if kind == "dnsbl":
        kept_set = set().union(*(e["entries"] for e in kept))
        plan_set = set().union(*(e["entries"] for e in others_in_plan))
        return not any(not is_domain_covered(d, kept_set) and is_domain_covered(d, plan_set)
                       for d in entry["entries"])
    kept_index = CoverageIndex(set().union(*(e["entries"] for e in kept)))
    plan_index = CoverageIndex(set().union(*(e["entries"] for e in others_in_plan)))
    return not any(not is_excluded(n) and not kept_index.overlaps(n) and plan_index.overlaps(n)
                   for n in entry["entries"])


def load_previous_runs(path):
    """redundant_runs per list URL from the previous run's output, if any."""
    try:
        with open(path) as f:
            return {l["url"]: int(l.get("redundant_runs") or 0) for l in json.load(f).get("lists", [])}
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        return {}


def main():
    now = datetime.now(timezone.utc)
    print("=== Blocklist Manager – Existing List Analysis ===")
    print(f"Time: {now.strftime('%Y-%m-%d %H:%M UTC')}")

    with open(merge.MY_LISTS_FILE) as f:
        raw = f.read()
    if merge.ABUSECH_KEY and merge.ABUSECH_KEY in raw:
        raise RuntimeError("The abuse.ch key is stored in plain text in my_lists.json - aborting.")
    my_lists = json.loads(raw)

    print("\n[1] Downloading my lists...")
    lists, skipped = [], []
    for kind, key in (("ip", "ip_lists"), ("dnsbl", "dnsbl_lists")):
        for url in my_lists.get(key, []):
            reason = skip_reason(url)
            if reason:
                skipped.append({"url": redact(url), "type": kind, "reason": reason})
                continue
            label = redact(url.split("/")[-1] or url)
            parse = parse_domains if kind == "dnsbl" else parse_ips
            try:
                entries, _ = parse(download(url, label))
                error = None if entries else "no valid entries"
            except Exception as e:
                entries, error = set(), redact(e)
            lists.append({"url": url, "type": kind, "entries": entries, "error": error})
            print(f"    {label}: {'DEAD (' + error + ')' if error else str(len(entries)) + ' entries'}")

    print("\n[2] Counting unique entries and building the prune plan...")
    ok = [entry for entry in lists if entry["error"] is None]
    previous_runs = load_previous_runs(OUTPUT_FILE)
    prune_plan = {}
    for kind in ("ip", "dnsbl"):
        group = [entry for entry in ok if entry["type"] == kind]
        for entry, unique in zip(group, count_unique(kind, group)):
            entry["unique"] = unique
        plan = build_prune_plan(kind, group)
        plan_entries = [e for e, _ in plan]
        first = list_name(plan[0][0]["url"]) if plan else None
        prune_plan[kind] = []
        for step, (entry, unique_at_step) in enumerate(plan, 1):
            entry["prune_step"] = step
            entry["blocked_by"] = first if step > 1 else None
            entry["cover_ok"] = cover_ok(kind, entry, group, plan_entries)
            prune_plan[kind].append({"step": step, "name": list_name(entry["url"]), "url": redact(entry["url"]),
                                     "unique": unique_at_step, "total": len(entry["entries"])})
            print(f"    {kind} step {step}: {list_name(entry['url'])} ({unique_at_step} unique at that step)"
                  f"{'' if entry['cover_ok'] else ' - covered only by lists also in the plan'}")
        if not plan:
            print(f"    {kind}: nothing to prune")

    if any(entry["type"] == "dnsbl" for entry in ok):
        print("\n[3] Sampling DNSBL liveness...")
        if not linter_available():
            print(f"    {LINTER} not installed - using DNS lookups")
            if not dns_works():
                print("    Warning: DNS lookups do not work on this machine - live_pct left empty")

    results = []
    for entry in lists:
        url, total = entry["url"], len(entry["entries"])
        step = entry.get("prune_step")
        result = {"url": redact(url), "type": entry["type"], "name": list_name(url)}
        if entry["error"] is not None:
            result.update(status="dead", total=0, unique=None, unique_pct=None,
                          live_pct=None, redundant=False, error=entry["error"])
        else:
            unique = entry["unique"]
            unique_pct = round(unique / total * 100, 1)
            live = live_pct(entry["entries"], url) if entry["type"] == "dnsbl" else None
            result.update(status="ok", total=total, unique=unique, unique_pct=unique_pct, live_pct=live,
                          redundant=unique < REDUNDANT_MAX_UNIQUE and unique_pct < REDUNDANT_MAX_PCT)
            flag = f"  PRUNE STEP {step}" if step else ""
            print(f"    {redact(url.split('/')[-1] or url)}: {total} total, {unique} unique ({unique_pct}%), "
                  f"live {live if live is not None else '-'}%{flag}")
        # Prune fields: only step 1 is safe now, later steps depend on step 1 being removed first.
        # redundant_runs counts the runs in a row in which this list was the step 1 list.
        result.update(
            prune_step=step,
            safe_now=step == 1,
            blocked_by=entry.get("blocked_by"),
            cover_ok=entry.get("cover_ok"),
            redundant_runs=previous_runs.get(result["url"], 0) + 1 if step == 1 else 0,
        )
        results.append(result)

    text = json.dumps({
        "generated": now.isoformat(),
        "dns_ok": dns_works() if any(e["type"] == "dnsbl" for e in ok) else None,
        "live_check": dict(LIVE_METHODS),
        "prune_plan": prune_plan,
        "lists": results,
        "skipped": skipped,
    }, indent=2)
    if merge.ABUSECH_KEY and merge.ABUSECH_KEY in text:
        raise RuntimeError("Output would contain the abuse.ch key - aborting without publishing.")
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    tmp = OUTPUT_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(text + "\n")
    os.replace(tmp, OUTPUT_FILE)
    print(f"\n=== Done → {OUTPUT_FILE} ===")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print(f"ERROR: {redact(e)}", file=sys.stderr)
        sys.exit(1)
