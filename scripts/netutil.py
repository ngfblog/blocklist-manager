#!/usr/bin/env python3
"""
Shared helpers for merge.py and compare.py.

Keeping the bogon list, the parsers and the overlap check in one place
guarantees both scripts always use exactly the same rules.
"""

import bisect
import collections
import functools
import hashlib
import ipaddress
import os
import random
import re
import shutil
import socket
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# Networks that must never end up in a block list (private, reserved, documentation)
BOGON_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),          # RFC1918 private
    ipaddress.ip_network("172.16.0.0/12"),       # RFC1918 private
    ipaddress.ip_network("192.168.0.0/16"),      # RFC1918 private
    ipaddress.ip_network("127.0.0.0/8"),         # loopback
    ipaddress.ip_network("169.254.0.0/16"),      # link-local
    ipaddress.ip_network("0.0.0.0/8"),           # "this network"
    ipaddress.ip_network("100.64.0.0/10"),       # CGNAT
    ipaddress.ip_network("224.0.0.0/4"),         # multicast
    ipaddress.ip_network("240.0.0.0/4"),         # reserved / future use
    ipaddress.ip_network("255.255.255.255/32"),  # limited broadcast
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1 (RFC 5737 documentation)
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2 (RFC 5737 documentation)
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3 (RFC 5737 documentation)
]

# Safety net: an entry shorter than this (for example a /1) would block a huge
# part of the internet. Such entries are dropped and reported.
MIN_PREFIX_LEN = 8


def is_bogon(net):
    return any(net.overlaps(b) for b in BOGON_RANGES)


def is_excluded(net):
    """True if the network must not be written to the output."""
    return net.prefixlen < MIN_PREFIX_LEN or is_bogon(net)


def is_self_url(url):
    """True if the URL points to this repository (its own output files)."""
    repo = os.environ.get("GITHUB_REPOSITORY", "").lower()
    marker = f"/{repo}/" if repo else "/blocklist-manager/"
    return marker in url.lower()


def is_geoip_url(url):
    """GeoIP country lists are irrelevant for coverage comparison."""
    return "/ipverse/" in url.lower()


def parse_ips(text):
    """
    Parse IPv4 networks from a list.
    Returns (set_of_networks, skipped_line_count).
    Handles plain IPs, CIDR, trailing comments and the three-column
    "start end prefix" format. IPv6 is ignored on purpose (IPv4 only).
    """
    nets = set()
    skipped = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        line = re.split(r"[#;]", line, maxsplit=1)[0].strip()
        parts = line.split()
        if not parts:
            continue
        entry = parts[0]
        if len(parts) >= 3 and parts[2].isdigit():
            try:
                ipaddress.ip_address(parts[1])
                entry = f"{parts[0]}/{parts[2]}"
            except ValueError:
                pass
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            skipped += 1
            continue
        if net.version == 4:
            nets.add(net)
    return nets, skipped


DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,62}$"
)
HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::1", "::"}


def _extract_host(line):
    line = line.strip()
    if not line or line[0] in "#!;":
        return None, False  # comment or empty: not counted as skipped
    line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
    if line.startswith("||"):
        return line[2:].split("^")[0], True
    if "://" in line:
        try:
            return urlparse(line).hostname, True
        except ValueError:
            return None, True
    parts = line.split()
    if len(parts) >= 2 and parts[0] in HOSTS_IPS:
        return parts[1], True  # hosts format, separated by spaces or tabs
    if len(parts) == 1:
        return parts[0], True
    return None, True


def parse_domains(text):
    """
    Parse domains from a list (plain domains, hosts format with spaces or tabs,
    adblock ||domain^ and URL feeds). Every result is validated.
    Returns (set_of_domains, skipped_line_count).
    """
    domains = set()
    skipped = 0
    for raw in text.splitlines():
        host, counted = _extract_host(raw)
        if not counted:
            continue
        if host:
            host = host.strip().lower()
            if host.startswith("*."):
                host = host[2:]
            host = host.rstrip(".")
        if host and DOMAIN_RE.match(host):
            domains.add(host)
        else:
            skipped += 1
    return domains, skipped


class CoverageIndex:
    """
    Fast "does this network overlap anything I already have?" lookup.
    The base networks are merged into sorted, non-overlapping ranges, so each
    lookup is a binary search instead of a scan over every base network.
    """

    def __init__(self, nets):
        ranges = sorted(
            (int(n.network_address), int(n.broadcast_address))
            for n in nets
            if n.version == 4
        )
        merged = []
        for start, end in ranges:
            if merged and start <= merged[-1][1] + 1:
                if end > merged[-1][1]:
                    merged[-1][1] = end
            else:
                merged.append([start, end])
        self._starts = [m[0] for m in merged]
        self._ends = [m[1] for m in merged]

    def overlaps(self, net):
        if net.version != 4:
            return False
        start = int(net.network_address)
        end = int(net.broadcast_address)
        i = bisect.bisect_right(self._starts, end) - 1
        return i >= 0 and self._ends[i] >= start


# Liveness sampling: what share of a list's domains are still alive. Uses
# AdGuard's Dead Domains Linter when it is installed (see discover.yml), and
# falls back to plain DNS lookups when it is missing or fails.
LIVE_SAMPLE_SIZE = 300
LINTER = "dead-domains-linter"
LINTER_TIMEOUT = 600      # seconds per list
LIVE_TIMEOUT = 3          # seconds per lookup
LIVE_THREADS = 20
DNS_CONTROL_DOMAINS = ("example.com", "wikipedia.org", "cloudflare.com", "microsoft.com")


def _resolves(domain, timeout=LIVE_TIMEOUT):
    """True if the domain resolves within timeout seconds."""
    result = []

    def lookup():
        try:
            result.append(bool(socket.getaddrinfo(domain, None)))
        except (OSError, UnicodeError):
            result.append(False)

    # getaddrinfo has no timeout of its own, so run it in a helper thread
    t = threading.Thread(target=lookup, daemon=True)
    t.start()
    t.join(timeout)
    return bool(result and result[0])


@functools.lru_cache(maxsize=1)
def dns_works():
    """False unless at least 2 well-known domains resolve (a partly blocked resolver counts as broken)."""
    return sum(_resolves(d) for d in DNS_CONTROL_DOMAINS) >= 2


# How the live_pct values of this run were measured, e.g. {"dead-domains-linter": 12}
LIVE_METHODS = collections.Counter()
_linter_failed = False


def linter_available():
    return not _linter_failed and shutil.which(LINTER) is not None


def _linter_dead_count(sample):
    """
    Number of dead domains in sample according to AdGuard's Dead Domains Linter,
    or None if the linter is missing or fails. After one failure the linter is
    not tried again in this run.
    """
    global _linter_failed
    if not linter_available():
        return None
    with tempfile.TemporaryDirectory() as tmp:
        # The linter only checks network rules, bare domain lines are ignored
        with open(os.path.join(tmp, "sample.txt"), "w") as f:
            f.write("".join(f"||{d}^\n" for d in sample))
        try:
            proc = subprocess.run(
                [shutil.which(LINTER), "-i", "sample.txt", "--export", "dead.txt"],
                cwd=tmp, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=LINTER_TIMEOUT,
            )
            log = proc.stdout + proc.stderr
            # A failed lookup is only a warning and the linter still exits 0,
            # so an empty export would look like "nothing is dead". Check the log too.
            failed = proc.returncode != 0 or "Failed to process" in log
            export = os.path.join(tmp, "dead.txt")
            if failed or not os.path.exists(export):
                detail = next((l.strip() for l in log.splitlines() if "Failed" in l), f"exit code {proc.returncode}")
                raise RuntimeError(detail[:200])
            with open(export) as f:
                dead = {line.strip().lower() for line in f if line.strip()}
        except (OSError, subprocess.SubprocessError, RuntimeError) as e:
            print(f"    Warning: {LINTER} failed ({e}) - using DNS lookups instead for the rest of this run")
            _linter_failed = True
            return None
    return len(dead & set(sample))


def _sample(domains, seed_key, sample_size):
    """The same sample every run for an unchanged list (seeded per list)."""
    rng = random.Random(int(hashlib.sha256(seed_key.encode()).hexdigest()[:16], 16))
    pool = sorted(domains)
    return rng.sample(pool, min(sample_size, len(pool)))


def live_pct(domains, seed_key, sample_size=LIVE_SAMPLE_SIZE):
    """
    Percentage of up to sample_size domains that are alive. The sample is
    deterministic per seed_key (e.g. the list URL). Measured with AdGuard's Dead
    Domains Linter (live = 100 - dead/sampled*100), or with DNS lookups if the
    linter is missing or fails. Returns None when nothing could be measured, so
    a failed check is never shown as 0%.
    """
    if not domains:
        return None
    sample = _sample(domains, seed_key, sample_size)
    dead = _linter_dead_count(sample)
    if dead is not None:
        LIVE_METHODS[LINTER] += 1
        return round(100 - dead / len(sample) * 100, 1)
    if not dns_works():
        return None
    with ThreadPoolExecutor(LIVE_THREADS) as ex:
        alive = sum(ex.map(_resolves, sample))
    LIVE_METHODS["dns-lookup"] += 1
    return round(alive / len(sample) * 100, 1)
