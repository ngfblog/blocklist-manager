#!/usr/bin/env python3
"""
Shared helpers for merge.py and compare.py.

Keeping the bogon list, the parsers and the overlap check in one place
guarantees both scripts always use exactly the same rules.
"""

import bisect
import ipaddress
import os
import re
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
