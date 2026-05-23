# Blocklist Manager

A self-hosted tool that automatically finds and fills the gaps in your pfBlockerNG blocklists.

**Live demo:** https://ngfblog.github.io/blocklist-manager

---

## How it works

```
pfSense (daily at 02:30)
    pfblockerng_sync.py reads your active pfBlockerNG URLs from config.xml
    pushes my_lists.json to GitHub

GitHub Actions (daily at 03:00 UTC)
    merge.py downloads firehol_level1 + firehol_level2 + Hagezi Pro
    removes everything already covered by your pfBlockerNG lists
    saves only the GAPS to output/merged_ip.txt and output/merged_dnsbl.txt

    compare.py compares your lists against firehol sources
    saves recommendations to output/recommendations.json

Web UI (GitHub Pages)
    reads my_lists.json → shows your active pfBlockerNG lists
    reads recommendations.json → shows what you are missing
    merged_ip.txt and merged_dnsbl.txt → add these to pfBlockerNG
```

---

## What you get

| Output file | What it contains | Add to pfBlockerNG |
|-------------|-----------------|-------------------|
| `output/merged_ip.txt` | IPs from firehol not covered by your lists | IP → IPv4 |
| `output/merged_dnsbl.txt` | Domains from Hagezi Pro not covered by your lists | DNSBL → DNSBL Groups |

---

## Setup

### Step 1 – Fork this repo

Fork to your own GitHub account and enable GitHub Pages:
- Settings → Pages → Branch: `main` → Folder: `/ (root)` → Save

### Step 2 – Install sync script on pfSense

Copy `pfblockerng_sync.py` to pfSense via SCP or paste manually:

```bash
scp pfblockerng_sync.py root@YOUR_PFSENSE_IP:/root/Scripts/
```

Edit the script and set your GitHub token:

```bash
nano /root/Scripts/pfblockerng_sync.py
```

Replace `YOUR_GITHUB_TOKEN_HERE` with a GitHub Personal Access Token.

**How to create a token:**
1. Go to https://github.com/settings/tokens
2. Click **Generate new token (classic)**
3. Note: `blocklist-manager`
4. Expiration: `No expiration`
5. Scopes: check **repo** only
6. Click **Generate token**
7. Copy the token (starts with `ghp_`) – it will not be shown again

Test it:

```bash
python3.11 /root/Scripts/pfblockerng_sync.py
```

Add to cron (pfSense GUI → Services → Cron → Add):
- Minute: `30`
- Hour: `2`
- Day/Month/Weekday: `*`
- Command: `python3.11 /root/Scripts/pfblockerng_sync.py`

### Step 3 – Add output URLs to pfBlockerNG

**IP gaps** – Firewall → pfBlockerNG → IP → IPv4 → Add:
- Name: `BLM_IP_Gaps`
- Source: `https://raw.githubusercontent.com/YOUR_USERNAME/blocklist-manager/main/output/merged_ip.txt`
- Action: `Deny Both`
- Update Frequency: `Every 6 hours`

**DNSBL gaps** – Firewall → pfBlockerNG → DNSBL → DNSBL Groups → Add:
- Name: `BLM_DNSBL_Gaps`
- Source: `https://raw.githubusercontent.com/YOUR_USERNAME/blocklist-manager/main/output/merged_dnsbl.txt`
- Action: `Unbound`
- Update Frequency: `Every 6 hours`

### Step 4 – Run GitHub Actions

Actions → Update Blocklists → Run workflow

Wait ~20 minutes for the first run.
After that, runs automatically every day at 03:00 UTC.

---

## pfSense Sync Script (pfblockerng_sync.py)

```python
#!/usr/bin/env python3
"""
pfBlockerNG Sync Script
Reads active URLs from pfSense config.xml and pushes to GitHub as my_lists.json
Run daily via cron on pfSense
"""

import xml.etree.ElementTree as ET
import json
import urllib.request
import urllib.error
import base64
from datetime import datetime, timezone

# ── Configuration ──────────────────────────────────────────────
CONFIG_XML    = "/cf/conf/config.xml"
GITHUB_TOKEN  = "YOUR_GITHUB_TOKEN_HERE"
GITHUB_REPO   = "YOUR_USERNAME/blocklist-manager"
GITHUB_FILE   = "my_lists.json"
GITHUB_BRANCH = "main"
# ───────────────────────────────────────────────────────────────

def read_pfblockerng_urls():
    tree = ET.parse(CONFIG_XML)
    root = tree.getroot()

    ip_keywords    = ["spamhaus", "emergingthreats", "firehol", "blocklist.de", "abuseipdb", "drop.txt"]
    dnsbl_keywords = ["hagezi", "oisd", "openphish", "urlhaus", "stevenblack", "hosts", "hostfile", "dnsbl", "adblock", "feed.txt"]

    all_urls = []
    for el in root.iter("url"):
        if el.text and el.text.strip().startswith("http"):
            all_urls.append(el.text.strip())

    ip_urls    = []
    dnsbl_urls = []

    for url in all_urls:
        if "127.0.0.1" in url or "localhost" in url:
            continue
        url_lower = url.lower()
        if any(k in url_lower for k in ip_keywords):
            if url not in ip_urls:
                ip_urls.append(url)
        elif any(k in url_lower for k in dnsbl_keywords):
            if url not in dnsbl_urls:
                dnsbl_urls.append(url)
        else:
            if "/hosts/" in url_lower or "hostfile" in url_lower:
                if url not in dnsbl_urls:
                    dnsbl_urls.append(url)
            else:
                if url not in ip_urls:
                    ip_urls.append(url)

    return ip_urls, dnsbl_urls


def get_github_file_sha(token, repo, filepath, branch):
    url = f"https://api.github.com/repos/{repo}/contents/{filepath}?ref={branch}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"token {token}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data.get("sha", "")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return ""
        raise


def push_to_github(token, repo, filepath, content, branch, sha=""):
    url = f"https://api.github.com/repos/{repo}/contents/{filepath}"
    content_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")
    payload = {
        "message": f"sync: update pfBlockerNG lists {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "content": content_b64,
        "branch": branch
    }
    if sha:
        payload["sha"] = sha
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("Authorization", f"token {token}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status in (200, 201)
    except urllib.error.HTTPError as e:
        print(f"GitHub push error: {e.code} {e.read().decode()}")
        return False


def main():
    print("=== pfBlockerNG Sync ===")
    print(f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

    ip_urls, dnsbl_urls = read_pfblockerng_urls()

    print(f"  IP lists:    {len(ip_urls)}")
    for u in ip_urls:
        print(f"    {u}")
    print(f"  DNSBL lists: {len(dnsbl_urls)}")
    for u in dnsbl_urls:
        print(f"    {u}")

    my_lists = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "source": "pfSense config.xml",
        "ip_lists": ip_urls,
        "dnsbl_lists": dnsbl_urls
    }

    content = json.dumps(my_lists, indent=2)
    sha = get_github_file_sha(GITHUB_TOKEN, GITHUB_REPO, GITHUB_FILE, GITHUB_BRANCH)
    success = push_to_github(GITHUB_TOKEN, GITHUB_REPO, GITHUB_FILE, content, GITHUB_BRANCH, sha)

    if success:
        print(f"  Done – {GITHUB_FILE} updated on GitHub")
    else:
        print("  ERROR – push failed")


if __name__ == "__main__":
    main()
```

---

## File structure

```
blocklist-manager/
├── index.html                    # Web UI (GitHub Pages)
├── my_lists.json                 # Your active pfBlockerNG lists (auto-updated by pfSense)
├── README.md                     # This file
├── requirements.txt              # Python dependencies
├── pfblockerng_sync.py           # Script to run on pfSense
├── .github/
│   └── workflows/
│       └── update.yml            # GitHub Actions workflow
├── scripts/
│   ├── merge.py                  # Finds gaps and generates output files
│   └── compare.py                # Compares against firehol sources
└── output/
    ├── merged_ip.txt             # IP gaps to add to pfBlockerNG
    ├── merged_dnsbl.txt          # DNSBL gaps to add to pfBlockerNG
    ├── recommendations.json      # Shown in Recommendations tab
    └── last_run.json             # Last run stats
```

---

## Comparison sources

| Type | Source | What it covers |
|------|--------|---------------|
| IP | firehol_level1 | Top consensus – aggregates 10+ trusted sources |
| IP | firehol_level2 | Broader coverage, more aggressive |
| IP | blocklist.de | IPs that attacked SSH/FTP/web in last 48h |
| DNSBL | Hagezi Pro | Comprehensive domain blocklist from multiple sources |

---

## Auto-update schedule

| Time | What runs |
|------|-----------|
| 02:30 local | pfSense cron runs pfblockerng_sync.py |
| 03:00 UTC | GitHub Actions runs merge.py + compare.py |
| Every 6h | pfBlockerNG fetches merged_ip.txt and merged_dnsbl.txt |

---

## Requirements

- pfSense 2.7+ with pfBlockerNG installed
- Python 3.11 on pfSense (included by default)
- GitHub account (free)
- GitHub Personal Access Token (scope: repo)
