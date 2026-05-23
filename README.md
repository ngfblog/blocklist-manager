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

## pfSense Sync Script

Download `pfblockerng_sync.py` from this repo and copy to pfSense:

```bash
scp pfblockerng_sync.py root@YOUR_PFSENSE_IP:/root/Scripts/
```

Edit the file and set your `GITHUB_TOKEN` and `GITHUB_REPO` at the top of the script.

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
