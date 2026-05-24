# Blocklist Manager

A self-hosted tool for pfBlockerNG that gives you visibility into your blocklist coverage.

It reads your active lists directly from pfSense, compares them against sources like FireHOL and Hagezi Pro, and shows you exactly what's covered, what overlaps, and what's missing — without downloading everything twice.

**Live demo:** https://ngfblog.github.io/blocklist-manager

---

## What it does

- Reads your active pfBlockerNG URLs directly from pfSense config
- Compares them against FireHOL level1/level2 and Hagezi Pro
- Identifies ecosystem overlap and coverage gaps
- Generates two output files containing only what you don't already have
- Shows a recommendation breakdown in a simple web UI

The output files are optional — add them to pfBlockerNG or use the analysis to decide which sources to add manually.

---

## Why GitHub?

GitHub handles two things here:

1. **Automation** — GitHub Actions runs the daily comparison. No server, no cron job, no Python environment to maintain on your end.
2. **Hosting** — GitHub Pages serves the web UI. The output files are served via raw.githubusercontent.com so pfBlockerNG can pull them directly.

Your config (`my_lists.json`) lives in your own repo. Nothing passes through any third-party server.

---

## Output files

| File | Contains | Optional use |
|------|----------|-------------|
| `output/merged_ip.txt` | IPs from FireHOL not in your lists | Add to pfBlockerNG → IP → IPv4 |
| `output/merged_dnsbl.txt` | Domains from Hagezi Pro not in your lists | Add to pfBlockerNG → DNSBL Groups |

---

## Setup

### Step 1 – Fork this repo

Fork to your own GitHub account and enable GitHub Pages:
- Settings → Pages → Branch: `main` → Folder: `/ (root)` → Save

### Step 2 – Install sync script on pfSense

Copy `pfblockerng_sync.py` to pfSense:

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
7. Copy the token (starts with `ghp_`) — it will not be shown again

Test it:

```bash
python3.11 /root/Scripts/pfblockerng_sync.py
```

Add to cron (pfSense GUI → Services → Cron → Add):
- Minute: `30`
- Hour: `2`
- Day/Month/Weekday: `*`
- Command: `python3.11 /root/Scripts/pfblockerng_sync.py`

### Step 3 – Add output URLs to pfBlockerNG (optional)

**IP gaps** — Firewall → pfBlockerNG → IP → IPv4 → Add:
- Name: `BLM_IP_Gaps`
- Source: `https://raw.githubusercontent.com/YOUR_USERNAME/blocklist-manager/main/output/merged_ip.txt`
- Action: `Deny Both`
- Update Frequency: `Every 6 hours`

**DNSBL gaps** — Firewall → pfBlockerNG → DNSBL → DNSBL Groups → Add:
- Name: `BLM_DNSBL_Gaps`
- Source: `https://raw.githubusercontent.com/YOUR_USERNAME/blocklist-manager/main/output/merged_dnsbl.txt`
- Action: `Unbound`
- Update Frequency: `Every 6 hours`

### Step 4 – Run GitHub Actions

Actions → Update Blocklists → Run workflow

First run takes ~20 minutes. After that it runs automatically every day at 03:00 UTC.

---

## pfSense Sync Script

Download `pfblockerng_sync.py` from this repo and copy to pfSense. Set `GITHUB_TOKEN` and `GITHUB_REPO` at the top of the script.

---

## File structure

```
blocklist-manager/
├── index.html                    # Web UI (GitHub Pages)
├── my_lists.json                 # Your active pfBlockerNG lists (synced from pfSense)
├── README.md
├── requirements.txt
├── pfblockerng_sync.py           # Runs on pfSense via cron
├── .github/
│   └── workflows/
│       └── update.yml
├── scripts/
│   ├── merge.py                  # Generates gap output files
│   └── compare.py                # Generates recommendations
└── output/
    ├── merged_ip.txt
    ├── merged_dnsbl.txt
    ├── recommendations.json
    └── last_run.json
```

---

## Comparison sources

| Type | Source | Coverage |
|------|--------|----------|
| IP | firehol_level1 | Aggregates 10+ trusted sources |
| IP | firehol_level2 | Broader, more aggressive |
| IP | blocklist.de | IPs that attacked SSH/FTP/web in last 48h |
| DNSBL | Hagezi Pro | Large multi-source domain blocklist |

---

## Schedule

| Time | What runs |
|------|-----------|
| 02:30 local | pfSense syncs active list URLs to GitHub |
| 03:00 UTC | GitHub Actions runs comparison and generates output |
| Every 6h | pfBlockerNG fetches updated output files |

---

## Requirements

- pfSense 2.7+ with pfBlockerNG
- Python 3.11 on pfSense (included by default)
- GitHub account (free)
- GitHub Personal Access Token (scope: repo)

---

## Support

This started as a personal homelab project. If it saved you time or improved your setup, a small donation is appreciated.

👉 https://paypal.me/ShopNGF
