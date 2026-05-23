# Blocklist Manager

Automatically merges and deduplicates IP and DNSBL blocklists for pfBlockerNG.  
Runs daily via GitHub Actions. Sends Gotify notification on each update.

---

## How it works

1. GitHub Actions runs daily at 03:00 UTC
2. Downloads all lists defined in `sources.yaml`
3. Merges, deduplicates, and collapses subnets
4. Pushes output files to `/output/`
5. Sends Gotify alert with entry counts

---

## Output URLs (add these to pfBlockerNG)

**IP list:**
```
https://raw.githubusercontent.com/ngfblog/blocklist-manager/main/output/merged_ip.txt
```

**DNSBL list:**
```
https://raw.githubusercontent.com/ngfblog/blocklist-manager/main/output/merged_dnsbl.txt
```

---

## pfBlockerNG setup

### IP list
- pfBlockerNG → IP → IPv4 → Add
- Name: `BLM_Merged_IP`
- Source URL: paste IP URL above
- Action: `Deny Both`
- Update Frequency: `Every 6 hours`

### DNSBL list
- pfBlockerNG → DNSBL → DNSBL Groups → Add
- Name: `BLM_Merged_DNSBL`
- Source URL: paste DNSBL URL above
- Action: `Unbound`
- Update Frequency: `Every 6 hours`

---

## Managing your lists

Edit `sources.yaml` directly in GitHub to add or remove sources.  
The next scheduled run will pick up the changes automatically.

---

## Manual run

Go to Actions → Update Blocklists → Run workflow
