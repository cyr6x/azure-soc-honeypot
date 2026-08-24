# Azure SOC Honeypot Lab

An intentionally exposed Windows VM on Azure, feeding Microsoft Sentinel — built to practice the SOC workflow end to end: ingest logs, enrich them with threat intel, detect, and visualize.

## What it does

A Windows VM with an open NSG rule sits on the public internet and gets scanned/brute-forced automatically within minutes of going live, as any exposed host does. Failed RDP logons (Event ID 4625) flow into a Log Analytics workspace via Azure Monitor Agent, get joined against a custom GeoIP watchlist in KQL, and surface on a Sentinel workbook as a live attack map. Analytics rules alert above a configurable failed-attempt threshold.

## Why I built it

Reading about SIEM workflows and running one are different skills. I wanted to go from zero to a working detection pipeline on infrastructure I provisioned myself — NSGs, Data Collection Rules, watchlists, KQL joins — the parts of SOC work that don't show up in a certification syllabus.

## Architecture

`[SCREENSHOT: architecture diagram — VM → AMA/DCR → Log Analytics → Sentinel → Workbook]`

## Detection logic (simplified)
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, Account, Computer
| join kind=leftouter (
    _GetWatchlist('geoip')
    | project network, country_name, city_name, latitude, longitude
) on $left.IpAddress == $right.network
| where FailedAttempts > 5
| order by FailedAttempts desc
```
Left-outer join so events without a GeoIP match aren't silently dropped; aggregated by IP/account/computer to cut noise before the alert threshold fires.

## What I found

Attack traffic began arriving within minutes of the VM going public, from a broad spread of source countries — consistent with automated botnet scanning rather than a targeted attack. GeoIP enrichment made it possible to see that spread at a glance on the Sentinel workbook map rather than reading raw IPs.

## MITRE ATT&CK / Security+ mapping

| Detection | Event ID | Technique | Security+ Domain |
|---|---|---|---|
| Failed RDP logon | 4625 | T1110 Brute Force | 4.1 Monitoring & Logging |
| Attack aggregation | 4625 | T1110.004 Credential Stuffing | 4.2 Event Analysis |
| GeoIP enrichment | watchlist join | T1598 (threat intel context) | 4.3 Threat Intelligence |
| Alert rule | 4625 | T1087 Account Discovery | 4.4 Incident Response |

## Tech stack

Azure VM, Network Security Groups, Azure Monitor Agent + Data Collection Rules, Log Analytics Workspace, Microsoft Sentinel, KQL.

## Running this yourself

1. Provision a Windows VM with an intentionally permissive inbound NSG rule
2. Create a Log Analytics Workspace and attach Microsoft Sentinel
3. Configure Azure Monitor Agent to collect Windows Security Events (4625)
4. Upload a GeoIP CSV as a Sentinel watchlist
5. Deploy the KQL analytics rule above
6. Build a workbook to visualize results on a map

Full steps: [`docs/SETUP.md`](docs/SETUP.md) · Troubleshooting: [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)

⚠️ **Cost note:** this isn't free-tier. Sentinel + Log Analytics ingestion + a running VM ran me roughly $170–200/month at full scale — deallocate the VM between sessions and trim log retention to control cost. Delete the resource group when you're done.

## Repo structure
```
azure-soc-honeypot/
├── docs/SETUP.md
├── docs/TROUBLESHOOTING.md
├── kql-queries/failed_logons.kql
└── screenshots/
```

`[SCREENSHOT: Sentinel workbook attack map]`
`[SCREENSHOT: KQL query results — enriched failed-logon table]`

## License

MIT — see [LICENSE](LICENSE) for details.
