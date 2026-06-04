# Azure SOC Honeypot Lab

![Azure](https://img.shields.io/badge/Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Query%20Language-blueviolet?style=for-the-badge)
![SIEM](https://img.shields.io/badge/SIEM-Security%20Operations-red?style=for-the-badge)
![Honeypot](https://img.shields.io/badge/Honeypot-Threat%20Intelligence-orange?style=for-the-badge)

---

## Architecture

```
+-------------------+        RDP/SSH Brute Force
|   Internet / WAN  | ---------------------------------------->
+-------------------+                                          |
                                                               v
                                              +--------------------------------+
                                              |  Azure VM (Honeypot)           |
                                              |  Windows 10/Server             |
                                              |  Firewall: ALL INBOUND OPEN    |
                                              +----------------+---------------+
                                                               |
                                              Event Logs (4625 Failed Logons)
                                                               |
                                                               v
                                              +--------------------------------+
                                              |  Log Analytics Workspace       |
                                              |  (SecurityEvent table)         |
                                              +----------------+---------------+
                                                               |
                                              KQL Query + GeoIP Watchlist Join
                                                               |
                                                               v
                                              +--------------------------------+
                                              |  Microsoft Sentinel            |
                                              |  - Workbooks (Attack Map)      |
                                              |  - Analytics Rules             |
                                              |  - Incidents & Alerts          |
                                              +--------------------------------+
```

---

## Objectives

- Deploy an intentionally vulnerable Azure VM honeypot exposed to live internet brute-force traffic
- Ingest Windows Security Event logs (EventID 4625) into a Log Analytics Workspace
- Enrich failed logon events with geolocation data using a custom GeoIP watchlist in Microsoft Sentinel
- Build KQL queries to detect, aggregate, and visualise attack origin by country and IP
- Map findings to real-world SOC workflows and Security+ domain competencies

---

## Setup Phases

1. **Provision Azure VM** — Deploy Windows VM, disable firewall, expose all inbound ports
2. **Create Log Analytics Workspace** — Connect VM via Azure Monitor Agent (AMA)
3. **Deploy Microsoft Sentinel** — Attach Sentinel to the Log Analytics Workspace
4. **Upload GeoIP Watchlist** — Import CSV watchlist (`geoip-summarized.csv`) mapping IP ranges to countries
5. **Write KQL Detection Queries** — Query `SecurityEvent` for EventID 4625, join GeoIP watchlist
6. **Build Sentinel Workbook (Attack Map)** — Visualise attacker origins on a world map
7. **Trigger & Observe Attacks** — Monitor live brute-force attempts within 30–60 minutes

---

## KQL — Failed RDP Logons Enriched with GeoIP

```kql
// See kql-queries/failed_logons.kql for full query
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, Account, Computer
| join kind=leftouter (
    _GetWatchlist('geoip')
    | project network = column_ifexists('network', ''),
              country_name = column_ifexists('country_name', ''),
              city_name = column_ifexists('city_name', ''),
              latitude = column_ifexists('latitude', ''),
              longitude = column_ifexists('longitude', '')
) on $left.IpAddress == $right.network
| project IpAddress, Account, Computer, FailedAttempts, country_name, city_name, latitude, longitude
| order by FailedAttempts desc
```

---

## Skills Demonstrated

| Skill | Tool / Technique | Security+ Domain |
|---|---|---|
| Threat Detection & Monitoring | Microsoft Sentinel, KQL | Domain 4 — Security Operations |
| Log Analysis | Log Analytics Workspace, SecurityEvent table | Domain 4 — Security Operations |
| Threat Intelligence | GeoIP Watchlist, Attack Map | Domain 1 — General Security Concepts |
| Network Exposure & Honeypots | Azure VM, Inbound NSG rules | Domain 1 — General Security Concepts |
| Incident Identification | EventID 4625, Brute-force detection | Domain 4 — Security Operations |
| SIEM Administration | Sentinel Workbooks, Analytics Rules | Domain 4 — Security Operations |

---

## Lessons Learned

Exposing a cloud VM to the public internet results in brute-force attempts within minutes, demonstrating how pervasive automated credential-stuffing attacks are in the wild. Enriching raw log data with GeoIP context transforms noise into actionable threat intelligence, highlighting the importance of data correlation in SOC environments. This lab reinforced that effective detection engineering is less about collecting data and more about asking precise questions of that data through well-crafted queries.

---

## Screenshots

### Attack Map
![Attack Map](screenshots/attack-map.png)

### KQL Query Results
![KQL Results](screenshots/kql-results.png)

---

## Repository Structure

```
azure-soc-honeypot/
├── README.md
├── kql-queries/
│   └── failed_logons.kql
├── screenshots/
│   ├── attack-map.png          <- upload after lab
│   └── kql-results.png         <- upload after lab
└── architecture/
    └── diagram.png             <- export from draw.io
```
