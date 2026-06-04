# Troubleshooting Guide

## Common Issues & Solutions

### ❌ No Security Events Appearing in Log Analytics

**Symptoms:**
- KQL query returns 0 results
- EventID 4625 not showing up after 10+ minutes

**Diagnostic Steps:**
1. **On the VM**, check Windows Event Viewer:
   ```powershell
   # Open Event Viewer
   eventvwr.msc
   # Navigate to: Windows Logs → Security → Filter by EventID 4625
   ```

2. **Verify Log Analytics Agent is running:**
   ```powershell
   Get-Service HealthService
   # Should return: Running
   ```

3. **Check DCR (Data Collection Rule) assignment:**
   - Azure Portal → Monitor → Data Collection Rules
   - Verify VM is listed under "Resources"

4. **Verify NSG inbound rule:**
   ```bash
   az network nsg rule list \
     --resource-group rg-honeypot-lab \
     --nsg-name vm-honeypot-nsg
   ```
   Should include a rule allowing ALL inbound traffic.

5. **Test connectivity:**
   ```bash
   # From local machine
   nmap -p 3389 <vm-public-ip>
   # Should return: open (not filtered)
   ```

**Solution:**
- If Agent not running: Reinstall Azure Monitor Agent (AMA)
- If NSG rule missing: Add inbound allow-all rule
- If DCR not assigned: Create/reassign data collection rule

---

### ❌ Failed Logon Events (EventID 4625) Disabled

**Symptoms:**
- Events appear briefly, then stop

**Solution:**
```powershell
# Re-enable audit policy on VM
auditpol /set /subcategory:"Logon" /failure:enable

# Verify
auditpol /get /subcategory:"Logon"
# Should show: Failure: Enabled
```

---

### ❌ GeoIP Watchlist Not Joining in KQL

**Symptoms:**
- Query returns NULL for `country_name`, `latitude`, `longitude`
- Join fails silently

**Diagnostic Steps:**
1. **Verify watchlist exists and has data:**
   ```kql
   _GetWatchlist('geoip')
   | count
   ```
   Should return > 1000 rows

2. **Check watchlist columns:**
   ```kql
   _GetWatchlist('geoip')
   | getschema
   ```
   Should include: `network`, `country_name`, `city_name`, `latitude`, `longitude`

3. **Test join manually:**
   ```kql
   SecurityEvent
   | where EventID == 4625
   | take 5
   | project IpAddress
   | join kind=leftouter (
       _GetWatchlist('geoip')
       | project network
   ) on $left.IpAddress == $right.network
   ```

**Common Issues:**
- Watchlist name misspelled (must be exactly `geoip`)
- Network format mismatch (e.g., CIDR notation vs. IP range)
- CSV columns not matching query expectations

**Solution:**
- Recreate watchlist with correct name: `geoip`
- Ensure CSV has exact column names: `network,country_name,city_name,latitude,longitude`
- Use `column_ifexists()` in query for graceful fallback

---

### ❌ Incidents Not Triggering (Alert Rule Returns 0)

**Symptoms:**
- Analytics rule created but no incidents/alerts generated
- Query runs manually but shows data

**Diagnostic Steps:**
1. **Check rule is enabled:**
   - Sentinel → Analytics → Your Rule → Verify "Status" = "Enabled"

2. **Test query execution:**
   ```kql
   // Run rule query in Log Analytics
   SecurityEvent
   | where EventID == 4625
   | summarize FailedAttempts = count() by IpAddress
   | where FailedAttempts > 5
   ```

3. **Review rule configuration:**
   - Alert trigger threshold (e.g., > 5 failed attempts)
   - Time window (e.g., last 5 minutes)
   - Grouping settings

**Solution:**
- Lower threshold: Change from `> 10` to `> 3` for testing
- Extend query time window: Change `ago(5m)` to `ago(1h)`
- Manually test rule by running attack (see Phase 8 in SETUP.md)

---

### ❌ Azure Costs Exceeding Budget

**Symptoms:**
- Daily charges $10–20 higher than expected
- Log ingestion costs spiking

**Cause:**
- High-volume event ingestion (1000s events/min during attack)
- VM running 24/7
- Sentinel workspace retention (default 30 days)

**Cost Reduction Steps:**
1. **Stop VM when not in use:**
   ```bash
   az vm deallocate --resource-group rg-honeypot-lab --name vm-honeypot
   ```

2. **Scale down VM size:**
   ```bash
   az vm resize \
     --resource-group rg-honeypot-lab \
     --name vm-honeypot \
     --size Standard_B1s
   ```

3. **Adjust data retention:**
   - Log Analytics → Workspace Settings → Data Retention
   - Lower from 30 to 7–14 days

4. **Delete resource group entirely:**
   ```bash
   az group delete --resource-group rg-honeypot-lab --yes
   ```

---

### ❌ Map Visualization Not Rendering

**Symptoms:**
- Workbook loads but map shows no markers
- Performance is very slow

**Diagnostic Steps:**
1. **Check if latitude/longitude values are present:**
   ```kql
   SecurityEvent
   | where EventID == 4625
   | join kind=leftouter (
       _GetWatchlist('geoip')
       | project network, latitude, longitude
   ) on $left.IpAddress == $right.network
   | where isnotempty(latitude) and isnotempty(longitude)
   | count
   ```

2. **If count is low**, GeoIP enrichment failed (see GeoIP Watchlist troubleshooting above)

3. **For slow rendering:**
   - Limit to last 24 hours (not 30 days)
   - Aggregate by country instead of individual IPs
   - Reduce marker count: `top 100 by TotalAttempts`

**Solution:**
```kql
// Fast map query - country-level aggregation
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize FailedAttempts = count() by IpAddress
| join kind=leftouter (
    _GetWatchlist('geoip')
    | project network, country_name, latitude, longitude
) on $left.IpAddress == $right.network
| summarize TotalAttempts = sum(FailedAttempts) by country_name, latitude, longitude
| top 50 by TotalAttempts
| render map with (kind=marker)
```

---

### ❌ Firewall Disabled But VM Still Not Accessible

**Symptoms:**
- NSG rule is "Allow All"
- But `nmap` or `telnet` shows "filtered"

**Cause:**
- Windows Defender Firewall still active inside OS
- NSG rule not applied yet

**Solution:**
```powershell
# On VM - Disable all firewall profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $false

# Verify all disabled
Get-NetFirewallProfile
# Should show: Enabled = False for all profiles
```

---

### ❌ Azure Monitor Agent Failing to Connect

**Symptoms:**
- Event Viewer shows errors about agent connectivity
- Data Collection Rule status shows "Failed"

**Solution:**
```powershell
# Reinstall AMA
$uri = "https://aka.ms/dependencyagentwindows"
Invoke-WebRequest -Uri $uri -OutFile "InstallDependencyAgent-Windows.exe"
.\InstallDependencyAgent-Windows.exe /S

# Restart agent service
Restart-Service -Name HealthService

# Verify
Get-Service HealthService
# Should return: Running
```

---

## Quick Diagnostic Checklist

```
VM & Networking:
☐ NSG inbound rule allows ALL (port 0-65535, source 0.0.0.0/0)
☐ VM firewall disabled (Get-NetFirewallProfile)
☐ Failed logon audit enabled (auditpol)
☐ EventID 4625 appears in Event Viewer

Agent & Data Collection:
☐ Azure Monitor Agent installed (Services → HealthService running)
☐ Data Collection Rule exists and assigned to VM
☐ Log Analytics Workspace is receiving data

Sentinel & Queries:
☐ Sentinel deployed and enabled on workspace
☐ KQL query returns results in Log Analytics
☐ GeoIP Watchlist has > 1000 rows and columns match query
☐ Analytics rule is enabled with correct threshold

Costs:
☐ Understand estimated monthly charges (~$170–200)
☐ VM deallocated or deleted when not using lab
☐ Log retention set to reasonable duration (7–30 days)
```

---

## Getting Help

- **Sentinel Queries**: [KQL Documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- **Azure Support**: [Azure Help + Support](https://portal.azure.com/#blade/Microsoft_Azure_Support/HelpAndSupportBlade)
- **GitHub Issues**: [Report on this repo](https://github.com/cyr6x/azure-soc-honeypot/issues)

---

**Happy debugging!** 🔍
