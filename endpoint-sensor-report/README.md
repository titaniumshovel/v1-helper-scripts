# Endpoint Sensor Report

A CLI tool that retrieves endpoint inventory data from the **Trend Vision One** API, optionally enriches it with the **Endpoint Security Agent Readiness Status** from **Server & Workload Protection (S&WP)**, and displays everything in a formatted terminal table with optional CSV export.

## Prerequisites

- Python 3.7 or later
- A **Vision One API token** with *Endpoint Inventory > View* permission
- *(Optional)* A **Server & Workload Protection API key** — only needed if you want the "SWP Agent Readiness" column populated
- Network access to the Vision One and S&WP APIs for your region

> **Security recommendation:** Create both API keys with **read-only roles**. The tool only reads data — a key with write permissions is unnecessary risk.

## Installation

```bash
pip install -r requirements.txt
```

## First-Time Setup (one time only)

```bash
python endpoint_report.py --setup
```

The setup wizard asks three questions:

1. **Region** — your Vision One region code (e.g., `us`)
2. **Vision One API token** — from *Vision One Console → Administration → API Keys*
3. **S&WP API key** *(optional)* — from *S&WP Console → Administration → User Management → API Keys*. Press Enter to skip if you don't use Server & Workload Protection.

Your answers are saved to `config.json` next to the script, so you never have to type them again. Re-run `--setup` any time to change them.

> **Note:** `config.json` contains your API keys in plaintext. Keep it on a machine you control, don't email it, and don't commit it to source control.

## Usage

After setup, just run:

```bash
python endpoint_report.py                      # display table
python endpoint_report.py --csv report.csv     # also export CSV
```

### Optional Arguments

| Argument | Description |
|---|---|
| `--setup` | Run the interactive setup wizard |
| `--csv`, `-o` | Export all fields to a CSV file |
| `--top` | Records per API page: 10, 50, 100, 200, **500** (default), 1000 |
| `--filter`, `-f` | TMV1-Filter expression to narrow results |
| `--no-table` | Skip terminal table display (CSV-only mode) |
| `--no-swp` | Skip S&WP enrichment even if an S&WP key is configured |
| `--token`, `-t` | Vision One token (overrides config.json) |
| `--region`, `-r` | Region code (overrides config.json) |
| `--debug` | Print raw API request/response details for troubleshooting |

### Region Codes

| Code | Region | Vision One FQDN |
|---|---|---|
| `us` | United States | api.xdr.trendmicro.com |
| `au` | Australia | api.au.xdr.trendmicro.com |
| `ca` | Canada | api.ca.xdr.trendmicro.com |
| `de` | Germany | api.eu.xdr.trendmicro.com |
| `in` | India | api.in.xdr.trendmicro.com |
| `jp` | Japan | api.xdr.trendmicro.co.jp |
| `sg` | Singapore | api.sg.xdr.trendmicro.com |
| `za` | South Africa | api.za.xdr.trendmicro.com |
| `uae` | United Arab Emirates | api.mea.xdr.trendmicro.com |
| `uk` | United Kingdom | api.uk.xdr.trendmicro.com |

The S&WP API URL is derived automatically from the same region code — you never need to enter it.

## Examples

**Display all endpoints in a table:**
```bash
python endpoint_report.py
```

**Export to CSV:**
```bash
python endpoint_report.py --csv endpoints_report.csv
```

**Filter to Windows endpoints only:**
```bash
python endpoint_report.py -f "osPlatform eq 'windows'"
```

**Filter to disconnected sensors:**
```bash
python endpoint_report.py -f "edrSensorConnectivity eq 'disconnected'"
```

**Export only (no terminal table):**
```bash
python endpoint_report.py --csv report.csv --no-table
```

## Output

### Health Summary

A color-coded summary prints first with aggregate counts:

- Total endpoints, desktops, and servers
- EPP Agent status (on / off / unknown)
- EDR Sensor status (enabled / disabled / unknown) and connectivity
- Outdated EPP components and isolated endpoint counts
- **SWP readiness counts** — Ready to Install, Install Failed, Agent Installed

Healthy metrics are shown in **green**; concerning metrics are shown in **red**.

### Endpoint Table

The terminal table shows 30 columns grouped by category:

**Identity & OS:**
`Hostname`, `Display Name`, `Agent GUID`, `Type`, `OS`, `Platform`, `OS Version`, `OS Arch`

**Networking & Access:**
`Last IP`, `Last User`, `Isolation`

**EPP Agent (Endpoint Protection):**
`EPP Status`, `EPP Version`, `EPP Products`, `Protection Mgr`, `EPP Group`, `EPP Policy`, `EPP Component Ver`, `EPP Update Status`, `EPP Last Connected`, `EPP Last Scanned`, `Asset Tags`

**EDR Sensor:**
`EDR Status`, `EDR Connectivity`, `EDR Version`, `EDR Group`, `Risk Telemetry`, `EDR Update Status`, `EDR Last Connected`

**Licensing:**
`Licensed Features`

**Server & Workload Protection:**
`SWP Agent Readiness` — the *Endpoint Security Agent Readiness Status* from the S&WP console (Ready to Install, Install Pending, Installing, Install Failed, Endpoint Security Agent Installed, Platform not Supported, Deep Security Agent version not supported, or N/A)

### SWP Agent Readiness Column

This column is populated by querying the S&WP `/api/computers` API and correlating computers to Vision One endpoints **by hostname**. Endpoints that don't exist in S&WP (e.g., Standard Endpoint Protection machines) show an empty value; S&WP computers where readiness doesn't apply show **N/A**, matching the console.

### CSV Export

The CSV export includes **all** fields returned by the API (50+ fields), not just the summary columns, plus the `swp.endpointSecurityAgentReadinessStatus` column.

## Filter Syntax

The `--filter` argument accepts TMV1-Filter expressions. Supported operators: `eq`, `and`, `or`, `not`, `()`.

**Examples:**
```
osPlatform eq 'windows'
edrSensorStatus eq 'enabled'
not (osName eq 'Windows') and eppAgentStatus eq 'on'
type eq 'server' and edrSensorConnectivity eq 'connected'
```

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| No config found | First run without setup | Run `python endpoint_report.py --setup` |
| Authentication failed (401) | Invalid or expired V1 token | Generate a new API key in the Vision One console, re-run `--setup` |
| Error [S&WP]: Authentication failed | Invalid S&WP API key | Generate a new key in the S&WP console, re-run `--setup` |
| Access denied (403) | Insufficient permissions | V1 key needs *Endpoint Inventory > View*; S&WP key needs computer list access |
| Rate limited (429) | Too many requests | The script auto-retries; if persistent, reduce `--top` |
| Connection error | Network or region mismatch | Verify network access and the region code |
| SWP Agent Readiness column empty | Hostname mismatch between V1 and S&WP | Run with `--debug` to see per-computer values and hostnames |
