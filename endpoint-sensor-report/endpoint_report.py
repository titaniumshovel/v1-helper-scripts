#!/usr/bin/env python3
"""
Endpoint Sensor Report — TrendAI Vision One Endpoint Inventory CLI Tool

Retrieves endpoint inventory data from the Vision One API,
displays a formatted summary table, and optionally exports to CSV.

First-time setup:
    python endpoint_report.py --setup

After setup, just run:
    python endpoint_report.py
    python endpoint_report.py --csv report.csv
"""

import argparse
import csv
import json
import os
import sys
import time

import requests
from rich.console import Console
from rich.table import Table

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

REGION_FQDN_MAP = {
    "us":  "api.xdr.trendmicro.com",
    "au":  "api.au.xdr.trendmicro.com",
    "ca":  "api.ca.xdr.trendmicro.com",
    "de":  "api.eu.xdr.trendmicro.com",
    "in":  "api.in.xdr.trendmicro.com",
    "jp":  "api.xdr.trendmicro.co.jp",
    "sg":  "api.sg.xdr.trendmicro.com",
    "za":  "api.za.xdr.trendmicro.com",
    "uae": "api.mea.xdr.trendmicro.com",
    "uk":  "api.uk.xdr.trendmicro.com",
}

# S&WP region → FQDN mapping.  The S&WP API lives on a different host
# from the Vision One API, but the region code the user already knows
# maps directly so they never have to think about it.
SWP_REGION_FQDN_MAP = {
    "us":  "workload.us-1.cloudone.trendmicro.com",
    "au":  "workload.au-1.cloudone.trendmicro.com",
    "ca":  "workload.ca-1.cloudone.trendmicro.com",
    "de":  "workload.de-1.cloudone.trendmicro.com",
    "in":  "workload.in-1.cloudone.trendmicro.com",
    "jp":  "workload.jp-1.cloudone.trendmicro.com",
    "sg":  "workload.sg-1.cloudone.trendmicro.com",
    "uk":  "workload.gb-1.cloudone.trendmicro.com",
}

API_PATH = "/v3.0/endpointSecurity/endpoints"

# Server & Workload Protection (S&WP) API
SWP_API_PATH = "/api/computers"
SWP_PAGE_SIZE = 5000
SWP_API_VERSION = "v1"

# The S&WP API field for "Endpoint Security Agent Readiness Status".
# Confirmed in the official API schema: a top-level property on the
# computer object with kebab-case values (e.g. "ready-to-install").
# The field is omitted for computers where it doesn't apply (console
# shows "N/A" for those).
SWP_READINESS_FIELD = "v1AgentReadiness"

# Map raw API values to the labels shown in the S&WP console.
# Unknown values fall back to prettified kebab-case (dashes → spaces).
SWP_READINESS_LABELS = {
    "ready-to-install": "Ready to Install",
    "install-pending": "Install Pending",
    "installing": "Installing",
    "install-failed": "Install Failed",
    "installed": "Endpoint Security Agent Installed",
    "agent-installed": "Endpoint Security Agent Installed",
    "platform-not-supported": "Platform not Supported",
    "dsa-version-not-supported": "Deep Security Agent version not supported",
    "agent-version-not-supported": "Deep Security Agent version not supported",
}

DEFAULT_PAGE_SIZE = 500
MAX_RETRIES = 3

# Columns shown in the terminal table — field key → friendly header.
# Ordered to group identity, OS, networking, EPP Agent, EDR Sensor, and licensing.
SUMMARY_COLUMNS = {
    "endpointName":                          "Hostname",
    "displayName":                           "Display Name",
    "agentGuid":                             "Agent GUID",
    "type":                                  "Type",
    "os.name":                               "OS",
    "os.platform":                           "Platform",
    "os.version":                            "OS Version",
    "os.architecture":                       "OS Arch",
    "lastUsedIp":                            "Last IP",
    "lastLoggedOnUser":                      "Last User",
    "isolationStatus":                       "Isolation",
    # --- EPP Agent ---
    "eppAgent.status":                       "EPP Status",
    "eppAgent.version":                      "EPP Version",
    "eppAgent.productNames":                 "EPP Products",
    "eppAgent.protectionManager":            "Protection Mgr",
    "eppAgent.endpointGroup":                "EPP Group",
    "eppAgent.policyName":                   "EPP Policy",
    "eppAgent.componentVersion":             "EPP Component Ver",
    "eppAgent.componentUpdateStatus":        "EPP Update Status",
    "eppAgent.lastConnectedDateTime":        "EPP Last Connected",
    "eppAgent.lastScannedDateTime":          "EPP Last Scanned",
    "eppAgent.tags":                         "Asset Tags",
    # --- EDR Sensor ---
    "edrSensor.status":                      "EDR Status",
    "edrSensor.connectivity":                "EDR Connectivity",
    "edrSensor.version":                     "EDR Version",
    "edrSensor.endpointGroup":               "EDR Group",
    "edrSensor.advancedRiskTelemetryStatus": "Risk Telemetry",
    "edrSensor.componentUpdateStatus":       "EDR Update Status",
    "edrSensor.lastConnectedDateTime":       "EDR Last Connected",
    # --- Licensing ---
    "creditAllocatedLicenses":               "Licensed Features",
    # --- Server & Workload Protection ---
    "swp.endpointSecurityAgentReadinessStatus": "SWP Agent Readiness",
}


# ---------------------------------------------------------------------------
# Config File (one-time setup saves creds so users never type them again)
# ---------------------------------------------------------------------------


def load_config():
    """Load saved config from config.json next to this script.

    Returns an empty dict if the file doesn't exist.
    """
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Warning: Could not read {CONFIG_FILE}: {exc}")
        return {}


def save_config(config):
    """Write config dict to config.json next to this script."""
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    print(f"\nConfig saved to {CONFIG_FILE}")


def run_setup():
    """Interactive first-time setup wizard. Prompts for keys, saves config."""
    print("=" * 60)
    print("  Endpoint Report — First-Time Setup")
    print("=" * 60)
    print()

    existing = load_config()

    # --- Region ---
    regions = sorted(REGION_FQDN_MAP.keys())
    default_region = existing.get("region", "")
    print(f"Available regions: {', '.join(regions)}")
    if default_region:
        region = (
            input(f"Region [{default_region}]: ").strip().lower()
            or default_region
        )
    else:
        region = input("Region: ").strip().lower()
    if region not in REGION_FQDN_MAP:
        sys.exit(f"Error: Invalid region '{region}'.")

    # --- V1 Token ---
    print()
    print("Vision One API token")
    print("  (Console → Administration → API Keys)")
    default_v1 = existing.get("v1_token", "")
    if default_v1:
        masked = default_v1[:8] + "..." + default_v1[-4:]
        v1_token = (
            input(f"V1 Token [{masked}]: ").strip() or default_v1
        )
    else:
        v1_token = input("V1 Token: ").strip()
    if not v1_token:
        sys.exit("Error: Vision One token is required.")

    # --- S&WP Key (optional) ---
    print()
    print("Server & Workload Protection API key (optional)")
    print("  (S&WP Console → Administration → User Management → API Keys)")
    print("  Press Enter to skip if you don't use S&WP.")
    default_swp = existing.get("swp_key", "")
    if default_swp:
        masked = default_swp[:8] + "..." + default_swp[-4:]
        swp_key = input(f"S&WP Key [{masked}]: ").strip() or default_swp
    else:
        swp_key = input("S&WP Key: ").strip()

    config = {
        "region": region,
        "v1_token": v1_token,
    }
    if swp_key:
        config["swp_key"] = swp_key

    save_config(config)

    print()
    print("Setup complete! You can now run:")
    print("  python endpoint_report.py")
    print("  python endpoint_report.py --csv report.csv")
    print()
    print("To change settings later, run:")
    print("  python endpoint_report.py --setup")


# ---------------------------------------------------------------------------
# CLI Argument Parsing
# ---------------------------------------------------------------------------


def parse_args():
    """Build and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Retrieve and display TrendAI Vision One endpoint inventory.",
        epilog=(
            "First-time setup (saves your keys so you never type them again):\n"
            "  python endpoint_report.py --setup\n"
            "\n"
            "After setup, just run:\n"
            "  python endpoint_report.py\n"
            "  python endpoint_report.py --csv report.csv\n"
            '  python endpoint_report.py -f "osPlatform eq \'windows\'"'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run interactive first-time setup (saves keys to config.json)",
    )
    parser.add_argument(
        "--token", "-t",
        default=None,
        help="Vision One API token (overrides config.json)",
    )
    parser.add_argument(
        "--region", "-r",
        default=None,
        choices=sorted(REGION_FQDN_MAP.keys()),
        help="Region code (overrides config.json)",
    )
    parser.add_argument(
        "--csv", "-o",
        metavar="FILE",
        default=None,
        help="Export results to the specified CSV file path",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        choices=[10, 50, 100, 200, 500, 1000],
        help=f"Number of records per API page (default: {DEFAULT_PAGE_SIZE})",
    )
    parser.add_argument(
        "--filter", "-f",
        default=None,
        dest="filter_expr",
        help='TMV1-Filter expression (e.g., "osPlatform eq \'windows\'")',
    )
    parser.add_argument(
        "--no-table",
        action="store_true",
        help="Skip terminal table display (useful when only exporting CSV)",
    )
    parser.add_argument(
        "--no-swp",
        action="store_true",
        help="Skip S&WP enrichment even if an S&WP key is configured",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print raw API response headers and body for troubleshooting",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# API Interaction
# ---------------------------------------------------------------------------


def handle_response_error(response):
    """Check for HTTP errors and print user-friendly messages.

    Returns "rate_limited" if a 429 was received so the caller can retry.
    Exits the process on non-retryable errors.
    """
    if response.status_code == 401:
        sys.exit(
            "Error: Authentication failed. Check that your API token "
            "is valid and has not expired."
        )
    if response.status_code == 403:
        sys.exit(
            "Error: Access denied. Ensure the API key role has "
            "'Endpoint Inventory > View' permission."
        )
    if response.status_code == 429:
        return "rate_limited"
    if response.status_code >= 400:
        try:
            err = response.json().get("error", {})
            msg = err.get("message", response.text)
        except (ValueError, AttributeError):
            msg = response.text
        sys.exit(f"Error: API returned {response.status_code}: {msg}")
    return None


def fetch_all_endpoints(base_url, token, top=DEFAULT_PAGE_SIZE,
                        filter_expr=None, debug=False):
    """Fetch all endpoints from the Vision One API, handling pagination.

    Args:
        base_url: The full base URL (e.g., https://api.xdr.trendmicro.com).
        token: Bearer authentication token.
        top: Number of records per page.
        filter_expr: Optional TMV1-Filter expression string.
        debug: If True, print raw request/response details.

    Returns:
        A list of raw endpoint dicts from the API.
    """
    url = f"{base_url}{API_PATH}"
    headers = {
        "Authorization": f"Bearer {token}",
    }
    if filter_expr:
        headers["TMV1-Filter"] = filter_expr

    params = {"top": top}
    all_endpoints = []
    page = 1

    while url:
        retries = 0
        response = None

        if debug:
            print(f"\n  [DEBUG] Request URL: {url}")
            print(f"  [DEBUG] Params: {params}")
            safe_headers = {
                k: (v[:20] + "...REDACTED") if k == "Authorization" else v
                for k, v in headers.items()
            }
            print(f"  [DEBUG] Headers: {safe_headers}")

        while retries < MAX_RETRIES:
            try:
                response = requests.get(
                    url, headers=headers, params=params, timeout=60
                )
            except requests.ConnectionError:
                sys.exit(
                    f"Error: Cannot connect to {url}. "
                    "Check your network connection and region."
                )
            except requests.Timeout:
                sys.exit("Error: Request timed out after 60 seconds.")

            result = handle_response_error(response)
            if result == "rate_limited":
                retries += 1
                retry_after = int(response.headers.get("Retry-After", 60))
                print(
                    f"  Rate limited. Waiting {retry_after}s before retry "
                    f"({retries}/{MAX_RETRIES})..."
                )
                time.sleep(retry_after)
                continue
            break  # Successful response or fatal error (already exited)

        if retries >= MAX_RETRIES:
            sys.exit(
                "Error: Rate limit exceeded after maximum retries. "
                "Try again later or reduce the page size with --top."
            )

        if debug:
            print(f"  [DEBUG] Response status: {response.status_code}")
            print(f"  [DEBUG] Response headers:")
            for k, v in response.headers.items():
                print(f"    {k}: {v}")
            # Print full body on first page, truncated on subsequent
            body_text = response.text
            if page == 1 or len(body_text) < 2000:
                print(f"  [DEBUG] Response body:\n{body_text}")
            else:
                print(f"  [DEBUG] Response body (truncated):\n{body_text[:2000]}...")

        data = response.json()
        items = data.get("items", [])
        all_endpoints.extend(items)
        total = data.get("totalCount", "?")
        print(
            f"  Page {page}: fetched {len(items)} endpoints "
            f"({len(all_endpoints)}/{total} total)"
        )

        # nextLink is a fully-qualified URL with skipToken included.
        # Clear params so we don't double-encode query parameters.
        url = data.get("nextLink")
        params = {}
        page += 1

    return all_endpoints


# ---------------------------------------------------------------------------
# Server & Workload Protection API
# ---------------------------------------------------------------------------


def handle_swp_response_error(response):
    """Check for HTTP errors from the S&WP API.

    Returns "rate_limited" on 429 so the caller can retry.
    Exits the process on non-retryable errors.
    """
    if response.status_code == 401:
        sys.exit(
            "Error [S&WP]: Authentication failed. Check that your "
            "S&WP API secret key is valid (run --setup to update it)."
        )
    if response.status_code == 403:
        sys.exit(
            "Error [S&WP]: Access denied. Ensure the API key has "
            "permission to list computers."
        )
    if response.status_code == 429:
        return "rate_limited"
    if response.status_code >= 400:
        try:
            msg = response.json().get("message", response.text)
        except (ValueError, AttributeError):
            msg = response.text
        sys.exit(f"Error [S&WP]: API returned {response.status_code}: {msg}")
    return None


def fetch_swp_computers(swp_url, swp_key, debug=False):
    """Fetch all computers from the S&WP / Workload Security API.

    Uses id-based pagination: each page returns up to SWP_PAGE_SIZE
    computers, and the next page is requested with idValue/idType params.

    Args:
        swp_url: Base URL (e.g., https://workload.us-1.cloudone.trendmicro.com).
        swp_key: API secret key for S&WP.
        debug: If True, print raw request/response details.

    Returns:
        A list of raw computer dicts from the API.
    """
    url = f"{swp_url.rstrip('/')}{SWP_API_PATH}"
    headers = {
        "api-secret-key": swp_key,
        "api-version": SWP_API_VERSION,
        "Content-Type": "application/json",
    }
    all_computers = []
    page = 1
    last_id = 0

    while True:
        params = {}
        if last_id > 0:
            params["idValue"] = last_id
            params["idType"] = "id-greater-than"

        if debug:
            print(f"\n  [DEBUG S&WP] Request URL: {url}")
            print(f"  [DEBUG S&WP] Params: {params}")

        retries = 0
        response = None

        while retries < MAX_RETRIES:
            try:
                response = requests.get(
                    url, headers=headers, params=params, timeout=60
                )
            except requests.ConnectionError:
                sys.exit(
                    f"Error [S&WP]: Cannot connect to {url}. "
                    "Check your network connection and region."
                )
            except requests.Timeout:
                sys.exit("Error [S&WP]: Request timed out after 60 seconds.")

            result = handle_swp_response_error(response)
            if result == "rate_limited":
                retries += 1
                retry_after = int(response.headers.get("Retry-After", 60))
                print(
                    f"  [S&WP] Rate limited. Waiting {retry_after}s before "
                    f"retry ({retries}/{MAX_RETRIES})..."
                )
                time.sleep(retry_after)
                continue
            break

        if retries >= MAX_RETRIES:
            sys.exit(
                "Error [S&WP]: Rate limit exceeded after maximum retries."
            )

        data = response.json()

        # S&WP returns {"computers": [...]} for list endpoints
        computers = data.get("computers", [])
        if not computers:
            break

        if debug and page == 1:
            print("  [DEBUG S&WP] Sample computer object (first):")
            print(f"  {json.dumps(computers[0], indent=2, default=str)}")

        all_computers.extend(computers)
        print(
            f"  [S&WP] Page {page}: fetched {len(computers)} computers "
            f"({len(all_computers)} total)"
        )

        # If we got fewer than the page size, there are no more pages
        if len(computers) < SWP_PAGE_SIZE:
            break

        # Next page starts after the last ID in this batch
        last_id = computers[-1].get("ID", 0)
        page += 1

    return all_computers


def format_readiness_value(raw):
    """Convert a raw v1AgentReadiness API value to its console label.

    e.g. "ready-to-install" → "Ready to Install".
    Unknown values are prettified (dashes → spaces, title case).
    """
    if not raw:
        return "N/A"
    label = SWP_READINESS_LABELS.get(str(raw).strip().lower())
    if label:
        return label
    return str(raw).replace("-", " ").strip().title()


def build_swp_readiness_lookup(computers, debug=False):
    """Build a hostname → readiness-status lookup from S&WP computers.

    Reads the documented `v1AgentReadiness` field from each computer.
    Computers without the field (e.g. unmanaged) get "N/A", matching
    what the S&WP console displays.

    Returns:
        dict mapping lowercase hostname → readiness status label.
    """
    lookup = {}
    with_field = 0

    for comp in computers:
        hostname = comp.get("hostName", "")
        if not hostname:
            continue

        raw = comp.get(SWP_READINESS_FIELD)
        if raw:
            with_field += 1
        lookup[hostname.lower()] = format_readiness_value(raw)

        if debug:
            print(
                f"  [DEBUG S&WP] {hostname}: "
                f"{SWP_READINESS_FIELD}={raw!r} → "
                f"'{lookup[hostname.lower()]}'"
            )

    print(
        f"  [S&WP] {with_field}/{len(lookup)} computers report "
        f"'{SWP_READINESS_FIELD}' (others show N/A)."
    )
    return lookup


# ---------------------------------------------------------------------------
# Data Processing
# ---------------------------------------------------------------------------


def flatten_endpoint(endpoint):
    """Flatten a nested endpoint dict into a single-level dict with dotted keys.

    Nested dicts produce dotted keys (e.g., os.name, eppAgent.status).
    Lists of primitives are joined with "; ".
    Lists of objects are JSON-serialized per element, then joined with "; ".
    """
    flat = {}

    def _flatten(obj, prefix=""):
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_key = f"{prefix}.{key}" if prefix else key
                _flatten(value, new_key)
        elif isinstance(obj, list):
            parts = []
            for item in obj:
                if isinstance(item, dict):
                    parts.append(json.dumps(item, ensure_ascii=False))
                else:
                    parts.append(str(item))
            flat[prefix] = "; ".join(parts)
        else:
            flat[prefix] = obj if obj is not None else ""

    _flatten(endpoint)
    return flat


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------


def build_health_summary(endpoints_flat):
    """Compute aggregate health stats from the flattened endpoint list."""
    total = len(endpoints_flat)
    stats = {
        "Total Endpoints":        total,
        "Desktops":               0,
        "Servers":                0,
        # EPP
        "EPP Agent On":           0,
        "EPP Agent Off":          0,
        "EPP Agent Unknown":      0,
        # EDR
        "EDR Sensor Enabled":     0,
        "EDR Sensor Disabled":    0,
        "EDR Sensor Unknown":     0,
        "EDR Connected":          0,
        "EDR Disconnected":       0,
        # Component health
        "EPP Components Outdated": 0,
        "Isolated Endpoints":     0,
        # S&WP readiness
        "SWP Ready to Install":   0,
        "SWP Install Failed":     0,
        "SWP Agent Installed":    0,
    }

    for ep in endpoints_flat:
        ep_type = str(ep.get("type", "")).lower()
        if ep_type == "desktop":
            stats["Desktops"] += 1
        elif ep_type == "server":
            stats["Servers"] += 1

        # EPP status
        epp_status = str(ep.get("eppAgent.status", "")).lower()
        if epp_status == "on":
            stats["EPP Agent On"] += 1
        elif epp_status == "off":
            stats["EPP Agent Off"] += 1
        else:
            stats["EPP Agent Unknown"] += 1

        # EDR sensor status
        edr_status = str(ep.get("edrSensor.status", "")).lower()
        if edr_status == "enabled":
            stats["EDR Sensor Enabled"] += 1
        elif edr_status == "disabled":
            stats["EDR Sensor Disabled"] += 1
        else:
            stats["EDR Sensor Unknown"] += 1

        # EDR connectivity
        edr_conn = str(ep.get("edrSensor.connectivity", "")).lower()
        if edr_conn == "connected":
            stats["EDR Connected"] += 1
        elif edr_conn == "disconnected":
            stats["EDR Disconnected"] += 1

        # Component version
        comp_ver = str(ep.get("eppAgent.componentVersion", "")).lower()
        if comp_ver == "outdatedversion":
            stats["EPP Components Outdated"] += 1

        # Isolation
        iso = str(ep.get("isolationStatus", "")).lower()
        if iso == "on":
            stats["Isolated Endpoints"] += 1

        # S&WP agent readiness
        readiness = str(
            ep.get("swp.endpointSecurityAgentReadinessStatus", "")
        ).lower()
        if readiness:
            if readiness == "ready to install":
                stats["SWP Ready to Install"] += 1
            elif readiness == "install failed":
                stats["SWP Install Failed"] += 1
            elif "installed" in readiness:
                stats["SWP Agent Installed"] += 1

    return stats


def display_health_summary(stats, console):
    """Print a compact health-check summary above the main table."""
    table = Table(
        title="Health Summary",
        show_header=False,
        box=None,
        padding=(0, 2),
    )
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    for metric, value in stats.items():
        style = ""
        # Highlight concerning values in red
        if value > 0 and metric in (
            "EPP Agent Off", "EDR Sensor Disabled", "EDR Disconnected",
            "EPP Components Outdated", "Isolated Endpoints",
            "SWP Install Failed",
        ):
            style = "red"
        elif value > 0 and metric in (
            "EPP Agent On", "EDR Sensor Enabled", "EDR Connected",
            "SWP Agent Installed",
        ):
            style = "green"
        table.add_row(metric, str(value), style=style)

    console.print(table)
    console.print()


def display_table(endpoints_flat):
    """Render a summary table in the terminal using rich."""
    console = Console()

    # Health summary first
    stats = build_health_summary(endpoints_flat)
    display_health_summary(stats, console)

    # Main endpoint table
    table = Table(
        title=f"Endpoint Inventory — {len(endpoints_flat)} endpoint(s)",
        show_lines=True,
        row_styles=["", "dim"],
    )

    for col_key, col_header in SUMMARY_COLUMNS.items():
        table.add_column(col_header, overflow="fold", max_width=32)

    for ep in endpoints_flat:
        row = [str(ep.get(col, "")) for col in SUMMARY_COLUMNS]
        table.add_row(*row)

    console.print(table)


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------


def export_csv(endpoints_flat, filepath):
    """Export all flattened endpoint data to a CSV file.

    The CSV header is the union of all keys across every endpoint,
    preserving insertion order. Missing values become empty cells.
    """
    if not endpoints_flat:
        print("No endpoints to export.")
        return

    # Collect all unique keys in first-seen order
    all_keys = []
    seen = set()
    for ep in endpoints_flat:
        for key in ep.keys():
            if key not in seen:
                all_keys.append(key)
                seen.add(key)

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        for ep in endpoints_flat:
            writer.writerow(ep)

    print(
        f"Exported {len(endpoints_flat)} endpoints to {filepath} "
        f"({len(all_keys)} columns)"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    args = parse_args()

    # --setup: interactive wizard, then exit
    if args.setup:
        run_setup()
        sys.exit(0)

    # Load saved config — CLI args override config values
    config = load_config()

    token = args.token or config.get("v1_token")
    region = args.region or config.get("region")

    if not token or not region:
        if not os.path.exists(CONFIG_FILE):
            print("No config found. Run first-time setup:\n")
            print("  python endpoint_report.py --setup\n")
        else:
            print("Missing token or region. Run setup to fix:\n")
            print("  python endpoint_report.py --setup\n")
        sys.exit(1)

    if region not in REGION_FQDN_MAP:
        sys.exit(f"Error: Invalid region '{region}'.")

    fqdn = REGION_FQDN_MAP[region]
    base_url = f"https://{fqdn}"

    print(f"Connecting to Vision One ({region.upper()}: {fqdn})...")
    print(f"Fetching endpoints (page size: {args.top})...")
    if args.filter_expr:
        print(f"  Filter: {args.filter_expr}")

    endpoints_raw = fetch_all_endpoints(
        base_url, token, args.top, args.filter_expr, args.debug
    )

    if not endpoints_raw:
        print("\nNo endpoints found.")
        if args.filter_expr:
            print(f"  Filter used: {args.filter_expr}")
            print("  Verify the filter expression is correct.")
        sys.exit(0)

    print(f"\nRetrieved {len(endpoints_raw)} endpoint(s). Processing...\n")

    # Flatten nested JSON into dotted-key dicts
    endpoints_flat = [flatten_endpoint(ep) for ep in endpoints_raw]

    # --- S&WP enrichment (automatic if key is configured) ---
    swp_key = config.get("swp_key")
    if swp_key and not args.no_swp:
        swp_fqdn = SWP_REGION_FQDN_MAP.get(region)
        if not swp_fqdn:
            print(
                f"  [S&WP] Skipping — no S&WP API URL mapped for "
                f"region '{region}'. Use --debug to troubleshoot.\n"
            )
        else:
            swp_url = f"https://{swp_fqdn}"
            print(f"Fetching S&WP data ({swp_fqdn})...")
            swp_computers = fetch_swp_computers(
                swp_url, swp_key, args.debug
            )

            if swp_computers:
                print(
                    f"  Retrieved {len(swp_computers)} S&WP computer(s). "
                    "Correlating by hostname..."
                )
                readiness_lookup = build_swp_readiness_lookup(
                    swp_computers, args.debug
                )

                # Merge readiness status into flattened endpoints.
                # Always set the column so it appears in CSV for every row.
                matched = 0
                for ep in endpoints_flat:
                    hostname = str(ep.get("endpointName", "")).lower()
                    if hostname and hostname in readiness_lookup:
                        ep["swp.endpointSecurityAgentReadinessStatus"] = (
                            readiness_lookup[hostname]
                        )
                        matched += 1
                    else:
                        ep.setdefault(
                            "swp.endpointSecurityAgentReadinessStatus", ""
                        )

                print(
                    f"  Matched {matched}/{len(endpoints_flat)} endpoints "
                    f"with S&WP data.\n"
                )
            else:
                print("  No S&WP computers found.\n")
                # Still ensure the column exists in every row
                for ep in endpoints_flat:
                    ep.setdefault(
                        "swp.endpointSecurityAgentReadinessStatus", ""
                    )

    # Count total unique fields across all endpoints
    all_keys = set()
    for ep in endpoints_flat:
        all_keys.update(ep.keys())

    # Terminal table display
    if not args.no_table:
        display_table(endpoints_flat)
        print(
            f"\nShowing {len(SUMMARY_COLUMNS)} columns in table. "
            f"Full data has {len(all_keys)} fields. "
            "Use --csv FILE to export all fields."
        )

    # CSV export
    if args.csv:
        print()
        export_csv(endpoints_flat, args.csv)

    if not args.csv and args.no_table:
        print(
            "Nothing to display. Use --csv FILE to export, "
            "or remove --no-table to see results."
        )


if __name__ == "__main__":
    main()
