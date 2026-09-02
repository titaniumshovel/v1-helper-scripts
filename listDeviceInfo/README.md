# listDeviceInfo

A small Windows utility (prebuilt executable) that lists devices currently connected to the machine — USB storage devices, mobile devices, CD/DVD drives, and wireless network adapters. Intended for endpoint triage: quickly see what removable or network hardware is attached, e.g. when investigating unmanaged or suspicious endpoints.

## Contents

| File | Description |
|---|---|
| `listDeviceInfo.exe` | The utility (PE32, 32-bit, Windows GUI) |
| `listDeviceInfo.ini` | Display configuration — which device types to show |
| `Logger.cfg` | Debug logging configuration (disabled by default) |

## Usage

1. Copy the folder to the target Windows machine.
2. Double-click `listDeviceInfo.exe` (or run it from a command prompt).
3. Connected devices matching the enabled display types are listed.

## Configuration

`listDeviceInfo.ini` controls which device categories are displayed:

```ini
[display]
device_type=USB Storage Devices,Mobile Devices,CD/DVD,Wireless Network Adapters
```

- Categories on the `device_type` line are shown.
- Categories commented out with `#` are hidden.
- The four supported categories: `USB Storage Devices`, `Mobile Devices`, `CD/DVD`, `Wireless Network Adapters`.

`Logger.cfg` optionally enables debug logging to `.\listDeviceInfo-debug` — leave the debug level low (`15`) unless troubleshooting.

## Notes

- This is a prebuilt binary, not source — no build steps required.
- 32-bit executable; runs on 64-bit Windows via WOW64.
