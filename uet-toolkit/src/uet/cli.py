from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="uet", description="Unmanaged Endpoints Toolkit")
    parser.add_argument("--config", default="uet.toml")
    parser.add_argument("--key-file", default=None,
                        help="file containing the V1 API secret")
    parser.add_argument("--swp-key-file", default=None,
                        help="file containing the SWP API secret (separate from --key-file; "
                             "the V1 key does not work for SWP)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_triage = sub.add_parser("triage", help="classify unmanaged endpoints into action buckets")
    p_triage.add_argument("--axonius-csv", default=None)
    p_triage.add_argument("--refresh", action="store_true", help="ignore cached snapshots")
    p_triage.add_argument("--dns-timeout", type=float, default=5.0,
                          help="per-hostname DNS lookup timeout in seconds (default 5.0); "
                               "a lookup that exceeds it is treated as inconclusive, not 'gone'")
    p_triage.add_argument("--dns-workers", type=int, default=32,
                          help="max concurrent DNS lookups (ThreadPoolExecutor size, default 32)")
    p_triage.add_argument("--no-dns", action="store_true",
                          help="skip DNS liveness entirely; every lookup is inconclusive, so no "
                               "host is marked DNS-gone (STALE is then driven only by Axonius/V1)")

    p_run = sub.add_parser("run", help="run payloads against worklist hosts")
    p_run.add_argument("--transport", choices=["ssh", "winrm", "ssm"], required=True)
    p_run.add_argument("--mode", choices=["safe", "reinstall", "install"], default="safe")
    p_run.add_argument("--dry-run", action="store_true")
    p_run.add_argument("--canary", type=int, default=None, help="only run first N hosts")
    p_run.add_argument("--bucket", default=None, help="only hosts in this bucket")
    p_run.add_argument("--allow-public-target", action="store_true",
                       help="skip the connect-target safety check for ssh/winrm. By "
                            "default a host is refused if it has no private IP and its "
                            "hostname resolves outside RFC1918 / [run] allowed_cidrs, "
                            "since dialling it would reach a third party on the public "
                            "internet rather than the host (typical of ISP reverse-DNS "
                            "hostnames). Only use this if you know the range is yours.")

    p_collect = sub.add_parser("collect", help="merge results and verify against console")
    p_collect.add_argument("--settle-attempts", type=int, default=3,
                            help="number of times to re-poll SWP for hosts to settle")
    p_collect.add_argument("--settle-delay", type=int, default=60,
                            help="seconds to wait between settle attempts")

    p_del = sub.add_parser("delete", help="delete approved STALE computers from SWP")
    p_del.add_argument("--approved-csv", required=True)
    p_del.add_argument("--execute", action="store_true", help="actually delete (default: dry-run)")
    p_del.add_argument("--allow-non-stale", action="store_true",
                       help="permit deleting approved rows whose bucket is not STALE. "
                            "Off by default: a NEEDS_REPAIR/NEEDS_INSTALL host still has "
                            "an agent that can be fixed, and deleting its record discards "
                            "the activation history instead of repairing it.")

    args = parser.parse_args(argv)

    if args.command == "triage":
        from uet.triage import cmd_triage
        return cmd_triage(args)
    if args.command == "run":
        from uet.transports import cmd_run
        return cmd_run(args)
    if args.command == "collect":
        from uet.collect import cmd_collect
        return cmd_collect(args)
    if args.command == "delete":
        from uet.delete import cmd_delete
        return cmd_delete(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
