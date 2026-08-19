from __future__ import annotations

import time

from uet.config import Config
from uet.worklist import WorklistItem

_RUNNING = {"Name": "instance-state-name", "Values": ["running"]}


def _resolve_instance_id(ec2, item: WorklistItem) -> tuple[str | None, str | None]:
    tiers = [("tag:Name", [item.hostname]), ("private-dns-name", [item.hostname])]
    if item.ips:
        tiers.append(("private-ip-address", item.ips))
    tried = [name for name, _ in tiers]
    for name, values in tiers:
        resp = ec2.describe_instances(Filters=[{"Name": name, "Values": values}, _RUNNING])
        ids = [i["InstanceId"] for r in resp["Reservations"] for i in r["Instances"]]
        if len(ids) == 1:
            return ids[0], None
        if len(ids) > 1:
            return None, (f"ambiguous EC2 match for {item.hostname} on {name}: "
                          f"{', '.join(ids)}")
    return None, (f"no running EC2 instance found for {item.hostname} "
                  f"(tried {', '.join(tried)})")


def run_host(item: WorklistItem, payload_path: str, mode: str,
             dry_run: bool, cfg: Config):
    from uet.transports import HostResult

    try:
        import boto3  # type: ignore
    except ImportError:
        raise SystemExit("ssm transport requires: pip install 'uet[ssm]'")
    region = cfg.ssm_region or None
    ec2 = boto3.client("ec2", region_name=region)
    ssm = boto3.client("ssm", region_name=region)

    iid, err = _resolve_instance_id(ec2, item)
    if err:
        return HostResult(item.hostname, False, "", err, 1)

    with open(payload_path, encoding="utf-8") as f:
        script = f.read()
    is_ps = payload_path.endswith(".ps1")
    doc = "AWS-RunPowerShellScript" if is_ps else "AWS-RunShellScript"
    if is_ps:
        prefix = f"$env:UET_MODE='{mode}'\n" + ("$env:UET_DRY_RUN='1'\n" if dry_run else "")
    else:
        prefix = f"export UET_MODE={mode}\n" + ("export UET_DRY_RUN=1\n" if dry_run else "")
    from botocore.exceptions import ClientError  # type: ignore
    # NOTE: SSM caps command payloads (~100KB); embedded deployment scripts fit,
    # but if a tenant's script is huge use an S3-based document instead (README caveat).
    try:
        resp = ssm.send_command(
            InstanceIds=[iid],
            DocumentName=doc,
            Parameters={"commands": [prefix + script]},
            TimeoutSeconds=1200,
        )
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "InvalidInstanceId":
            return HostResult(item.hostname, False, "",
                              f"instance {iid} found but not registered with SSM "
                              f"(agent missing/offline, or no instance profile)", 1)
        raise
    cmd_id = resp["Command"]["CommandId"]
    for _ in range(120):
        time.sleep(10)
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=iid)
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        if inv["Status"] in ("Success", "Failed", "TimedOut", "Cancelled"):
            return HostResult(item.hostname, inv["Status"] == "Success",
                              inv.get("StandardOutputContent", ""),
                              inv.get("StandardErrorContent", ""),
                              inv.get("ResponseCode", 1))
    return HostResult(item.hostname, False, "", "ssm polling timed out", 124)
