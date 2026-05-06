import json
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from awscan.aws.session import get_session
from awscan.aws import s3, iam, ec2, network, cloudtrail, accessanalyzer

from awscan.checks import (
    attack_path_checks,
    access_analyzer_checks,
    cloudtrail_checks,
    ebs_checks,
    imdsv2_checks,
    s3_checks,
    iam_checks,
    root_mfa_checks,
    sg_checks,
    vpc_checks,
    subnet_checks,
    route_checks,
    igw_checks,
)

from awscan.core.runner import run_checks_parallel
from awscan.core.finding_catalog import enrich_findings

app = typer.Typer(name="awscan")
console = Console()
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}


def should_fail(results, fail_on):
    if not fail_on:
        return False

    threshold = fail_on.upper()
    threshold_rank = SEVERITY_RANK[threshold]

    for finding in results:
        severity = finding.get("severity", "INFO").upper()
        severity_rank = SEVERITY_RANK.get(severity, SEVERITY_RANK["INFO"])
        if severity_rank >= threshold_rank:
            return True

    return False


@app.command()
def scan(
    json_out: Path | None = typer.Option(
        None,
        "--json-out",
        "-j",
        help="Write scan results to a JSON file",
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Fail with exit code 1 when findings include this severity or higher",
    ),
):
    console.print("[bold cyan]⚡ AWS Scan Started[/bold cyan]\n")

    normalized_fail_on = None
    if fail_on:
        normalized_fail_on = fail_on.upper()
        if normalized_fail_on not in SEVERITY_RANK:
            raise typer.BadParameter(
                f"Invalid --fail-on severity '{fail_on}'. "
                f"Use one of: {', '.join(SEVERITY_ORDER)}"
            )

    session = get_session()

    checks = [
        lambda s: s3_checks.check_public_buckets(s, s3),
        lambda s: iam_checks.check_admin_roles(s, iam),
        lambda s: sg_checks.check_open_ports(s, ec2),
        lambda s: vpc_checks.check_vpc_dns(s, network),
        lambda s: subnet_checks.check_public_subnets(s, network),
        lambda s: route_checks.check_public_routes(s, network),
        lambda s: igw_checks.check_internet_gateways(s, network),
        lambda s: attack_path_checks.check_public_to_admin_exploit_path(s, network, ec2, iam),
        lambda s: cloudtrail_checks.check_cloudtrail_enabled(s, cloudtrail),
        lambda s: root_mfa_checks.check_root_mfa_enabled(s, iam),
        lambda s: access_analyzer_checks.check_access_analyzer_enabled(s, accessanalyzer),
        lambda s: ebs_checks.check_ebs_encryption(s, ec2),
        lambda s: imdsv2_checks.check_imdsv2_required(s, ec2),
    ]

    results = run_checks_parallel(checks, session)
    results = enrich_findings(results)
    severity_counts = {}
    for finding in results:
        severity = finding.get("severity", "UNKNOWN")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    report_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(results),
        "severity_counts": severity_counts,
        "findings": results,
    }

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
        console.print(f"[bold blue]JSON report saved:[/bold blue] {json_out}")

    table = Table(title="🚨 AWS Findings")

    table.add_column("Type", style="cyan")
    table.add_column("Resource", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Risk", style="yellow")
    table.add_column("Message", style="white")

    if not results:
        console.print("[bold green]✅ No issues found[/bold green]")
        return

    for r in results:
        table.add_row(
            r["type"],
            r["resource"],
            r["severity"],
            str(r.get("risk_score", "n/a")),
            r["message"]
        )

    console.print(table)
    console.print(f"\n[bold]Total findings:[/bold] {len(results)}")

    if normalized_fail_on and should_fail(results, normalized_fail_on):
        console.print(
            f"[bold red]Failing due to findings at or above {normalized_fail_on}[/bold red]"
        )
        raise typer.Exit(code=1)


def main():
    app(prog_name="awscan")


if __name__ == "__main__":
    main()
