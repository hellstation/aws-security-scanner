import typer
from rich.console import Console
from rich.table import Table

from awscan.aws.session import get_session
from awscan.aws import s3, iam, ec2, network

from awscan.checks import (
    s3_checks,
    iam_checks,
    sg_checks,
    vpc_checks,
    subnet_checks,
    route_checks,
    igw_checks,
)

from awscan.core.runner import run_checks_parallel

app = typer.Typer(name="awscan")
console = Console()


@app.command()
def scan():
    console.print("[bold cyan]⚡ AWS Scan Started[/bold cyan]\n")

    session = get_session()

    checks = [
        lambda s: s3_checks.check_public_buckets(s, s3),
        lambda s: iam_checks.check_admin_roles(s, iam),
        lambda s: sg_checks.check_open_ports(s, ec2),
        lambda s: vpc_checks.check_vpc_dns(s, network),
        lambda s: subnet_checks.check_public_subnets(s, network),
        lambda s: route_checks.check_public_routes(s, network),
        lambda s: igw_checks.check_internet_gateways(s, network),
    ]

    results = run_checks_parallel(checks, session)

    table = Table(title="🚨 AWS Findings")

    table.add_column("Type", style="cyan")
    table.add_column("Resource", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Message", style="white")

    if not results:
        console.print("[bold green]✅ No issues found[/bold green]")
        return

    for r in results:
        table.add_row(
            r["type"],
            r["resource"],
            r["severity"],
            r["message"]
        )

    console.print(table)
    console.print(f"\n[bold]Total findings:[/bold] {len(results)}")


def main():
    app(prog_name="awscan")


if __name__ == "__main__":
    main()
