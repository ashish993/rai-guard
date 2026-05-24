"""
rai-guard CLI tool.

Commands:
  raiguard audit   — scan a file/text for AI safety issues
  raiguard serve   — start the OpenAI-compatible proxy server
  raiguard report  — generate a compliance evidence report
  raiguard check   — one-off text check with output
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    _RICH = True
except ImportError:
    _RICH = False


console = Console() if _RICH else None


def _print(msg: str, style: str = "") -> None:
    if _RICH and console:
        console.print(msg, style=style)
    else:
        click.echo(msg)


# ── Main group ────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(package_name="raiguard")
def main() -> None:
    """rai-guard — Runtime Responsible AI Compliance Engine.\n
    Enforce OWASP LLM Top 10, EU AI Act, and NIST AI RMF at runtime.
    """


# ── audit ─────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("text_or_file")
@click.option("--checks", "-c", default=None, help="Comma-separated check names (default: all)")
@click.option("--output", "-o", default=None, help="Output JSON results to file")
@click.option("--direction", "-d", type=click.Choice(["input", "output"]), default="input",
              help="Check as prompt input or LLM output")
def audit(text_or_file: str, checks: Optional[str], output: Optional[str], direction: str) -> None:
    """Audit TEXT_OR_FILE for responsible AI policy violations.

    TEXT_OR_FILE can be a string literal or path to a .txt/.json file.
    """
    # Resolve text
    path = Path(text_or_file)
    if path.exists() and path.is_file():
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            try:
                data = json.loads(text)
                text = data.get("prompt") or data.get("content") or data.get("text") or text
            except json.JSONDecodeError:
                pass
    else:
        text = text_or_file

    check_list = [c.strip() for c in checks.split(",")] if checks else None

    from raiguard.instrument import AIGuard
    guard = AIGuard(checks=check_list, block_on_fail=False)

    async def _run() -> None:
        if direction == "input":
            result = await guard.check_input(text)
        else:
            result = await guard.check_output(text)
        return result

    result = asyncio.run(_run())

    if _RICH and console:
        _render_audit_result(result, text[:100])
    else:
        click.echo(json.dumps(result.to_dict(), indent=2))

    if output:
        Path(output).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        _print(f"Results saved to {output}", style="dim")

    sys.exit(0 if result.allowed else 1)


def _render_audit_result(result: "GuardResult", text_preview: str) -> None:  # type: ignore[name-defined]
    from rich.table import Table
    from rich.panel import Panel

    status = "[green]✓ ALLOWED[/green]" if result.allowed else "[red]✗ BLOCKED[/red]"
    console.print(Panel(
        f"{status}  |  Risk score: [bold]{result.risk_score:.3f}[/bold]  |  Session: {result.session_id[:8]}",
        title="[bold]rai-guard Audit[/bold]",
        subtitle=f"Input preview: {text_preview!r}",
    ))

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Score")
    table.add_column("Severity")
    table.add_column("OWASP")
    table.add_column("Details")

    for r in result.check_results:
        status_cell = "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]"
        table.add_row(
            r.check_name,
            status_cell,
            f"{r.score:.3f}",
            r.severity.value,
            ", ".join(r.owasp_refs),
            str(r.details)[:60] if r.details else "",
        )

    console.print(table)


# ── serve ─────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", "-p", default=8000, show_default=True)
@click.option("--upstream", default="https://api.openai.com",
              show_default=True, help="Upstream LLM API base URL")
@click.option("--no-block", is_flag=True, default=False, help="Log violations but don't block requests")
def serve(host: str, port: int, upstream: str, no_block: bool) -> None:
    """Start the OpenAI-compatible rai-guard proxy server."""
    import os
    os.environ["RAI_UPSTREAM_URL"] = upstream
    os.environ["RAI_BLOCK_ON_FAIL"] = "false" if no_block else "true"

    _print(f"[bold green]rai-guard proxy[/bold green] starting on http://{host}:{port}/v1", "")
    _print(f"  Upstream: {upstream}", "dim")
    _print(f"  Block on fail: {not no_block}", "dim")

    try:
        import uvicorn
        from raiguard.proxy import app as proxy_app
        uvicorn.run(proxy_app, host=host, port=port, log_level="info")
    except ImportError:
        click.echo("uvicorn is required to run the proxy. Install with: pip install uvicorn", err=True)
        sys.exit(1)


# ── dashboard ─────────────────────────────────────────────────────────────────

@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", "-p", default=8080, show_default=True)
@click.option("--db", default="raiguard_audit.db", show_default=True, help="Path to evidence SQLite DB")
def dashboard(host: str, port: int, db: str) -> None:
    """Launch the rai-guard web dashboard."""
    import os
    os.environ["RAI_DB_PATH"] = db

    _print(f"[bold cyan]rai-guard dashboard[/bold cyan] starting on http://{host}:{port}", "")

    try:
        import uvicorn
        from raiguard.dashboard.app import app as dash_app
        uvicorn.run(dash_app, host=host, port=port, log_level="info")
    except ImportError:
        click.echo("uvicorn is required. Install with: pip install uvicorn", err=True)
        sys.exit(1)


# ── report ────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--db", default="raiguard_audit.db", show_default=True, help="Evidence DB path")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "html"]), default="html", show_default=True)
@click.option("--output", "-o", default=None, help="Output file path (default: raiguard_report.<ext>)")
def report(db: str, fmt: str, output: Optional[str]) -> None:
    """Generate a compliance evidence report from the audit database."""
    from raiguard.evidence.report import generate_html_report, generate_json_report, save_report
    from raiguard.compliance.owasp_llm import owasp_compliance_score, OWASPFinding
    from raiguard.compliance.eu_ai_act import eu_ai_act_overall_score, EUAIActFinding
    from raiguard.compliance.nist_ai_rmf import NISTFinding

    # Build minimal empty reports (no live DB required for demo)
    owasp_score = owasp_compliance_score([])
    eu_score = eu_ai_act_overall_score([])

    out_path = output or f"raiguard_report.{fmt}"

    if fmt == "html":
        content = generate_html_report(owasp_score, [], eu_score, [], [], store_stats={})
    else:
        content = generate_json_report(owasp_score, [], eu_score, [], [], store_stats={})

    saved = save_report(content, out_path)
    _print(f"[green]Report saved:[/green] {saved}", "")


# ── check (quick one-liner) ───────────────────────────────────────────────────

@main.command(name="check")
@click.argument("text")
@click.option("--json-output", is_flag=True, default=False)
def check_cmd(text: str, json_output: bool) -> None:
    """Quick one-line check of TEXT. Exit code 1 if blocked."""
    from raiguard.instrument import AIGuard
    guard = AIGuard(block_on_fail=False)

    async def _run() -> None:
        return await guard.check_input(text)

    result = asyncio.run(_run())

    if json_output:
        click.echo(json.dumps(result.to_dict(), indent=2))
    elif _RICH and console:
        _render_audit_result(result, text[:100])
    else:
        # blocked_by is populated even when block_on_fail=False
        is_blocked = bool(result.blocked_by)
        status = f"[red]BLOCKED[/red]" if is_blocked else f"[green]ALLOWED[/green]"
        risk_colour = "red" if result.risk_score >= 0.7 else "yellow" if result.risk_score >= 0.4 else "green"
        click.echo(f"{status} | risk=[{risk_colour}]{result.risk_score:.3f}[/{risk_colour}] | checks={len(result.check_results)}")
        if result.blocked_by:
            click.echo(f"  blocked by: {', '.join(result.blocked_by)}")

    sys.exit(1 if result.blocked_by else 0)
