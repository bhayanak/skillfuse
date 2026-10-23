"""Rich console reporter."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from skillchain.core.models import Decision, PolicyVerdict, ScanResult, Severity

_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_DECISION_STYLE = {
    Decision.ALLOW: "bold green",
    Decision.QUARANTINE: "bold yellow",
    Decision.BLOCK: "bold red",
}


def render_console(
    result: ScanResult,
    console: Console | None = None,
    *,
    verdicts: dict[str, PolicyVerdict] | None = None,
    show_evidence: bool = False,
    max_findings: int | None = None,
) -> None:
    console = console or Console()
    verdicts = verdicts or {}
    for scan in result.skills:
        pkg = scan.package
        verdict = verdicts.get(pkg.name)
        title = Text.assemble((pkg.name, "bold"), (f"  [{pkg.kind.value}]", "dim"))
        if verdict:
            title.append(f"  {verdict.decision.value.upper()}", style=_DECISION_STYLE[verdict.decision])
        header = Text()
        header.append(f"{pkg.entrypoint}", style="dim")
        header.append(f"\ndigest {scan.digest[:23]}…", style="dim")
        caps = ", ".join(scan.inferred.capabilities) or "none"
        header.append(f"\ncapabilities: {caps}")
        if scan.declared is not None:
            header.append(f"\ndeclared:     {', '.join(scan.declared.capabilities) or 'none'}")
        if scan.diff.undeclared:
            header.append(f"\nundeclared:   {', '.join(scan.diff.undeclared)}", style="red")
        if verdict and verdict.reasons:
            header.append("\npolicy: " + "; ".join(verdict.reasons), style="yellow")
        console.print(Panel(header, title=title, title_align="left", border_style="blue"))
        if not scan.findings:
            console.print("  [green]✔ no findings[/green]\n")
            continue
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False, expand=True)
        table.add_column("sev", width=8)
        table.add_column("conf", width=4)
        table.add_column("rule", width=11)
        table.add_column("location", ratio=2, overflow="fold")
        table.add_column("message", ratio=5, overflow="fold")
        findings = list(scan.findings)
        shown = findings if max_findings is None else findings[:max_findings]
        for f in shown:
            msg = f.message
            if f.location.snippet and show_evidence:
                msg += f"\n[dim]{f.location.snippet}[/dim]"
            table.add_row(
                Text(f.severity.value, style=_STYLE[f.severity]),
                f.confidence.value[:3],
                f.rule_id,
                f"{f.location.path}:{f.location.line}",
                msg,
            )
        console.print(table)
        if len(shown) < len(findings):
            console.print(f"  [dim]… {len(findings) - len(shown)} more[/dim]")
        console.print()
    _summary(result, console)


def _summary(result: ScanResult, console: Console) -> None:
    counts = dict.fromkeys(Severity, 0)
    det = heu = 0
    for f in result.findings:
        counts[f.severity] += 1
        if f.confidence.value == "deterministic":
            det += 1
        else:
            heu += 1
    parts = [
        Text(f"{counts[s]} {s.value}", style=_STYLE[s] if counts[s] else "dim")
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    ]
    line = Text(f"{len(result.skills)} skill(s) · {len(result.findings)} finding(s) · ")
    for i, p in enumerate(parts):
        if i:
            line.append(" · ")
        line.append_text(p)
    line.append(f" · {det} deterministic / {heu} heuristic", style="dim")
    if result.suppressed:
        line.append(f" · {result.suppressed} suppressed", style="dim")
    console.print(line)
    for err in result.errors:
        console.print(f"[red]error:[/red] {err}")
