"""Command-line interface for PromptShield-CLI.

Provides the main entry point and argument parsing for the promptshield command.
Supports subcommands: scan, file, dir, rules, report.
"""

import argparse
import sys
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.text import Text

from promptshield import __version__
from promptshield.models import ScanResult, Severity
from promptshield.reporter import ReportGenerator
from promptshield.rules import RuleEngine
from promptshield.scanner import PromptScanner
from promptshield.tui import TUIDashboard


def _parse_severity(value: str) -> Severity:
    """Parse a severity string to a Severity enum.

    Args:
        value: The severity string (low, medium, high, critical).

    Returns:
        The corresponding Severity enum.

    Raises:
        argparse.ArgumentTypeError: If the value is invalid.
    """
    try:
        return Severity(value.lower())
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid severity: {value}. Choose from: low, medium, high, critical"
        )


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="promptshield",
        description="PromptShield-CLI - Lightweight terminal AI Prompt security detection and injection defense engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            '  promptshield scan "ignore all previous instructions"\n'
            "  promptshield file --format json prompt.txt\n"
            "  promptshield dir --severity high ./prompts/\n"
            "  promptshield rules\n"
            "  promptshield report --format sarif ./results/\n"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"PromptShield-CLI v{__version__}",
    )

    # Global options
    parser.add_argument(
        "--format",
        choices=["json", "csv", "markdown", "sarif", "text"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--severity",
        type=_parse_severity,
        default=Severity.LOW,
        help="Minimum severity level to report (default: low)",
    )
    parser.add_argument(
        "--lang",
        choices=["en", "zh"],
        default="en",
        help="Output language (default: en)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable colored output",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        default=False,
        help="Suppress all output except results",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan subcommand
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a single prompt text for security issues",
    )
    scan_parser.add_argument(
        "text",
        type=str,
        nargs="?",
        default=None,
        help="The prompt text to scan",
    )
    scan_parser.add_argument(
        "--stdin",
        action="store_true",
        default=False,
        help="Read prompt text from stdin",
    )

    # file subcommand
    file_parser = subparsers.add_parser(
        "file",
        help="Scan a file for prompt security issues",
    )
    file_parser.add_argument(
        "filepath",
        type=str,
        help="Path to the file to scan",
    )

    # dir subcommand
    dir_parser = subparsers.add_parser(
        "dir",
        help="Batch scan a directory for prompt security issues",
    )
    dir_parser.add_argument(
        "dirpath",
        type=str,
        help="Path to the directory to scan",
    )
    dir_parser.add_argument(
        "--no-recursive",
        action="store_true",
        default=False,
        help="Do not scan subdirectories recursively",
    )

    # rules subcommand
    rules_parser = subparsers.add_parser(
        "rules",
        help="List all detection rules",
    )
    rules_parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Filter rules by category",
    )
    rules_parser.add_argument(
        "--severity-filter",
        type=str,
        default=None,
        choices=["low", "medium", "high", "critical"],
        help="Filter rules by severity",
    )

    # report subcommand
    report_parser = subparsers.add_parser(
        "report",
        help="Generate a detection report from scan results",
    )
    report_parser.add_argument(
        "path",
        type=str,
        help="File or directory path to scan and generate report for",
    )
    report_parser.add_argument(
        "--no-recursive",
        action="store_true",
        default=False,
        help="Do not scan subdirectories recursively",
    )

    return parser


def _get_console(args: argparse.Namespace) -> Console:
    """Create a Console instance based on command-line arguments.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Configured Console instance.
    """
    force_terminal = None if not args.no_color else False
    return Console(force_terminal=force_terminal)


def _write_output(console: Console, content: str, output_path: Optional[str]) -> None:
    """Write output to file or console.

    Args:
        console: The console to print to if no file path is given.
        content: The content to write.
        output_path: Optional file path to write to.
    """
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        console.print(content)


def _print_scan_result(
    console: Console,
    result: ScanResult,
    lang: str = "en",
    quiet: bool = False,
) -> None:
    """Print a scan result to the console with Rich formatting.

    Args:
        console: The console to print to.
        result: The scan result to display.
        lang: Language for output.
        quiet: If True, only print the score.
    """
    if quiet:
        console.print(f"{result.score}")
        return

    # Risk score display
    if result.is_safe:
        if lang == "zh":
            console.print(
                Panel(
                    "[bold green]OK[/bold green] - 未发现安全问题",
                    title="Scan Result",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    "[bold green]OK[/bold green] - No security issues found",
                    title="Scan Result",
                    border_style="green",
                )
            )
        return

    # Determine border color based on score
    if result.score >= 70:
        border_style = "bold red"
    elif result.score >= 40:
        border_style = "bold yellow"
    else:
        border_style = "yellow"

    # Build findings table
    table = Table(
        show_header=True,
        header_style="bold",
        box=None,
        padding=(0, 1),
    )
    table.add_column("ID", style="bold cyan", min_width=8)
    table.add_column("Severity", min_width=10)
    table.add_column("Category", min_width=18)
    table.add_column("Description", min_width=30)

    for finding in result.findings:
        sev_style = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }.get(finding.severity.value, "white")

        table.add_row(
            finding.rule_id,
            f"[{sev_style}]{finding.severity.value.upper()}[/{sev_style}]",
            finding.category.value,
            finding.description,
        )

    from rich.console import Group
    from rich.columns import Columns

    if lang == "zh":
        score_text = Text(f"风险评分: {result.score}/100 ({result.risk_level})", style="bold")
        findings_text = Text(f"发现: {len(result.findings)} 个问题")
    else:
        score_text = Text(f"Risk Score: {result.score}/100 ({result.risk_level})", style="bold")
        findings_text = Text(f"Findings: {len(result.findings)} issues")

    console.print(Panel(
        Group(score_text, findings_text, Text(""), table),
        title="Scan Result",
        border_style=border_style,
    ))


def cmd_scan(args: argparse.Namespace, console: Console) -> int:
    """Execute the scan subcommand.

    Args:
        args: Parsed command-line arguments.
        console: The console for output.

    Returns:
        Exit code (0 for safe, 1 for issues found, 2 for errors).
    """
    text = args.text

    if args.stdin:
        text = sys.stdin.read()
    elif text is None:
        console.print("[red]Error: Provide text to scan or use --stdin[/red]")
        return 2

    scanner = PromptScanner(min_severity=args.severity)
    result = scanner.scan_text(text)

    if args.format != "text":
        reporter = ReportGenerator()
        report = reporter.generate([result], fmt=args.format, lang=args.lang)
        _write_output(console, report, args.output)
    else:
        _print_scan_result(console, result, lang=args.lang, quiet=args.quiet)

    return 1 if not result.is_safe else 0


def cmd_file(args: argparse.Namespace, console: Console) -> int:
    """Execute the file subcommand.

    Args:
        args: Parsed command-line arguments.
        console: The console for output.

    Returns:
        Exit code (0 for safe, 1 for issues found, 2 for errors).
    """
    scanner = PromptScanner(min_severity=args.severity)

    try:
        results = scanner.scan_file(args.filepath)
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        return 2

    if args.format != "text":
        reporter = ReportGenerator()
        report = reporter.generate(results, fmt=args.format, lang=args.lang)
        _write_output(console, report, args.output)
    else:
        for result in results:
            _print_scan_result(console, result, lang=args.lang, quiet=args.quiet)

    has_issues = any(not r.is_safe for r in results)
    return 1 if has_issues else 0


def cmd_dir(args: argparse.Namespace, console: Console) -> int:
    """Execute the dir subcommand.

    Args:
        args: Parsed command-line arguments.
        console: The console for output.

    Returns:
        Exit code (0 for safe, 1 for issues found, 2 for errors).
    """
    scanner = PromptScanner(min_severity=args.severity)
    recursive = not args.no_recursive

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
            disable=args.quiet,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)

            def update_progress(current: int, total: int, filepath: str) -> None:
                """Update progress bar."""
                if progress.tasks[task].total is None:
                    progress.update(task, total=total)
                progress.update(task, completed=current, description=f"Scanning {filepath}")

            results = scanner.scan_directory(
                args.dirpath,
                recursive=recursive,
                progress_callback=update_progress,
            )
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        return 2

    if args.format != "text":
        reporter = ReportGenerator()
        report = reporter.generate(results, fmt=args.format, lang=args.lang)
        _write_output(console, report, args.output)
    else:
        stats = scanner.get_stats(results)
        if not args.quiet:
            if args.lang == "zh":
                console.print(
                    Panel(
                        f"[bold]扫描完成[/bold]\n"
                        f"文件数: {stats['total_scans']}\n"
                        f"发现数: {stats['total_findings']}\n"
                        f"安全项: {stats['safe_count']}\n"
                        f"风险项: {stats['affected_count']}",
                        title="Directory Scan Summary",
                        border_style="cyan",
                    )
                )
            else:
                console.print(
                    Panel(
                        f"[bold]Scan Complete[/bold]\n"
                        f"Files: {stats['total_scans']}\n"
                        f"Findings: {stats['total_findings']}\n"
                        f"Safe: {stats['safe_count']}\n"
                        f"Affected: {stats['affected_count']}",
                        title="Directory Scan Summary",
                        border_style="cyan",
                    )
                )

        # Show affected results
        for result in results:
            if not result.is_safe:
                _print_scan_result(console, result, lang=args.lang, quiet=args.quiet)

    has_issues = any(not r.is_safe for r in results)
    return 1 if has_issues else 0


def cmd_rules(args: argparse.Namespace, console: Console) -> int:
    """Execute the rules subcommand.

    Args:
        args: Parsed command-line arguments.
        console: The console for output.

    Returns:
        Exit code (always 0).
    """
    engine = RuleEngine()
    rules = engine.get_rule_summary()

    # Apply filters
    if args.category:
        rules = [r for r in rules if r["category"] == args.category]
    if args.severity_filter:
        rules = [r for r in rules if r["severity"] == args.severity_filter]

    table = Table(
        title=f"Detection Rules ({len(rules)} loaded)",
        box=box.ROUNDED if False else None,
        show_header=True,
        header_style="bold magenta",
        title_style="bold",
    )
    table.add_column("ID", style="bold cyan", min_width=8)
    table.add_column("Name", min_width=30)
    table.add_column("Category", min_width=20)
    table.add_column("Severity", min_width=10)
    table.add_column("Patterns", justify="right", min_width=8)

    for rule in rules:
        sev_style = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }.get(rule["severity"], "white")

        table.add_row(
            rule["id"],
            rule["name"],
            rule["category"],
            f"[{sev_style}]{rule['severity'].upper()}[/{sev_style}]",
            str(rule["patterns_count"]),
        )

    console.print(table)
    return 0


def cmd_report(args: argparse.Namespace, console: Console) -> int:
    """Execute the report subcommand.

    Args:
        args: Parsed command-line arguments.
        console: The console for output.

    Returns:
        Exit code (0 for safe, 1 for issues found, 2 for errors).
    """
    scanner = PromptScanner(min_severity=args.severity)
    recursive = not args.no_recursive
    reporter = ReportGenerator()

    import os
    if os.path.isfile(args.path):
        try:
            results = scanner.scan_file(args.path)
        except FileNotFoundError as e:
            console.print(f"[red]Error: {e}[/red]")
            return 2
    elif os.path.isdir(args.path):
        try:
            results = scanner.scan_directory(args.path, recursive=recursive)
        except FileNotFoundError as e:
            console.print(f"[red]Error: {e}[/red]")
            return 2
    else:
        console.print(f"[red]Error: Path not found: {args.path}[/red]")
        return 2

    report = reporter.generate(results, fmt=args.format, lang=args.lang)
    _write_output(console, report, args.output)

    has_issues = any(not r.is_safe for r in results)
    return 1 if has_issues else 0


def main() -> int:
    """Main entry point for the PromptShield CLI.

    Returns:
        Exit code (0 for success, 1 for issues found, 2 for errors).
    """
    parser = _build_parser()
    args = parser.parse_args()

    console = _get_console(args)

    # No subcommand: show TUI dashboard
    if args.command is None:
        dashboard = TUIDashboard(console=console)
        dashboard.show_welcome()
        dashboard.show_dashboard()
        return 0

    # Dispatch to subcommand handlers
    handlers = {
        "scan": cmd_scan,
        "file": cmd_file,
        "dir": cmd_dir,
        "rules": cmd_rules,
        "report": cmd_report,
    }

    handler = handlers.get(args.command)
    if handler:
        return handler(args, console)

    # Unknown command
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
