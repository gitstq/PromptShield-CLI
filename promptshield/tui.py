"""Interactive TUI dashboard for PromptShield.

Provides a rich terminal-based dashboard for viewing scan statistics,
risk distribution, recent results, and rule coverage.
"""

from typing import List, Optional

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich import box

from promptshield.models import ScanResult, Severity
from promptshield.rules import RuleEngine
from promptshield.scanner import PromptScanner


class TUIDashboard:
    """Interactive TUI dashboard for PromptShield.

    Displays scan statistics, risk distribution, recent results,
    and rule coverage information using Rich components.
    """

    def __init__(self, console: Optional[Console] = None) -> None:
        """Initialize the TUI dashboard.

        Args:
            console: Rich Console instance. Creates a new one if not provided.
        """
        self.console = console or Console()
        self.scanner = PromptScanner()
        self.engine = self.scanner.engine
        self._recent_results: List[ScanResult] = []

    def show_dashboard(self) -> None:
        """Display the main interactive dashboard."""
        self.console.clear()
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="center"),
            Layout(name="right"),
        )
        layout["left"].split_column(
            Layout(name="stats", ratio=2),
            Layout(name="severity", ratio=2),
        )
        layout["center"].split_column(
            Layout(name="rules"),
            Layout(name="categories"),
        )
        layout["right"].split_column(
            Layout(name="recent"),
        )

        self._render_header(layout)
        self._render_stats(layout)
        self._render_severity(layout)
        self._render_rules(layout)
        self._render_categories(layout)
        self._render_recent(layout)
        self._render_footer(layout)

        self.console.print(layout)

    def _render_header(self, layout: Layout) -> None:
        """Render the header panel.

        Args:
            layout: The layout to render into.
        """
        header_text = Text()
        header_text.append(" PromptShield-CLI ", style="bold white on blue")
        header_text.append(" v1.0.0 ", style="bold black on cyan")
        header_text.append("  Security Dashboard", style="bold white")

        layout["header"].update(Panel(
            header_text,
            style="blue",
            box=box.DOUBLE,
        ))

    def _render_stats(self, layout: Layout) -> None:
        """Render the statistics panel.

        Args:
            layout: The layout to render into.
        """
        stats = self.scanner.get_stats(self._recent_results) if self._recent_results else None

        table = Table(
            title="Scan Statistics",
            box=box.ROUNDED,
            show_header=False,
            title_style="bold cyan",
        )
        table.add_column("Metric", style="bold")
        table.add_column("Value", style="green", justify="right")

        if stats:
            table.add_row("Total Scans", str(stats["total_scans"]))
            table.add_row("Total Findings", str(stats["total_findings"]))
            table.add_row("Safe Items", str(stats["safe_count"]))
            table.add_row("Affected Items", str(stats["affected_count"]))
            table.add_row("Avg Score", f"{stats['average_score']:.1f}")
            table.add_row("Max Score", str(stats["max_score"]))
        else:
            table.add_row("Total Scans", "0")
            table.add_row("Total Findings", "0")
            table.add_row("Safe Items", "-")
            table.add_row("Affected Items", "-")
            table.add_row("Avg Score", "-")
            table.add_row("Max Score", "-")

        layout["stats"].update(Panel(table, border_style="cyan", box=box.ROUNDED))

    def _render_severity(self, layout: Layout) -> None:
        """Render the severity distribution panel.

        Args:
            layout: The layout to render into.
        """
        table = Table(
            title="Severity Distribution",
            box=box.ROUNDED,
            show_header=True,
            title_style="bold yellow",
        )
        table.add_column("Level", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Bar", min_width=20)

        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for result in self._recent_results:
            for sev, count in result.severity_counts.items():
                severity_counts[sev] += count

        max_count = max(severity_counts.values()) if any(severity_counts.values()) else 1
        color_map = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }

        for sev in ["critical", "high", "medium", "low"]:
            count = severity_counts[sev]
            bar_len = int((count / max_count) * 20) if max_count > 0 else 0
            bar = "\u2588" * bar_len
            table.add_row(
                sev.upper(),
                str(count),
                f"[{color_map[sev]}]{bar}[/{color_map[sev]}]",
            )

        layout["severity"].update(Panel(table, border_style="yellow", box=box.ROUNDED))

    def _render_rules(self, layout: Layout) -> None:
        """Render the rules coverage panel.

        Args:
            layout: The layout to render into.
        """
        table = Table(
            title=f"Rules ({self.engine.total_rules} loaded)",
            box=box.ROUNDED,
            show_header=True,
            title_style="bold magenta",
        )
        table.add_column("Category", style="bold")
        table.add_column("Count", justify="right")

        category_counts: dict = {}
        for rule in self.engine.rules.values():
            cat = rule.config.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1

        for cat, count in sorted(category_counts.items()):
            table.add_row(cat.replace("_", " ").title(), str(count))

        layout["rules"].update(Panel(table, border_style="magenta", box=box.ROUNDED))

    def _render_categories(self, layout: Layout) -> None:
        """Render the category breakdown panel.

        Args:
            layout: The layout to render into.
        """
        table = Table(
            title="Category Breakdown",
            box=box.ROUNDED,
            show_header=True,
            title_style="bold green",
        )
        table.add_column("Category", style="bold")
        table.add_column("Findings", justify="right")

        category_counts: dict = {}
        for result in self._recent_results:
            for finding in result.findings:
                cat = finding.category.value
                category_counts[cat] = category_counts.get(cat, 0) + 1

        if category_counts:
            for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
                table.add_row(cat.replace("_", " ").title(), str(count))
        else:
            table.add_row("No findings yet", "0")

        layout["categories"].update(Panel(table, border_style="green", box=box.ROUNDED))

    def _render_recent(self, layout: Layout) -> None:
        """Render the recent scan results panel.

        Args:
            layout: The layout to render into.
        """
        table = Table(
            title="Recent Scans",
            box=box.ROUNDED,
            show_header=True,
            title_style="bold blue",
        )
        table.add_column("Source", style="bold", max_width=20)
        table.add_column("Score", justify="right")
        table.add_column("Risk", justify="center")
        table.add_column("Findings", justify="right")

        recent = self._recent_results[-8:] if self._recent_results else []

        for result in recent:
            source = (result.source or "inline")[:20]
            risk_color = "green" if result.score == 0 else "yellow" if result.score <= 40 else "red"
            table.add_row(
                source,
                str(result.score),
                f"[{risk_color}]{result.risk_level}[/{risk_color}]",
                str(len(result.findings)),
            )

        if not recent:
            table.add_row("No scans yet", "-", "-", "-")

        layout["recent"].update(Panel(table, border_style="blue", box=box.ROUNDED))

    def _render_footer(self, layout: Layout) -> None:
        """Render the footer panel.

        Args:
            layout: The layout to render into.
        """
        footer_text = Text()
        footer_text.append(" Commands: ", style="bold")
        footer_text.append("promptshield scan ", style="cyan")
        footer_text.append("| ")
        footer_text.append("promptshield file ", style="cyan")
        footer_text.append("| ")
        footer_text.append("promptshield dir ", style="cyan")
        footer_text.append("| ")
        footer_text.append("promptshield rules ", style="cyan")
        footer_text.append("| ")
        footer_text.append("promptshield report ", style="cyan")

        layout["footer"].update(Panel(
            footer_text,
            style="dim",
            box=box.HEAVY,
        ))

    def add_result(self, result: ScanResult) -> None:
        """Add a scan result to the recent results list.

        Args:
            result: The scan result to add.
        """
        self._recent_results.append(result)
        # Keep only the last 100 results
        if len(self._recent_results) > 100:
            self._recent_results = self._recent_results[-100:]

    def show_scan_progress(self, total: int, current: int, filepath: str) -> None:
        """Show a progress indicator for directory scanning.

        Args:
            total: Total number of files to scan.
            current: Current file index.
            filepath: Path of the file being scanned.
        """
        # Simple inline progress display
        percent = (current / total * 100) if total > 0 else 0
        self.console.print(
            f"  Scanning [{current}/{total}] ({percent:.0f}%) - {filepath}",
            end="\r",
        )

    def show_welcome(self) -> None:
        """Display the welcome banner."""
        self.console.print()
        banner = Text()
        banner.append("\n  ╔══════════════════════════════════════════════════╗\n", style="bold cyan")
        banner.append("  ║                                                ║\n", style="bold cyan")
        banner.append("  ║       ", style="bold cyan")
        banner.append("PromptShield-CLI", style="bold white on blue")
        banner.append("                    ║\n", style="bold cyan")
        banner.append("  ║    ", style="bold cyan")
        banner.append("AI Prompt Security Scanner", style="bold yellow")
        banner.append("              ║\n", style="bold cyan")
        banner.append("  ║                                                ║\n", style="bold cyan")
        banner.append("  ╚══════════════════════════════════════════════════╝\n", style="bold cyan")
        self.console.print(banner)
        self.console.print(
            "  Version 1.0.0 | "
            f"{self.engine.total_rules} detection rules loaded | "
            f"{len(self.engine.categories)} categories\n",
            style="dim",
        )
