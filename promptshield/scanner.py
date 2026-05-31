"""Prompt scanner for analyzing text, files, and directories for security issues."""

import os
from typing import List, Optional

from promptshield.models import ScanResult, Severity
from promptshield.rules import RuleEngine
from promptshield.utils import (
    is_scannable_file,
    is_valid_directory,
    is_valid_file,
    read_file,
)


class PromptScanner:
    """Scanner for analyzing prompts for security issues.

    Uses the RuleEngine to detect security issues in text, files, and directories.

    Attributes:
        engine: The rule engine used for detection.
        min_severity: Minimum severity level to report.
    """

    def __init__(self, min_severity: Severity = Severity.LOW) -> None:
        """Initialize the scanner.

        Args:
            min_severity: Minimum severity level to report findings.
        """
        self.engine = RuleEngine()
        self.min_severity = min_severity

    def scan_text(self, text: str, source: Optional[str] = None) -> ScanResult:
        """Scan a single prompt text for security issues.

        Args:
            text: The prompt text to scan.
            source: Optional source identifier for the text.

        Returns:
            ScanResult containing all findings.
        """
        if not text or not text.strip():
            return ScanResult(prompt_text=text or "", source=source)

        findings = self.engine.analyze(text, self.min_severity)
        return ScanResult(
            prompt_text=text,
            findings=findings,
            source=source,
        )

    def scan_file(self, filepath: str) -> List[ScanResult]:
        """Scan a file for security issues.

        Reads the file content and scans it as a single prompt.

        Args:
            filepath: Path to the file to scan.

        Returns:
            List of ScanResult objects (one per file).

        Raises:
            FileNotFoundError: If the file does not exist.
            IOError: If the file cannot be read.
        """
        if not is_valid_file(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        content = read_file(filepath)
        result = self.scan_text(content, source=filepath)
        return [result]

    def scan_directory(
        self,
        dirpath: str,
        recursive: bool = True,
        progress_callback=None,
    ) -> List[ScanResult]:
        """Scan all files in a directory for security issues.

        Args:
            dirpath: Path to the directory to scan.
            recursive: Whether to scan subdirectories recursively.
            progress_callback: Optional callback function for progress updates.
                Called with (current_count, total_files, current_filepath).

        Returns:
            List of ScanResult objects for all scanned files.

        Raises:
            FileNotFoundError: If the directory does not exist.
        """
        if not is_valid_directory(dirpath):
            raise FileNotFoundError(f"Directory not found: {dirpath}")

        results: List[ScanResult] = []
        files_to_scan = self._collect_files(dirpath, recursive)
        total_files = len(files_to_scan)

        for idx, filepath in enumerate(files_to_scan, start=1):
            if progress_callback:
                progress_callback(idx, total_files, filepath)

            try:
                content = read_file(filepath)
                if content.strip():
                    result = self.scan_text(content, source=filepath)
                    results.append(result)
            except (IOError, OSError):
                # Skip files that cannot be read
                continue

        return results

    def _collect_files(self, dirpath: str, recursive: bool) -> List[str]:
        """Collect all scannable files from a directory.

        Args:
            dirpath: Path to the directory.
            recursive: Whether to include subdirectories.

        Returns:
            Sorted list of file paths.
        """
        files: List[str] = []

        if recursive:
            for root, _dirs, filenames in os.walk(dirpath):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    if is_scannable_file(filepath):
                        files.append(filepath)
        else:
            for entry in os.listdir(dirpath):
                filepath = os.path.join(dirpath, entry)
                if is_valid_file(filepath) and is_scannable_file(filepath):
                    files.append(filepath)

        return sorted(files)

    def scan_batch(self, texts: List[str]) -> List[ScanResult]:
        """Scan a batch of prompt texts.

        Args:
            texts: List of prompt texts to scan.

        Returns:
            List of ScanResult objects.
        """
        results: List[ScanResult] = []
        for idx, text in enumerate(texts):
            result = self.scan_text(text, source=f"batch_item_{idx}")
            results.append(result)
        return results

    def get_stats(self, results: List[ScanResult]) -> dict:
        """Calculate aggregate statistics from scan results.

        Args:
            results: List of ScanResult objects.

        Returns:
            Dictionary with aggregate statistics.
        """
        if not results:
            return {
                "total_scans": 0,
                "total_findings": 0,
                "safe_count": 0,
                "affected_count": 0,
                "severity_counts": {
                    "low": 0,
                    "medium": 0,
                    "high": 0,
                    "critical": 0,
                },
                "category_counts": {},
                "average_score": 0,
                "max_score": 0,
            }

        total_findings = 0
        safe_count = 0
        affected_count = 0
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        category_counts: dict = {}
        total_score = 0
        max_score = 0

        for result in results:
            total_findings += len(result.findings)
            total_score += result.score
            if result.score > max_score:
                max_score = result.score

            if result.is_safe:
                safe_count += 1
            else:
                affected_count += 1

            for sev, count in result.severity_counts.items():
                severity_counts[sev] += count

            for finding in result.findings:
                cat = finding.category.value
                category_counts[cat] = category_counts.get(cat, 0) + 1

        return {
            "total_scans": len(results),
            "total_findings": total_findings,
            "safe_count": safe_count,
            "affected_count": affected_count,
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "average_score": total_score / len(results) if results else 0,
            "max_score": max_score,
        }

    def quick_check(self, text: str) -> bool:
        """Perform a quick safety check on text.

        Args:
            text: The text to check.

        Returns:
            True if the text is considered safe (no high or critical findings).
        """
        result = self.scan_text(text)
        for finding in result.findings:
            if finding.severity in (Severity.HIGH, Severity.CRITICAL):
                return False
        return True
