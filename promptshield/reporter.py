"""Report generator for PromptShield scan results.

Supports multiple output formats: JSON, CSV, Markdown, SARIF, and Text.
"""

import csv
import io
import json
from datetime import datetime
from typing import List, Optional

from promptshield.models import ScanResult, Severity


class ReportGenerator:
    """Generates reports from scan results in various formats.

    Supported formats: JSON, CSV, Markdown, SARIF, Text.
    """

    def generate(
        self,
        results: List[ScanResult],
        fmt: str = "text",
        lang: str = "en",
    ) -> str:
        """Generate a report from scan results.

        Args:
            results: List of ScanResult objects.
            fmt: Output format (json, csv, markdown, sarif, text).
            lang: Language for the report (en, zh).

        Returns:
            The formatted report as a string.

        Raises:
            ValueError: If the format is not supported.
        """
        generators = {
            "json": self._generate_json,
            "csv": self._generate_csv,
            "markdown": self._generate_markdown,
            "sarif": self._generate_sarif,
            "text": self._generate_text,
        }

        generator = generators.get(fmt.lower())
        if not generator:
            raise ValueError(
                f"Unsupported format: {fmt}. Supported: {', '.join(generators.keys())}"
            )

        return generator(results, lang)

    def _generate_json(self, results: List[ScanResult], lang: str = "en") -> str:
        """Generate a JSON report.

        Args:
            results: List of ScanResult objects.
            lang: Language setting (unused for JSON).

        Returns:
            JSON formatted report string.
        """
        report = {
            "report_version": "1.0.0",
            "tool": "PromptShield-CLI",
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_scans": len(results),
                "total_findings": sum(len(r.findings) for r in results),
                "safe_count": sum(1 for r in results if r.is_safe),
                "affected_count": sum(1 for r in results if not r.is_safe),
            },
            "results": [r.to_dict() for r in results],
        }
        return json.dumps(report, indent=2, ensure_ascii=False)

    def _generate_csv(self, results: List[ScanResult], lang: str = "en") -> str:
        """Generate a CSV report.

        Args:
            results: List of ScanResult objects.
            lang: Language setting (unused for CSV).

        Returns:
            CSV formatted report string.
        """
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "Source", "Score", "Risk Level", "Rule ID", "Rule Name",
            "Category", "Severity", "Description", "Matched Text",
            "Position", "Suggestion", "CWE ID", "Timestamp",
        ])

        # Rows
        for result in results:
            if result.is_safe:
                writer.writerow([
                    result.source or "inline",
                    result.score,
                    result.risk_level,
                    "", "", "", "", "", "", "", "", "",
                    result.timestamp,
                ])
            else:
                for finding in result.findings:
                    writer.writerow([
                        result.source or "inline",
                        result.score,
                        result.risk_level,
                        finding.rule_id,
                        finding.rule_name,
                        finding.category.value,
                        finding.severity.value,
                        finding.description,
                        finding.matched_text[:100],
                        f"{finding.position[0]}-{finding.position[1]}",
                        finding.suggestion,
                        finding.cwe_id or "",
                        result.timestamp,
                    ])

        return output.getvalue()

    def _generate_markdown(self, results: List[ScanResult], lang: str = "en") -> str:
        """Generate a Markdown report.

        Args:
            results: List of ScanResult objects.
            lang: Language for the report content.

        Returns:
            Markdown formatted report string.
        """
        lines: List[str] = []

        if lang == "zh":
            lines.append("# PromptShield 安全检测报告")
            lines.append("")
            lines.append(f"**生成时间**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
            lines.append(f"**扫描总数**: {len(results)}")
            total_findings = sum(len(r.findings) for r in results)
            lines.append(f"**发现总数**: {total_findings}")
            safe_count = sum(1 for r in results if r.is_safe)
            lines.append(f"**安全项**: {safe_count}")
            lines.append(f"**风险项**: {len(results) - safe_count}")
            lines.append("")
            lines.append("---")
            lines.append("")
        else:
            lines.append("# PromptShield Security Report")
            lines.append("")
            lines.append(f"**Generated**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
            lines.append(f"**Total Scans**: {len(results)}")
            total_findings = sum(len(r.findings) for r in results)
            lines.append(f"**Total Findings**: {total_findings}")
            safe_count = sum(1 for r in results if r.is_safe)
            lines.append(f"**Safe**: {safe_count}")
            lines.append(f"**Affected**: {len(results) - safe_count}")
            lines.append("")
            lines.append("---")
            lines.append("")

        # Severity summary table
        if lang == "zh":
            lines.append("## 严重程度分布")
        else:
            lines.append("## Severity Distribution")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")

        severity_totals = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for result in results:
            for sev, count in result.severity_counts.items():
                severity_totals[sev] += count

        emoji_map = {"low": ":white_check_mark:", "medium": ":yellow_circle:", "high": ":red_circle:", "critical": ":rotating_light:"}
        for sev in ["critical", "high", "medium", "low"]:
            lines.append(f"| {emoji_map[sev]} {sev.upper()} | {severity_totals[sev]} |")
        lines.append("")

        # Detailed findings
        if lang == "zh":
            lines.append("## 详细发现")
        else:
            lines.append("## Detailed Findings")
        lines.append("")

        for result in results:
            source_label = result.source or "inline"
            if lang == "zh":
                lines.append(f"### 来源: `{source_label}`")
                lines.append(f"- **风险评分**: {result.score}/100 ({result.risk_level})")
                lines.append(f"- **发现数量**: {len(result.findings)}")
            else:
                lines.append(f"### Source: `{source_label}`")
                lines.append(f"- **Risk Score**: {result.score}/100 ({result.risk_level})")
                lines.append(f"- **Findings**: {len(result.findings)}")
            lines.append("")

            if result.findings:
                lines.append("| Rule | Severity | Category | Matched Text |")
                lines.append("|------|----------|----------|--------------|")
                for finding in result.findings:
                    matched = finding.matched_text[:50].replace("|", "\\|").replace("\n", " ")
                    lines.append(
                        f"| {finding.rule_id} | {finding.severity.value} | "
                        f"{finding.category.value} | `{matched}` |"
                    )
                lines.append("")
            else:
                if lang == "zh":
                    lines.append("> No issues found. :white_check_mark:")
                else:
                    lines.append("> No issues found. :white_check_mark:")
                lines.append("")

        return "\n".join(lines)

    def _generate_sarif(self, results: List[ScanResult], lang: str = "en") -> str:
        """Generate a SARIF (Static Analysis Results Interchange Format) report.

        Conforms to the OASIS SARIF v2.1.0 standard.

        Args:
            results: List of ScanResult objects.
            lang: Language setting (unused for SARIF).

        Returns:
            SARIF formatted report string.
        """
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PromptShield-CLI",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/promptshield/cli",
                            "rules": [],
                        }
                    },
                    "results": [],
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.utcnow().isoformat() + "Z",
                        }
                    ],
                }
            ],
        }

        rule_definitions = sarif["runs"][0]["tool"]["driver"]["rules"]
        sarif_results = sarif["runs"][0]["results"]

        for result in results:
            for finding in result.findings:
                # Add rule definition if not already present
                rule_id = finding.rule_id
                if not any(r["id"] == rule_id for r in rule_definitions):
                    rule_definitions.append({
                        "id": rule_id,
                        "name": finding.rule_name,
                        "shortDescription": {
                            "text": finding.description,
                        },
                        "defaultConfiguration": {
                            "level": self._severity_to_sarif_level(finding.severity),
                        },
                        "properties": {
                            "category": finding.category.value,
                        },
                    })

                # Add result
                sarif_result = {
                    "ruleId": rule_id,
                    "level": self._severity_to_sarif_level(finding.severity),
                    "message": {
                        "text": finding.description,
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": result.source or "inline",
                                },
                                "region": {
                                    "start": {
                                        "charOffset": finding.position[0],
                                    },
                                    "end": {
                                        "charOffset": finding.position[1],
                                    },
                                },
                            },
                        }
                    ],
                    "properties": {
                        "matchedText": finding.matched_text,
                        "suggestion": finding.suggestion,
                        "cweId": finding.cwe_id,
                    },
                }

                if finding.cwe_id:
                    sarif_result["properties"]["cweId"] = finding.cwe_id

                sarif_results.append(sarif_result)

        return json.dumps(sarif, indent=2, ensure_ascii=False)

    @staticmethod
    def _severity_to_sarif_level(severity: Severity) -> str:
        """Convert a Severity enum to a SARIF level string.

        Args:
            severity: The severity level.

        Returns:
            SARIF level string.
        """
        mapping = {
            Severity.LOW: "note",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "error",
            Severity.CRITICAL: "error",
        }
        return mapping.get(severity, "warning")

    def _generate_text(self, results: List[ScanResult], lang: str = "en") -> str:
        """Generate a human-readable text report.

        Args:
            results: List of ScanResult objects.
            lang: Language for the report content.

        Returns:
            Plain text formatted report string.
        """
        lines: List[str] = []

        if lang == "zh":
            lines.append("=" * 60)
            lines.append("  PromptShield 安全检测报告")
            lines.append("=" * 60)
            lines.append(f"  生成时间: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
            lines.append(f"  扫描总数: {len(results)}")
            total_findings = sum(len(r.findings) for r in results)
            lines.append(f"  发现总数: {total_findings}")
            lines.append("=" * 60)
            lines.append("")
        else:
            lines.append("=" * 60)
            lines.append("  PromptShield Security Report")
            lines.append("=" * 60)
            lines.append(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
            lines.append(f"  Total Scans: {len(results)}")
            total_findings = sum(len(r.findings) for r in results)
            lines.append(f"  Total Findings: {total_findings}")
            lines.append("=" * 60)
            lines.append("")

        for result in results:
            source_label = result.source or "inline"
            separator = "-" * 60

            if lang == "zh":
                lines.append(separator)
                lines.append(f"[来源] {source_label}")
                lines.append(f"[风险评分] {result.score}/100 ({result.risk_level})")
                lines.append(f"[发现数量] {len(result.findings)}")
            else:
                lines.append(separator)
                lines.append(f"[Source] {source_label}")
                lines.append(f"[Risk Score] {result.score}/100 ({result.risk_level})")
                lines.append(f"[Findings] {len(result.findings)}")

            if result.findings:
                lines.append("")
                for finding in result.findings:
                    if lang == "zh":
                        lines.append(f"  [!] {finding.rule_id}: {finding.rule_name}")
                        lines.append(f"      严重程度: {finding.severity.value.upper()}")
                        lines.append(f"      类别: {finding.category.value}")
                        lines.append(f"      描述: {finding.description}")
                        lines.append(f"      匹配文本: {finding.matched_text[:80]}")
                        lines.append(f"      位置: 字符 {finding.position[0]}-{finding.position[1]}")
                        if finding.suggestion:
                            lines.append(f"      建议: {finding.suggestion}")
                        if finding.cwe_id:
                            lines.append(f"      CWE: {finding.cwe_id}")
                    else:
                        lines.append(f"  [!] {finding.rule_id}: {finding.rule_name}")
                        lines.append(f"      Severity: {finding.severity.value.upper()}")
                        lines.append(f"      Category: {finding.category.value}")
                        lines.append(f"      Description: {finding.description}")
                        lines.append(f"      Matched: {finding.matched_text[:80]}")
                        lines.append(f"      Position: chars {finding.position[0]}-{finding.position[1]}")
                        if finding.suggestion:
                            lines.append(f"      Suggestion: {finding.suggestion}")
                        if finding.cwe_id:
                            lines.append(f"      CWE: {finding.cwe_id}")
                    lines.append("")
            else:
                if lang == "zh":
                    lines.append("  [OK] 未发现安全问题")
                else:
                    lines.append("  [OK] No security issues found")
                lines.append("")

        lines.append("=" * 60)
        if lang == "zh":
            lines.append("  报告结束 - PromptShield-CLI v1.0.0")
        else:
            lines.append("  End of Report - PromptShield-CLI v1.0.0")
        lines.append("=" * 60)

        return "\n".join(lines)
