"""Data models for PromptShield scan results and findings."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class Severity(Enum):
    """Severity levels for security findings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score_weight(self) -> int:
        """Return the score weight for severity calculation."""
        weights = {
            Severity.LOW: 5,
            Severity.MEDIUM: 15,
            Severity.HIGH: 30,
            Severity.CRITICAL: 50,
        }
        return weights[self]

    @property
    def color(self) -> str:
        """Return the display color for this severity level."""
        colors = {
            Severity.LOW: "green",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red",
        }
        return colors[self]


class Category(Enum):
    """Categories of security rules and findings."""
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    SENSITIVE_INFO = "sensitive_info"
    HARMFUL_CONTENT = "harmful_content"
    PROMPT_LEAKAGE = "prompt_leakage"
    BYPASS_TECHNIQUE = "bypass_technique"

    @property
    def display_name(self) -> str:
        """Return a human-readable display name for the category."""
        names = {
            Category.PROMPT_INJECTION: "Prompt Injection",
            Category.DATA_EXFILTRATION: "Data Exfiltration",
            Category.SENSITIVE_INFO: "Sensitive Information",
            Category.HARMFUL_CONTENT: "Harmful Content",
            Category.PROMPT_LEAKAGE: "Prompt Leakage",
            Category.BYPASS_TECHNIQUE: "Bypass Technique",
        }
        return names[self]

    @property
    def color(self) -> str:
        """Return the display color for this category."""
        colors = {
            Category.PROMPT_INJECTION: "bold red",
            Category.DATA_EXFILTRATION: "bold yellow",
            Category.SENSITIVE_INFO: "bold magenta",
            Category.HARMFUL_CONTENT: "bold red",
            Category.PROMPT_LEAKAGE: "bold cyan",
            Category.BYPASS_TECHNIQUE: "bold blue",
        }
        return colors[self]


@dataclass
class Finding:
    """Represents a single security finding from a scan.

    Attributes:
        rule_id: Unique identifier for the rule that triggered this finding.
        rule_name: Human-readable name of the rule.
        category: The category of the security issue.
        severity: The severity level of the finding.
        description: Detailed description of the finding.
        matched_text: The specific text that matched the rule pattern.
        position: Character position (start, end) of the matched text.
        suggestion: Suggested remediation for the finding.
        cwe_id: MITRE CWE identifier if applicable.
    """
    rule_id: str
    rule_name: str
    category: Category
    severity: Severity
    description: str
    matched_text: str
    position: tuple
    suggestion: str
    cwe_id: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert the finding to a dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "matched_text": self.matched_text,
            "position": {
                "start": self.position[0],
                "end": self.position[1],
            },
            "suggestion": self.suggestion,
            "cwe_id": self.cwe_id,
        }


@dataclass
class ScanResult:
    """Represents the result of scanning a single prompt.

    Attributes:
        prompt_text: The original prompt text that was scanned.
        findings: List of security findings detected in the prompt.
        score: Risk score from 0 (safe) to 100 (dangerous).
        severity_counts: Count of findings per severity level.
        timestamp: When the scan was performed.
        source: Optional source identifier (filename, etc.).
    """
    prompt_text: str
    findings: List[Finding] = field(default_factory=list)
    score: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    source: Optional[str] = None

    def __post_init__(self) -> None:
        """Calculate score and severity counts after initialization."""
        self._calculate_score()
        self._calculate_severity_counts()

    def _calculate_score(self) -> None:
        """Calculate the overall risk score based on findings."""
        total_score = 0
        for finding in self.findings:
            total_score += finding.severity.score_weight
        # Cap at 100
        self.score = min(total_score, 100)

    def _calculate_severity_counts(self) -> None:
        """Count findings by severity level."""
        self.severity_counts = {
            Severity.LOW.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.HIGH.value: 0,
            Severity.CRITICAL.value: 0,
        }
        for finding in self.findings:
            self.severity_counts[finding.severity.value] += 1

    @property
    def is_safe(self) -> bool:
        """Return True if no findings were detected."""
        return len(self.findings) == 0

    @property
    def risk_level(self) -> str:
        """Return a human-readable risk level description."""
        if self.score == 0:
            return "SAFE"
        elif self.score <= 15:
            return "LOW RISK"
        elif self.score <= 40:
            return "MEDIUM RISK"
        elif self.score <= 70:
            return "HIGH RISK"
        else:
            return "CRITICAL RISK"

    def to_dict(self) -> Dict:
        """Convert the scan result to a dictionary representation."""
        return {
            "prompt_text": self.prompt_text,
            "source": self.source,
            "score": self.score,
            "risk_level": self.risk_level,
            "findings_count": len(self.findings),
            "severity_counts": self.severity_counts,
            "findings": [f.to_dict() for f in self.findings],
            "timestamp": self.timestamp,
        }
