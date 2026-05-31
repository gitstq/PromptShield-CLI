"""Security detection rules for PromptShield.

Contains 50+ detection rules organized into 6 categories:
1. Prompt Injection
2. Data Exfiltration
3. Sensitive Information
4. Harmful Content
5. Prompt Leakage
6. Bypass Techniques
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern

from promptshield.models import Category, Finding, Severity


@dataclass
class RuleConfig:
    """Configuration for a detection rule.

    Attributes:
        rule_id: Unique identifier for the rule.
        name: Human-readable name.
        description: Detailed description of what the rule detects.
        severity: Severity level of findings from this rule.
        category: The security category this rule belongs to.
        patterns: List of regex patterns to match.
        suggestion: Remediation suggestion.
        cwe_id: MITRE CWE identifier if applicable.
    """
    rule_id: str
    name: str
    description: str
    severity: Severity
    category: Category
    patterns: List[str] = field(default_factory=list)
    suggestion: str = ""
    cwe_id: Optional[str] = None


class Rule(ABC):
    """Abstract base class for all detection rules."""

    def __init__(self, config: RuleConfig) -> None:
        """Initialize the rule with its configuration.

        Args:
            config: The rule configuration.
        """
        self.config = config
        self._compiled_patterns: List[Pattern] = []
        for pattern_str in config.patterns:
            try:
                self._compiled_patterns.append(re.compile(pattern_str, re.IGNORECASE | re.DOTALL))
            except re.error:
                # Skip invalid patterns gracefully
                pass

    @abstractmethod
    def check(self, text: str) -> List[Finding]:
        """Check text against this rule and return any findings.

        Args:
            text: The text to analyze.

        Returns:
            List of findings from this rule.
        """
        pass

    def _find_pattern_matches(self, text: str) -> List[Finding]:
        """Find all regex pattern matches in the text.

        Args:
            text: The text to search.

        Returns:
            List of findings for each match.
        """
        findings: List[Finding] = []
        seen_positions: set = set()

        for pattern in self._compiled_patterns:
            for match in pattern.finditer(text):
                start, end = match.start(), match.end()
                if (start, end) not in seen_positions:
                    seen_positions.add((start, end))
                    findings.append(Finding(
                        rule_id=self.config.rule_id,
                        rule_name=self.config.name,
                        category=self.config.category,
                        severity=self.config.severity,
                        description=self.config.description,
                        matched_text=match.group(),
                        position=(start, end),
                        suggestion=self.config.suggestion,
                        cwe_id=self.config.cwe_id,
                    ))
        return findings


class PatternRule(Rule):
    """Rule that detects issues based on regex pattern matching."""

    def check(self, text: str) -> List[Finding]:
        """Check text for pattern matches.

        Args:
            text: The text to analyze.

        Returns:
            List of findings.
        """
        return self._find_pattern_matches(text)


class CompositeRule(Rule):
    """Rule that requires multiple patterns to match (AND logic)."""

    def __init__(self, config: RuleConfig, required_matches: int = 2) -> None:
        """Initialize with a minimum match count requirement.

        Args:
            config: The rule configuration.
            required_matches: Number of distinct patterns that must match.
        """
        super().__init__(config)
        self.required_matches = required_matches

    def check(self, text: str) -> List[Finding]:
        """Check text requiring multiple pattern matches.

        Args:
            text: The text to analyze.

        Returns:
            List of findings if enough patterns match.
        """
        match_count = 0
        matched_text = ""
        position = (0, 0)

        for pattern in self._compiled_patterns:
            match = pattern.search(text)
            if match:
                match_count += 1
                matched_text = match.group()
                position = (match.start(), match.end())

        if match_count >= self.required_matches:
            return [Finding(
                rule_id=self.config.rule_id,
                rule_name=self.config.name,
                category=self.config.category,
                severity=self.config.severity,
                description=self.config.description,
                matched_text=matched_text,
                position=position,
                suggestion=self.config.suggestion,
                cwe_id=self.config.cwe_id,
            )]
        return []


# ---------------------------------------------------------------------------
# Category 1: Prompt Injection Rules
# ---------------------------------------------------------------------------

class DirectInjectionRule(PatternRule):
    """Detects direct prompt injection attempts."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PI-001",
            name="Direct Prompt Injection",
            description="Direct attempt to inject instructions into the prompt",
            severity=Severity.CRITICAL,
            category=Category.PROMPT_INJECTION,
            patterns=[
                r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?|directives?)",
                r"forget\s+(all\s+)?(your|the)\s+(instructions?|prompts?|rules?|training)",
                r"disregard\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)",
                r"ignore\s+(everything|all)\s+(you|the system)\s+(said|told|instructed)",
                r"do\s+not\s+follow\s+(your|the|any)\s+(instructions?|rules?|guidelines?)",
            ],
            suggestion="Sanitize user input to prevent instruction injection. Use prompt delimiters and input validation.",
            cwe_id="CWE-74",
        ))


class IndirectInjectionRule(PatternRule):
    """Detects indirect injection through data manipulation."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PI-002",
            name="Indirect Prompt Injection",
            description="Indirect injection attempt through data or context manipulation",
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            patterns=[
                r"(?:user|data|input|text|message)\s*(?:says|states|contains|is|reads)[:\s]+.*(?:ignore|forget|disregard)",
                r"(?:hidden|invisible|encoded|obfuscated)\s*(?:instruction|command|prompt|directive)",
                r"(?:translate|convert|process)\s*(?:the\s+)?(?:following|this|these)\s*(?:text|data|input)\s*(?:and|then)",
                r"(?:pretend|act\s+as\s+if)\s+(?:you\s+)?(?:didn'?t\s+)?(?:see|read|receive)",
                r"(?:when|if|after)\s+(?:you|the\s+system)\s+(?:process|read|analyze)\s+(?:this|the)\s+(?:text|input|data)",
            ],
            suggestion="Implement context isolation between user data and system prompts. Validate data sources.",
            cwe_id="CWE-74",
        ))


class RolePlayJailbreakRule(PatternRule):
    """Detects role-playing based jailbreak attempts."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PI-003",
            name="Role-Play Jailbreak",
            description="Jailbreak attempt through role-playing or persona adoption",
            severity=Severity.CRITICAL,
            category=Category.PROMPT_INJECTION,
            patterns=[
                r"(?:pretend|act|imagine|roleplay|role-play)\s+(?:you\s+are|as\s+if\s+you|to\s+be)\s+(?:a|an|the)\s+\w+",
                r"(?:pretend|act|imagine|roleplay|role-play)\s+(?:you\s+are|as\s+if\s+you|to\s+be)\s+\w+,\s*(?:an?\s+)?\w+",
                r"(?:you\s+are\s+now|from\s+now\s+on(?:\s+you)?\s+are)\s+(?:a|an|the)?\s*\w+",
                r"(?:assume|take\s+on)\s+(?:the\s+)?(?:role|persona|character|identity)\s+of",
                r"(?:DAN|Developer\s+Mode|evil\s+mode|unfiltered|uncensored)\s+(?:mode|is|enabled|on)",
                r"(?:switch\s+to|enter|activate)\s+(?:jailbreak|developer|DAN|evil|unfiltered)\s+(?:mode|persona)",
                r"(?:I\s+am|you\s+are)\s+(?:now|currently)\s+(?:DAN|jailbroken|unfiltered|unrestricted)",
            ],
            suggestion="Implement persona validation and restrict role adoption. Use system-level constraints.",
            cwe_id="CWE-74",
        ))


class InstructionOverrideRule(PatternRule):
    """Detects attempts to override system instructions."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PI-004",
            name="Instruction Override",
            description="Attempt to override or replace system instructions",
            severity=Severity.CRITICAL,
            category=Category.PROMPT_INJECTION,
            patterns=[
                r"(?:new|updated|revised|modified)\s+(?:instructions?|rules?|directives?|guidelines?)\s*[:]",
                r"(?:system|your)\s+(?:new|updated|revised)\s+(?:instructions?|rules?|prompt|directive)\s*:",
                r"(?:override|replace|substitute|supersede)\s+(?:all|the|your|current)\s+(?:instructions?|rules?|prompts?)",
                r"(?:from\s+now\s+on|starting\s+now|henceforth),?\s*(?:you\s+must|always|only)\s+\w+",
                r"(?:your\s+new|the\s+new)\s+(?:task|mission|objective|goal|purpose)\s+is\s+(?:to|:)",
            ],
            suggestion="Use immutable system prompts with strong delimiters. Never accept instruction overrides from user input.",
            cwe_id="CWE-74",
        ))


class DelimiterAttackRule(PatternRule):
    """Detects delimiter-based injection attacks."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PI-005",
            name="Delimiter Attack",
            description="Injection attempt using special delimiters or markers",
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            patterns=[
                r"(?:<\|im_start\|>|<\|im_end\|>)",
                r"(?:###\s*(?:INSTRUCTION|RESPONSE|USER|ASSISTANT|SYSTEM)\s*###)",
                r"(?:---+\s*(?:BEGIN|END)\s+(?:USER|SYSTEM|INSTRUCTION)\s*---+)",
                r"(?:\[INST\]|\[/INST\]|\[RESP\]|\[/RESP\])",
                r"(?:<\|(?:user|assistant|system)\|>)",
                r"(?:<<SYS>>|<</SYS>>|<<USER>>|<<ASSISTANT>>)",
            ],
            suggestion="Use unique, unpredictable delimiters for system prompts. Sanitize special character sequences.",
            cwe_id="CWE-74",
        ))


class EncodingBypassRule(PatternRule):
    """Detects encoding-based bypass attempts."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PI-006",
            name="Encoding Bypass",
            description="Attempt to bypass filters using text encoding",
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            patterns=[
                r"(?:base64|hex|binary|rot13|url)\s*(?:encoded|decode|encrypt)\s*[:\s]+\S+",
                r"(?:\\x[0-9a-fA-F]{2}){4,}",
                r"(?:&#\d+;|&#x[0-9a-fA-F]+;){3,}",
                r"(?:\\u[0-9a-fA-F]{4}){3,}",
                r"(?:eval\s*\(\s*(?:atob|btoa|decode|unescap))",
            ],
            suggestion="Decode and normalize all encoded input before processing. Implement multi-layer filtering.",
            cwe_id="CWE-74",
        ))


class MultiLanguageInjectionRule(PatternRule):
    """Detects multi-language injection attempts."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PI-007",
            name="Multi-Language Injection",
            description="Injection attempt using non-English languages to evade detection",
            severity=Severity.MEDIUM,
            category=Category.PROMPT_INJECTION,
            patterns=[
                r"(?:忽略|忘记|无视| disregard|丢弃)\s*(?:所有|之前|上述|全部)\s*(?:指令|提示|规则|命令)",
                r"(?:假装|扮演|假设)\s*(?:你是|作为)\s*(?:一个|一名)",
                r"(?:无视|忽略|不要|停止)\s*(?:你的|系统|所有)\s*(?:指令|规则|限制|约束)",
                r"(?:新しい|無視|忘却|無効)\s*(?:指示|命令|ルール|制限)",
                r"(?:ignora|olvida|desactiva|ignorar|pretende)\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones?|reglas?|restricciones?)",
            ],
            suggestion="Implement multi-language detection and filtering. Normalize text to a canonical form before analysis.",
            cwe_id="CWE-74",
        ))


class ChainOfThoughtInjectionRule(PatternRule):
    """Detects injection through chain-of-thought manipulation."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PI-008",
            name="Chain-of-Thought Injection",
            description="Injection attempt through thought chain manipulation",
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            patterns=[
                r"(?:think\s+step\s+by\s+step.*?(?:ignore|forget|bypass|override))",
                r"(?:let'?s\s+think.*?(?:but\s+actually|however|instead|wait))",
                r"(?:reasoning:?\s*.*?(?:ignore|disregard|forget)\s+(?:your|the|all)\s+(?:rules|instructions))",
                r"(?:first,?\s*.*?(?:then\s+(?:ignore|bypass|override|skip)))",
                r"(?:step\s+\d+:?\s*.*?(?:ignore|forget|disregard|bypass))",
            ],
            suggestion="Isolate reasoning chains from user input. Validate intermediate reasoning steps.",
            cwe_id="CWE-74",
        ))


class FewShotManipulationRule(PatternRule):
    """Detects few-shot example manipulation."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PI-009",
            name="Few-Shot Manipulation",
            description="Manipulation of few-shot examples to alter model behavior",
            severity=Severity.MEDIUM,
            category=Category.PROMPT_INJECTION,
            patterns=[
                r"(?:example\s+\d+:?\s*.*?(?:ignore|bypass|hack|inject|override))",
                r"(?:Q:\s*.*?(?:ignore|forget|disregard).*?A:\s*)",
                r"(?:input:\s*.*?(?:malicious|harmful|inject).*?output:\s*)",
                r"(?:demonstration\s+\d+:?\s*.*?(?:jailbreak|bypass|hack))",
                r"(?:sample\s+\d+:?\s*.*?(?:ignore|override|break))",
            ],
            suggestion="Validate and sanitize few-shot examples. Use fixed, server-side examples only.",
            cwe_id="CWE-74",
        ))


# ---------------------------------------------------------------------------
# Category 2: Data Exfiltration Rules
# ---------------------------------------------------------------------------

class SensitiveDataExtractionRule(PatternRule):
    """Detects attempts to extract sensitive data."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="DE-001",
            name="Sensitive Data Extraction",
            description="Attempt to extract sensitive data from the system",
            severity=Severity.CRITICAL,
            category=Category.DATA_EXFILTRATION,
            patterns=[
                r"(?:output|print|display|show|reveal|tell\s+me|list)\s+(?:all|your|the|every)\s+(?:secrets?|keys?|passwords?|tokens?|credentials?)",
                r"(?:what\s+(?:are|is)\s+your\s+(?:secret|key|password|token|api|credential|hidden)\s+(?:key|password|token|phrase|instructions?))",
                r"(?:send|transmit|exfiltrate|export|dump)\s+(?:all|your|the)\s+(?:data|information|secrets?|keys?)",
                r"(?:reveal|expose|disclose|leak|share)\s+(?:your|the|system'?s?)\s+(?:prompt|instructions?|configuration|secrets?)",
                r"(?:extract|obtain|retrieve|get|fetch)\s+(?:all|the|your)\s+(?:internal|hidden|secret|private)\s+(?:data|info|details?)",
            ],
            suggestion="Implement output filtering. Never include system secrets or internal data in responses.",
            cwe_id="CWE-200",
        ))


class SystemPromptLeakageRule(PatternRule):
    """Detects attempts to leak system prompts."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="DE-002",
            name="System Prompt Leakage",
            description="Attempt to extract or reveal the system prompt",
            severity=Severity.HIGH,
            category=Category.DATA_EXFILTRATION,
            patterns=[
                r"(?:repeat|recite|echo|quote|reproduce|paste|copy)\s+(?:your|the|exactly|verbatim)\s+(?:system\s+prompt|instructions?|initial\s+prompt)",
                r"(?:what\s+(?:is|are|was)\s+your\s+(?:original|initial|system|first)\s+(?:prompt|instructions?|message|directive))",
                r"(?:show\s+me\s+(?:your|the)\s+(?:full|complete|entire|exact)\s+(?:system|hidden|initial)\s+(?:prompt|instructions?))",
                r"(?:tell\s+me\s+(?:what|exactly|precisely)\s+(?:you\s+were|the\s+system\s+was)\s+(?:told|instructed|configured))",
                r"(?:print\s+(?:your|the)\s+(?:system|initial|original)\s+(?:prompt|instructions?|message)\s+(?:from|starting)\s+(?:the\s+)?(?:beginning|start))",
            ],
            suggestion="Use prompt hardening techniques. Never echo system prompts verbatim.",
            cwe_id="CWE-200",
        ))


class TrainingDataExtractionRule(PatternRule):
    """Detects attempts to extract training data."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="DE-003",
            name="Training Data Extraction",
            description="Attempt to extract memorized training data",
            severity=Severity.MEDIUM,
            category=Category.DATA_EXFILTRATION,
            patterns=[
                r"(?:what\s+(?:data|text|information)\s+(?:were\s+you|did\s+you)\s+(?:trained\s+on|learned\s+from|fed\s+during\s+training))",
                r"(?:recall|remember|output)\s+(?:your\s+)?(?:training\s+data|training\s+set|memorized\s+text|learned\s+information)",
                r"(?:can\s+you\s+(?:recall|remember|reproduce)\s+(?:any|some|specific)\s+(?:training|memorized|learned)\s+(?:data|text|examples?))",
                r"(?:what\s+(?:examples?|sentences?|paragraphs?|documents?)\s+(?:were\s+)?(?:in\s+your\s+)?(?:training\s+(?:data|set|corpus)))",
            ],
            suggestion="Implement differential privacy and output deduplication against training data.",
            cwe_id="CWE-200",
        ))


class ConversationHistoryExtractionRule(PatternRule):
    """Detects attempts to extract conversation history."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="DE-004",
            name="Conversation History Extraction",
            description="Attempt to extract previous conversation data",
            severity=Severity.MEDIUM,
            category=Category.DATA_EXFILTRATION,
            patterns=[
                r"(?:show|list|print|display)\s+(?:all|previous|past|earlier|prior)\s+(?:conversations?|chats?|messages?|dialogues?)",
                r"(?:what\s+(?:did|have)\s+(?:I|we|other\s+users?)\s+(?:ask|say|tell|discuss|chat\s+about)\s+(?:before|earlier|previously|in\s+the\s+past))",
                r"(?:reveal|share|output)\s+(?:your|the)\s+(?:conversation|chat|message)\s+(?:history|log|record)",
            ],
            suggestion="Implement conversation isolation and access controls.",
            cwe_id="CWE-200",
        ))


# ---------------------------------------------------------------------------
# Category 3: Sensitive Information Rules
# ---------------------------------------------------------------------------

class APIKeyDetectionRule(PatternRule):
    """Detects exposed API keys."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="SI-001",
            name="API Key Detection",
            description="Detects exposed API keys in the text",
            severity=Severity.CRITICAL,
            category=Category.SENSITIVE_INFO,
            patterns=[
                r"(?:sk|pk|rk|tk|ak)[_-][a-zA-Z0-9\-_]{20,}",
                r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[a-zA-Z0-9\-_]{20,}['\"]?",
                r"(?:AKIA|ASIA|AIDA|AIPA|AROA|AIDA|ANPA|ANVA|AGPA)[A-Z0-9]{16}",
                r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}",
                r"(?:xox[bpas])-[a-zA-Z0-9\-]{10,}",
                r"AIza[a-zA-Z0-9\-_]{35}",
                r"(?:hooks\.googleusercontent\.com/[a-zA-Z0-9\-_/]+)",
            ],
            suggestion="Remove API keys from prompts. Use environment variables or secret management.",
            cwe_id="CWE-798",
        ))


class PasswordDetectionRule(PatternRule):
    """Detects exposed passwords."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="SI-002",
            name="Password Detection",
            description="Detects exposed passwords in the text",
            severity=Severity.CRITICAL,
            category=Category.SENSITIVE_INFO,
            patterns=[
                r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?\S{8,}['\"]?",
                r"(?:pass(?:word)?|secret)\s+(?:is|:)\s*['\"]?\S{6,}['\"]?",
                r"(?:my\s+password\s+is|the\s+password\s+is)\s+\S+",
                r"(?:db_password|admin_pass|root_pass|user_pass)\s*[=:]\s*['\"]?\S+['\"]?",
            ],
            suggestion="Never include passwords in prompts. Use secure credential management.",
            cwe_id="CWE-798",
        ))


class EmailDetectionRule(PatternRule):
    """Detects email addresses that may be PII."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="SI-003",
            name="Email Address Detection",
            description="Detects email addresses that may be personal information",
            severity=Severity.LOW,
            category=Category.SENSITIVE_INFO,
            patterns=[
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            ],
            suggestion="Consider redacting email addresses before sending to AI services.",
            cwe_id="CWE-359",
        ))


class PhoneDetectionRule(PatternRule):
    """Detects phone numbers that may be PII."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="SI-004",
            name="Phone Number Detection",
            description="Detects phone numbers that may be personal information",
            severity=Severity.LOW,
            category=Category.SENSITIVE_INFO,
            patterns=[
                r"(?:\+?86[-\s]?)?1[3-9]\d[-\s]?\d{4}[-\s]?\d{4}",
                r"(?:\+?1[-\s.]?)?\(?\d{3}\)?[-\s.]?\d{3}[-\s.]?\d{4}",
                r"(?:\+44[-\s]?)?(?:\d{2}[-\s]?)?\d{4}[-\s]?\d{6}",
            ],
            suggestion="Consider redacting phone numbers before sending to AI services.",
            cwe_id="CWE-359",
        ))


class IDCardDetectionRule(PatternRule):
    """Detects Chinese ID card numbers."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="SI-005",
            name="ID Card Number Detection",
            description="Detects Chinese national ID card numbers",
            severity=Severity.HIGH,
            category=Category.SENSITIVE_INFO,
            patterns=[
                r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
            ],
            suggestion="Never include ID card numbers in prompts. This is sensitive PII.",
            cwe_id="CWE-359",
        ))


class SecretKeyDetectionRule(PatternRule):
    """Detects private/secret keys."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="SI-006",
            name="Secret Key Detection",
            description="Detects private/secret keys in the text",
            severity=Severity.CRITICAL,
            category=Category.SENSITIVE_INFO,
            patterns=[
                r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----",
                r"(?:private[_-]?key|secret[_-]?key)\s*[=:]\s*['\"]?[a-zA-Z0-9\-/+=]{20,}['\"]?",
                r"(?:BEGIN|END)\s+(?:RSA|EC|DSA|SSH)\s+(?:PRIVATE|PUBLIC)\s+KEY",
                r"(?:signing[_-]?key|auth[_-]?token|access[_-]?token)\s*[=:]\s*['\"]?\S{20,}['\"]?",
                r"(?:JWT|bearer)\s*[=:]\s*['\"]?eyJ[a-zA-Z0-9\-_.]+['\"]?",
            ],
            suggestion="Never include private keys or tokens in prompts. Use a secrets manager.",
            cwe_id="CWE-798",
        ))


class DatabaseConnectionDetectionRule(PatternRule):
    """Detects database connection strings."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="SI-007",
            name="Database Connection String Detection",
            description="Detects database connection strings with credentials",
            severity=Severity.HIGH,
            category=Category.SENSITIVE_INFO,
            patterns=[
                r"(?:mongodb|postgres|mysql|redis|amqp)://[^\s]+:[^\s]+@[^\s]+",
                r"(?:mysql|pgsql|psql|sqlite|oracle)://[^\s]+:[^\s]+@[^\s]+",
                r"(?:DB_HOST|DB_USER|DB_PASS|DATABASE_URL|REDIS_URL)\s*[=:]\s*['\"]?\S+['\"]?",
            ],
            suggestion="Remove database connection strings from prompts. Use environment variables.",
            cwe_id="CWE-798",
        ))


class IPDetectionRule(PatternRule):
    """Detects IP addresses that may be sensitive."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="SI-008",
            name="IP Address Detection",
            description="Detects IP addresses that may be sensitive infrastructure information",
            severity=Severity.LOW,
            category=Category.SENSITIVE_INFO,
            patterns=[
                r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            ],
            suggestion="Consider redacting IP addresses before sending to AI services.",
            cwe_id="CWE-359",
        ))


# ---------------------------------------------------------------------------
# Category 4: Harmful Content Rules
# ---------------------------------------------------------------------------

class MaliciousCodeRule(PatternRule):
    """Detects requests to generate malicious code."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="HC-001",
            name="Malicious Code Generation",
            description="Request to generate malicious or harmful code",
            severity=Severity.CRITICAL,
            category=Category.HARMFUL_CONTENT,
            patterns=[
                r"(?:write|create|generate|make|build|code)\s+(?:a|an|the|me)\s+(?:malware|virus|trojan|ransomware|worm|backdoor|rootkit|keylogger)",
                r"(?:how\s+to\s+(?:write|create|make|build|code))\s+(?:a\s+)?(?:malware|virus|trojan|ransomware|exploit|backdoor)",
                r"(?:write|create)\s+(?:a\s+)?(?:exploit|payload|shellcode|buffer\s+overflow|sql\s+injection|XSS)\s+(?:for|against|to)",
                r"(?:create|write|generate)\s+(?:a\s+)?(?:phishing|spam|botnet|DDoS|brute\s+force)\s+(?:page|site|script|tool|attack)",
                r"(?:help\s+me\s+(?:hack|attack|break\s+into|compromise|exploit|breach))",
            ],
            suggestion="Reject requests to generate malicious code. Implement content safety filters.",
            cwe_id="CWE-94",
        ))


class PhishingTemplateRule(PatternRule):
    """Detects requests to create phishing templates."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="HC-002",
            name="Phishing Template Generation",
            description="Request to create phishing or social engineering templates",
            severity=Severity.HIGH,
            category=Category.HARMFUL_CONTENT,
            patterns=[
                r"(?:write|create|make|generate|draft)\s+(?:a|an|the|me)\s+(?:phishing|spoofing|scam)\s+(?:email|message|page|site|template|letter)",
                r"(?:create|make|write)\s+(?:a\s+)?(?:fake|spoofed|fraudulent)\s+(?:login|bank|email|website|portal)\s+(?:page|site|form)",
                r"(?:impersonate|pretend\s+to\s+be|pose\s+as)\s+(?:a|an|the)\s+(?:bank|company|service|person|authority)",
                r"(?:write\s+(?:a\s+)?(?:scam|fraud|deceptive)\s+(?:email|message|letter|text))",
            ],
            suggestion="Reject requests to create phishing content. Implement content safety filters.",
            cwe_id="CWE-451",
        ))


class SocialEngineeringRule(PatternRule):
    """Detects social engineering attack patterns."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="HC-003",
            name="Social Engineering",
            description="Social engineering attack patterns detected",
            severity=Severity.HIGH,
            category=Category.HARMFUL_CONTENT,
            patterns=[
                r"(?:manipulate|trick|deceive|coerce|pressure)\s+(?:the\s+)?(?:user|person|victim|target|employee)\s+(?:into|to)",
                r"(?:how\s+to\s+(?:manipulate|trick|deceive|convince|persuade))\s+(?:someone|people|users?|a\s+person)",
                r"(?:create|write|make)\s+(?:a\s+)?(?:pretext|cover\s+story|false\s+story|deceptive\s+story)\s+(?:for|to)",
                r"(?:bait|lure|entice|groom)\s+(?:the\s+)?(?:user|victim|target)\s+(?:into|to|with)",
            ],
            suggestion="Reject requests involving social engineering techniques.",
            cwe_id="CWE-451",
        ))


class IllegalContentRule(PatternRule):
    """Detects requests for illegal content."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="HC-004",
            name="Illegal Content Request",
            description="Request for illegal or prohibited content",
            severity=Severity.CRITICAL,
            category=Category.HARMFUL_CONTENT,
            patterns=[
                r"(?:how\s+to\s+(?:make|create|manufacture|produce|cook))\s+(?:a\s+)?(?:bomb|explosive|weapon|drug|meth)",
                r"(?:recipe|instructions?|guide|tutorial)\s+(?:for|to|on)\s+(?:making|creating|building)\s+(?:drugs?|bombs?|weapons?|explosives?)",
                r"(?:how\s+to\s+(?:steal|rob|burgle|shoplift|embezzle|defraud|launder\s+money))",
                r"(?:how\s+to\s+(?:commit|perform|execute))\s+(?:a\s+)?(?:crime|fraud|murder|assault|theft|hack)",
                r"(?:buy|purchase|acquire|obtain)\s+(?:illegal|fake|counterfeit|stolen|black\s+market)\s+(?:goods|documents?|weapons?|drugs?)",
            ],
            suggestion="Reject all requests for illegal content. Implement strict content moderation.",
            cwe_id="CWE-94",
        ))


class DoxxingRule(PatternRule):
    """Detects doxxing attempts."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="HC-005",
            name="Doxxing Attempt",
            description="Attempt to identify or expose personal information about individuals",
            severity=Severity.HIGH,
            category=Category.HARMFUL_CONTENT,
            patterns=[
                r"(?:find|look\s+up|search|identify|locate|track)\s+(?:the\s+)?(?:real|personal|private|home)\s+(?:identity|name|address|location|phone|info)",
                r"(?:doxx|dox|expose|reveal|unmask|deanonymize)\s+(?:the|this|a|an)\s+(?:user|person|individual|someone)",
                r"(?:what\s+is|find\s+(?:me|out))\s+(?:the|his|her|their)\s+(?:real\s+)?(?:name|address|location|identity|phone)",
                r"(?:where\s+(?:does|do)\s+(?:he|she|they|this\s+person))\s+(?:live|work|reside|stay)",
            ],
            suggestion="Reject doxxing requests. Implement PII protection measures.",
            cwe_id="CWE-359",
        ))


class SelfHarmRule(PatternRule):
    """Detects content related to self-harm."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="HC-006",
            name="Self-Harm Content",
            description="Content related to self-harm or suicide",
            severity=Severity.CRITICAL,
            category=Category.HARMFUL_CONTENT,
            patterns=[
                r"(?:how\s+to\s+(?:kill|harm|hurt|end)\s+(?:myself|oneself|yourself))",
                r"(?:ways?\s+to\s+(?:commit|die|end\s+it|suicide|self-harm))",
                r"(?:I\s+want\s+to\s+(?:die|kill\s+myself|hurt\s+myself|end\s+my\s+life))",
                r"(?:methods?\s+(?:of|for)\s+(?:suicide|self-harm|killing\s+oneself))",
            ],
            suggestion="Implement crisis response. Redirect to help resources.",
            cwe_id="CWE-94",
        ))


# ---------------------------------------------------------------------------
# Category 5: Prompt Leakage Rules
# ---------------------------------------------------------------------------

class SystemPromptExposureRule(PatternRule):
    """Detects system prompt exposure in user input."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PL-001",
            name="System Prompt Exposure",
            description="User input contains what appears to be a leaked system prompt",
            severity=Severity.HIGH,
            category=Category.PROMPT_LEAKAGE,
            patterns=[
                r"(?:You\s+are|you\s+are)\s+(?:a|an|the)\s+(?:helpful|AI|language|assistant|chat)\s+(?:assistant|model|bot)",
                r"(?:As\s+an?\s+AI|As\s+a\s+language\s+model|As\s+(?:a|an)\s+(?:AI|assistant))",
                r"(?:You\s+(?:must|should|are\s+instructed\s+to|are\s+designed\s+to)\s+(?:not|never|always|only))",
                r"(?:Your\s+(?:purpose|role|task|mission|goal|objective)\s+(?:is|:))",
                r"(?:You\s+(?:have\s+been|are)\s+(?:trained|designed|programmed|configured)\s+(?:to|as|for))",
            ],
            suggestion="Review system prompt for potential leakage. Use prompt isolation techniques.",
            cwe_id="CWE-200",
        ))


class FewShotLeakageRule(PatternRule):
    """Detects few-shot example leakage."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PL-002",
            name="Few-Shot Leakage",
            description="Few-shot examples may be leaking internal prompt structure",
            severity=Severity.MEDIUM,
            category=Category.PROMPT_LEAKAGE,
            patterns=[
                r"(?:Example\s+\d+:|Q\d+:|Input\s+\d+:|Prompt\s+\d+:)\s*\n",
                r"(?:A\d+:|Response\s+\d+:|Output\s+\d+:)\s*\n",
                r"(?:Here\s+(?:are|is)\s+(?:some|a\s+few|the)\s+(?:examples?|demonstrations?|samples?))",
            ],
            suggestion="Review few-shot examples for information leakage. Sanitize example content.",
            cwe_id="CWE-200",
        ))


class ToolUsageLeakageRule(PatternRule):
    """Detects tool usage information leakage."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PL-003",
            name="Tool Usage Leakage",
            description="Tool usage information may be leaking through prompts",
            severity=Severity.MEDIUM,
            category=Category.PROMPT_LEAKAGE,
            patterns=[
                r"(?:You\s+(?:have\s+)?(?:access\s+to|can\s+use|are\s+equipped\s+with)\s+(?:the\s+)?(?:following|these)\s+(?:tools?|functions?|capabilities?|plugins?))",
                r"(?:Available\s+(?:tools?|functions?|actions?|plugins?|capabilities?))\s*[:]",
                r"(?:tool_name|function_name|plugin_name)\s*[:=]\s*['\"]?\w+['\"]?",
                r"(?:You\s+may\s+(?:use|call|invoke)\s+(?:the\s+)?(?:\w+)\s+(?:tool|function|plugin|API))",
            ],
            suggestion="Review tool descriptions for information leakage. Minimize tool metadata exposure.",
            cwe_id="CWE-200",
        ))


class ConfigurationLeakageRule(PatternRule):
    """Detects configuration or parameter leakage."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="PL-004",
            name="Configuration Leakage",
            description="System configuration parameters may be leaking",
            severity=Severity.MEDIUM,
            category=Category.PROMPT_LEAKAGE,
            patterns=[
                r"(?:temperature|top_p|top_k|max_tokens|frequency_penalty|presence_penalty)\s*[=:]\s*[0-9.]+",
                r"(?:model_name|model_version|engine|deployment)\s*[=:]\s*['\"]?\w+['\"]?",
                r"(?:system\s+version|API\s+version|build\s+version)\s*[=:]\s*['\"]?\S+['\"]?",
            ],
            suggestion="Remove model configuration details from prompts.",
            cwe_id="CWE-200",
        ))


# ---------------------------------------------------------------------------
# Category 6: Bypass Technique Rules
# ---------------------------------------------------------------------------

class TokenSmugglingRule(PatternRule):
    """Detects token smuggling techniques."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="BT-001",
            name="Token Smuggling",
            description="Token smuggling technique to bypass content filters",
            severity=Severity.HIGH,
            category=Category.BYPASS_TECHNIQUE,
            patterns=[
                r"(?:token|word|character)\s*(?:smuggling|splitting|fragmentation|obfuscation)",
                r"(?:split\s+(?:the\s+)?(?:word|token|phrase|sentence)\s+(?:into|across))",
                r"(?:use\s+(?:spaces|special\s+chars?|invisible\s+chars?|zero-width)\s+(?:to|for|between))",
                r"(?:insert\s+(?:invisible|zero-width|hidden)\s+(?:characters?|spaces?|tokens?))",
                r"(?:break\s+(?:up|apart)\s+(?:the|a)\s+(?:word|phrase|instruction|command))",
            ],
            suggestion="Normalize and tokenize text before analysis. Remove invisible characters.",
            cwe_id="CWE-74",
        ))


class Base64BypassRule(PatternRule):
    """Detects base64 encoding used for bypass."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="BT-002",
            name="Base64 Bypass",
            description="Base64 encoded content that may be used to bypass filters",
            severity=Severity.HIGH,
            category=Category.BYPASS_TECHNIQUE,
            patterns=[
                r"(?:decode|decrypt|unencode)\s+(?:this|the)\s+(?:base64|b64|encoded)\s+(?:string|text|message|data)",
                r"(?:base64\s*(?:decode|encode)|b64\s*(?:decode|encode))\s*\(\s*['\"]?[A-Za-z0-9+/=]{20,}['\"]?",
                r"(?:please|pls|can\s+you)\s+(?:decode|decrypt|unencode)\s+(?:the\s+)?(?:following|this|the\s+below)",
                r"(?:atob|btoa|base64\.decode|base64\.encode)\s*\(\s*['\"]?[A-Za-z0-9+/=]{20,}['\"]?",
            ],
            suggestion="Decode all base64 content before analysis. Implement multi-layer content inspection.",
            cwe_id="CWE-74",
        ))


class UnicodeBypassRule(PatternRule):
    """Detects unicode manipulation for bypass."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="BT-003",
            name="Unicode Bypass",
            description="Unicode manipulation to bypass content filters",
            severity=Severity.MEDIUM,
            category=Category.BYPASS_TECHNIQUE,
            patterns=[
                r"(?:\\u[0-9a-fA-F]{4}){5,}",
                r"(?:U\+[0-9a-fA-F]{4}){3,}",
                r"(?:&#x[0-9a-fA-F]+;){3,}",
                r"(?:&#\d+;){5,}",
                r"(?:use\s+(?:unicode|homoglyphs?|lookalikes?|confusables?)\s+(?:to|for|characters?))",
                r"(?:fullwidth|halfwidth|homoglyph|confusable)\s+(?:characters?|letters?|text|substitution)",
            ],
            suggestion="Normalize unicode text (NFKC normalization) before analysis.",
            cwe_id="CWE-74",
        ))


class MarkdownInjectionRule(PatternRule):
    """Detects markdown-based injection attacks."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="BT-004",
            name="Markdown Injection",
            description="Markdown formatting used for injection attacks",
            severity=Severity.MEDIUM,
            category=Category.BYPASS_TECHNIQUE,
            patterns=[
                r"!\[.*?\]\(javascript:\S+\)",
                r"!\[.*?\]\(data:\S+;base64,\S+\)",
                r"<img\s+src\s*=\s*['\"]?(?:javascript|data)\s*:",
                r"<a\s+href\s*=\s*['\"]?(?:javascript|data)\s*:",
                r"!\[.*?\]\(https?://evil|malicious|attacker)",
            ],
            suggestion="Sanitize markdown content. Strip or escape dangerous HTML in markdown.",
            cwe_id="CWE-79",
        ))


class XMLInjectionRule(PatternRule):
    """Detects XML-based injection attacks."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="BT-005",
            name="XML Injection",
            description="XML tags used for injection or data manipulation",
            severity=Severity.HIGH,
            category=Category.BYPASS_TECHNIQUE,
            patterns=[
                r"<\?(?:xml|xsl)\s+",
                r"<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)\s+",
                r"<!DOCTYPE\s+\w+\s*\[",
                r"<!\[CDATA\[.*?(?:ignore|inject|override|bypass).*?\]\]>",
                r"<\!--\s*(?:ignore|inject|override|bypass|instruction)\s*-->",
                r"<(?:system|admin|root|superuser|debug|config)\s+",
            ],
            suggestion="Sanitize XML content. Disable external entity processing.",
            cwe_id="CWE-91",
        ))


class WhitespaceObfuscationRule(PatternRule):
    """Detects whitespace-based obfuscation."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="BT-006",
            name="Whitespace Obfuscation",
            description="Whitespace characters used to obfuscate malicious content",
            severity=Severity.MEDIUM,
            category=Category.BYPASS_TECHNIQUE,
            patterns=[
                r"(?:\u200b|\u200c|\u200d|\u2060|\u180e){3,}",
                r"(?:\u00a0|\u2002|\u2003|\u2004|\u2005|\u2006|\u2007|\u2008|\u2009){3,}",
                r"(?:\t|\r|\v|\f){5,}",
                r"(?:\s{10,})",
            ],
            suggestion="Normalize whitespace characters before analysis. Strip invisible characters.",
            cwe_id="CWE-74",
        ))


class PromptConcatenationRule(PatternRule):
    """Detects prompt concatenation attacks."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="BT-007",
            name="Prompt Concatenation Attack",
            description="Concatenation of multiple prompts to confuse the model",
            severity=Severity.HIGH,
            category=Category.BYPASS_TECHNIQUE,
            patterns=[
                r"(?:concat|combine|merge|join|append|chain)\s+(?:the|these|multiple)\s+(?:prompts?|instructions?|commands?)",
                r"(?:first\s+prompt|second\s+prompt|third\s+prompt|next\s+prompt)\s*[:.]",
                r"(?:part\s+1|part\s+2|part\s+3|section\s+1|section\s+2)\s*(?:of|:)",
                r"(?:continue\s+(?:from|with|where)\s+(?:the|last|previous|part))",
            ],
            suggestion="Implement prompt length limits and content validation.",
            cwe_id="CWE-74",
        ))


class ImagePromptExtractionRule(PatternRule):
    """Detects attempts to extract prompts from image generation."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="BT-008",
            name="Image Prompt Extraction",
            description="Attempt to extract or reverse-engineer image generation prompts",
            severity=Severity.LOW,
            category=Category.BYPASS_TECHNIQUE,
            patterns=[
                r"(?:what\s+prompt|reverse\s+engineer|extract\s+prompt|what\s+was\s+used)\s+(?:was|to|the)\s+(?:used|generate|create|make)\s+(?:this|the|that)\s+(?:image|picture|photo|artwork)",
                r"(?:reverse\s+(?:the|this|an)\s+(?:image|picture|artwork|photo)\s+(?:prompt|instruction|description))",
                r"(?:describe|analyze|examine)\s+(?:the|this)\s+(?:image|picture|metadata|EXIF)\s+(?:to\s+find|for|and)\s+(?:the\s+)?prompt",
            ],
            suggestion="Implement prompt obfuscation for image generation services.",
            cwe_id="CWE-200",
        ))


class CompletionManipulationRule(PatternRule):
    """Detects autocomplete/completion manipulation."""

    def __init__(self) -> None:
        super().__init__(RuleConfig(
            rule_id="BT-009",
            name="Completion Manipulation",
            description="Manipulation of autocomplete or completion behavior",
            severity=Severity.MEDIUM,
            category=Category.BYPASS_TECHNIQUE,
            patterns=[
                r"(?:complete\s+(?:the|this|my)\s+(?:sentence|text|code|thought|phrase))\s*[:.]",
                r"(?:autocomplete|auto-complete|fill\s+in|continue)\s+(?:the|this|my)\s+(?:text|code|sentence|pattern)",
                r"(?:finish\s+(?:this|the|my)\s+(?:sentence|paragraph|text|code|thought))",
                r"(?:continue\s+(?:writing|generating|the)\s+(?:following|this|the\s+text|pattern))",
            ],
            suggestion="Implement completion boundaries and validation.",
            cwe_id="CWE-74",
        ))


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """Engine that loads, manages, and executes all detection rules.

    Attributes:
        rules: Dictionary mapping rule IDs to rule instances.
        categories: Set of all rule categories.
    """

    def __init__(self) -> None:
        """Initialize the rule engine with all built-in rules."""
        self.rules: Dict[str, Rule] = {}
        self._load_builtin_rules()

    def _load_builtin_rules(self) -> None:
        """Load all built-in detection rules."""
        builtin_rules = [
            # Prompt Injection (9 rules)
            DirectInjectionRule(),
            IndirectInjectionRule(),
            RolePlayJailbreakRule(),
            InstructionOverrideRule(),
            DelimiterAttackRule(),
            EncodingBypassRule(),
            MultiLanguageInjectionRule(),
            ChainOfThoughtInjectionRule(),
            FewShotManipulationRule(),
            # Data Exfiltration (4 rules)
            SensitiveDataExtractionRule(),
            SystemPromptLeakageRule(),
            TrainingDataExtractionRule(),
            ConversationHistoryExtractionRule(),
            # Sensitive Information (8 rules)
            APIKeyDetectionRule(),
            PasswordDetectionRule(),
            EmailDetectionRule(),
            PhoneDetectionRule(),
            IDCardDetectionRule(),
            SecretKeyDetectionRule(),
            DatabaseConnectionDetectionRule(),
            IPDetectionRule(),
            # Harmful Content (6 rules)
            MaliciousCodeRule(),
            PhishingTemplateRule(),
            SocialEngineeringRule(),
            IllegalContentRule(),
            DoxxingRule(),
            SelfHarmRule(),
            # Prompt Leakage (4 rules)
            SystemPromptExposureRule(),
            FewShotLeakageRule(),
            ToolUsageLeakageRule(),
            ConfigurationLeakageRule(),
            # Bypass Techniques (9 rules)
            TokenSmugglingRule(),
            Base64BypassRule(),
            UnicodeBypassRule(),
            MarkdownInjectionRule(),
            XMLInjectionRule(),
            WhitespaceObfuscationRule(),
            PromptConcatenationRule(),
            ImagePromptExtractionRule(),
            CompletionManipulationRule(),
        ]

        for rule in builtin_rules:
            self.rules[rule.config.rule_id] = rule

    def get_rules_by_category(self, category: Category) -> List[Rule]:
        """Get all rules belonging to a specific category.

        Args:
            category: The category to filter by.

        Returns:
            List of rules in the specified category.
        """
        return [
            rule for rule in self.rules.values()
            if rule.config.category == category
        ]

    def get_rules_by_severity(self, severity: Severity) -> List[Rule]:
        """Get all rules with a specific severity level.

        Args:
            severity: The severity to filter by.

        Returns:
            List of rules with the specified severity.
        """
        return [
            rule for rule in self.rules.values()
            if rule.config.severity == severity
        ]

    def analyze(self, text: str, min_severity: Severity = Severity.LOW) -> List[Finding]:
        """Analyze text against all rules and return findings.

        Args:
            text: The text to analyze.
            min_severity: Minimum severity level to report.

        Returns:
            List of findings from all applicable rules.
        """
        all_findings: List[Finding] = []
        severity_order = {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3,
        }

        for rule in self.rules.values():
            if severity_order[rule.config.severity] < severity_order[min_severity]:
                continue
            findings = rule.check(text)
            all_findings.extend(findings)

        # Sort by severity (highest first) then by position
        all_findings.sort(
            key=lambda f: (severity_order[f.severity], f.position[0])
        )
        return all_findings

    def get_rule_summary(self) -> List[Dict]:
        """Get a summary of all loaded rules.

        Returns:
            List of dictionaries with rule information.
        """
        return [
            {
                "id": rule.config.rule_id,
                "name": rule.config.name,
                "category": rule.config.category.value,
                "severity": rule.config.severity.value,
                "description": rule.config.description,
                "patterns_count": len(rule.config.patterns),
            }
            for rule in self.rules.values()
        ]

    @property
    def total_rules(self) -> int:
        """Return the total number of loaded rules."""
        return len(self.rules)

    @property
    def categories(self) -> List[str]:
        """Return a list of all categories with rules."""
        cats = set(rule.config.category.value for rule in self.rules.values())
        return sorted(cats)
