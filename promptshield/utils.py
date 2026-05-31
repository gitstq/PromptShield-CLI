"""Utility functions for text processing, file I/O, and language detection."""

import os
import re
from typing import List, Optional, Tuple


def read_file(filepath: str, encoding: str = "utf-8") -> str:
    """Read file content with fallback encoding support.

    Args:
        filepath: Path to the file to read.
        encoding: Primary encoding to use.

    Returns:
        The file content as a string.

    Raises:
        FileNotFoundError: If the file does not exist.
        IOError: If the file cannot be read.
    """
    try:
        with open(filepath, "r", encoding=encoding) as f:
            return f.read()
    except UnicodeDecodeError:
        # Fallback to latin-1 for files with mixed encoding
        with open(filepath, "r", encoding="latin-1") as f:
            return f.read()


def truncate_text(text: str, max_length: int = 200, suffix: str = "...") -> str:
    """Truncate text to a maximum length with a suffix indicator.

    Args:
        text: The text to truncate.
        max_length: Maximum length before truncation.
        suffix: Suffix to append when truncated.

    Returns:
        The truncated text.
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def normalize_whitespace(text: str) -> str:
    """Normalize whitespace in text by collapsing multiple spaces.

    Args:
        text: The text to normalize.

    Returns:
        Text with normalized whitespace.
    """
    return re.sub(r"\s+", " ", text).strip()


def extract_code_blocks(text: str) -> List[str]:
    """Extract code blocks from markdown-formatted text.

    Args:
        text: The markdown text to extract code blocks from.

    Returns:
        List of code block contents.
    """
    pattern = r"```[\w]*\n(.*?)```"
    return re.findall(pattern, text, re.DOTALL)


def detect_language(text: str) -> str:
    """Detect the primary language of the given text (simplified).

    Uses a heuristic based on character ranges to detect Chinese vs English.

    Args:
        text: The text to analyze.

    Returns:
        'zh' for Chinese, 'en' for English, or 'mixed' for mixed content.
    """
    if not text:
        return "en"

    chinese_chars = len(re.findall(r"[\u4e00-\u9fff]", text))
    total_chars = len(re.findall(r"\S", text))

    if total_chars == 0:
        return "en"

    chinese_ratio = chinese_chars / total_chars
    if chinese_ratio > 0.3:
        return "zh"
    elif chinese_ratio > 0.05:
        return "mixed"
    else:
        return "en"


def get_severity_color(severity: str) -> str:
    """Return the Rich-compatible color name for a severity level.

    Args:
        severity: The severity level string.

    Returns:
        Rich color name string.
    """
    color_map = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red",
    }
    return color_map.get(severity.lower(), "white")


def get_category_color(category: str) -> str:
    """Return the Rich-compatible color name for a category.

    Args:
        category: The category string.

    Returns:
        Rich color name string.
    """
    color_map = {
        "prompt_injection": "bold red",
        "data_exfiltration": "bold yellow",
        "sensitive_info": "bold magenta",
        "harmful_content": "bold red",
        "prompt_leakage": "bold cyan",
        "bypass_technique": "bold blue",
    }
    return color_map.get(category.lower(), "white")


def find_matching_lines(text: str, pattern: str) -> List[Tuple[int, str]]:
    """Find all lines in text that match a given regex pattern.

    Args:
        text: The text to search through.
        pattern: The regex pattern to match.

    Returns:
        List of (line_number, line_content) tuples.
    """
    matches: List[Tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if re.search(pattern, line):
            matches.append((i, line.strip()))
    return matches


def is_valid_file(filepath: str) -> bool:
    """Check if a file exists and is a regular file.

    Args:
        filepath: Path to the file to check.

    Returns:
        True if the file exists and is a regular file.
    """
    return os.path.isfile(filepath)


def is_valid_directory(dirpath: str) -> bool:
    """Check if a directory exists and is accessible.

    Args:
        dirpath: Path to the directory to check.

    Returns:
        True if the directory exists and is accessible.
    """
    return os.path.isdir(dirpath)


def get_file_extension(filepath: str) -> str:
    """Get the lowercase file extension without the leading dot.

    Args:
        filepath: Path to the file.

    Returns:
        The lowercase file extension.
    """
    _, ext = os.path.splitext(filepath)
    return ext.lower().lstrip(".")


SUPPORTED_EXTENSIONS = {
    "txt", "md", "py", "js", "ts", "json", "yaml", "yml",
    "toml", "cfg", "ini", "env", "sh", "bash", "zsh",
    "html", "htm", "xml", "csv", "log", "rst", "tex",
}


def is_scannable_file(filepath: str) -> bool:
    """Check if a file has a scannable extension.

    Args:
        filepath: Path to the file.

    Returns:
        True if the file extension is in the supported set.
    """
    ext = get_file_extension(filepath)
    return ext in SUPPORTED_EXTENSIONS or ext == ""
