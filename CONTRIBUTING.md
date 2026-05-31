# Contributing to PromptShield-CLI

Thank you for your interest in contributing to PromptShield-CLI! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive in all interactions
- Provide constructive feedback
- Focus on the technical merits of contributions

## How to Contribute

### Reporting Issues

1. Check existing issues to avoid duplicates
2. Create a new issue with a clear title and description
3. Include steps to reproduce, expected behavior, and actual behavior
4. Attach relevant logs or screenshots

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Make your changes with clear commit messages following [Conventional Commits](https://www.conventionalcommits.org/)
4. Write tests for new functionality
5. Ensure all tests pass (`pytest tests/ -v`)
6. Submit your PR with a description of changes

### Commit Message Format

```
feat: add new detection rule for XYZ injection
fix: resolve false positive in API key detection
docs: update README with new usage examples
test: add test cases for bypass techniques
refactor: improve rule engine performance
```

### Adding New Detection Rules

1. Create a new rule class in `promptshield/rules.py`
2. Assign a unique rule ID (e.g., `PI-010`)
3. Set appropriate severity level and category
4. Add CWE mapping if applicable
5. Write corresponding test cases in `tests/test_rules.py`
6. Update the rules count in documentation

### Development Setup

```bash
git clone https://github.com/gitstq/PromptShield-CLI.git
cd PromptShield-CLI
pip install -e ".[dev]"
pytest tests/ -v
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
