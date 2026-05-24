# Contributing to rai-guard

Thank you for helping make AI systems safer and more compliant. Contributions of all kinds are welcome — bug fixes, new checks, documentation, and compliance mapping improvements.

---

## Getting Started

```bash
git clone https://github.com/ashish993/rai-guard
cd rai-guard
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -q          # all tests must pass before submitting
```

---

## Development Workflow

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/my-improvement
   ```
2. Make your changes.
3. Run the full test suite: `pytest tests/ -q`
4. Run the linter: `ruff check raiguard/ tests/`
5. Open a Pull Request against `main`.

---

## Adding a New Check

All checks live in `raiguard/checks/`. Each check:

- Inherits from `raiguard.checks.base.BaseCheck`
- Implements `check_input(self, text, context=None) -> CheckResult`
- Implements `check_output(self, text, prompt="", context=None) -> CheckResult`
- Sets `name`, `owasp_refs`, and `eu_ai_act_refs` class attributes
- Is registered in `raiguard/instrument.py` (`_ALL_CHECKS` list and `__init__`)

Example skeleton:

```python
from raiguard.checks.base import BaseCheck, CheckResult, Severity

class MyCheck(BaseCheck):
    name = "my_check"
    owasp_refs = ["LLM01"]
    eu_ai_act_refs = ["Article 9"]

    def check_input(self, text, context=None):
        # return self._make_result(passed, score, severity, ...)
        ...

    def check_output(self, text, prompt="", context=None):
        ...
```

Add at least one test in `tests/` that covers:
- A true-positive (check fires when it should)
- A true-negative (check does not fire on benign text)

---

## Improving Compliance Mappings

Compliance mapping lives in `raiguard/compliance/`. Each module maps `CheckResult` objects to a compliance framework:

- `owasp_llm.py` — OWASP LLM Top 10
- `eu_ai_act.py` — EU AI Act
- `nist_ai_rmf.py` — NIST AI RMF 1.0

When adding or modifying mappings, cite the relevant article/category in a comment.

---

## Commit Style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new check for data poisoning (LLM03)
fix: narrow phone_intl regex to require explicit country code
docs: update README install instructions
chore: bump fastapi to 0.115
```

---

## Code Style

- **Python 3.10+** with `from __future__ import annotations`
- Linted with `ruff` (no other formatter required)
- Type annotations on all public functions
- No external API calls from within checks — all logic must run locally

---

## Reporting Bugs

Please open a [GitHub Issue](https://github.com/ashish993/rai-guard/issues) with:
- Python version and OS
- Minimal reproducing example
- Expected vs. actual behaviour

For **security vulnerabilities**, follow the [Security Policy](SECURITY.md) instead.

---

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
