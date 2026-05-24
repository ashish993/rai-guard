"""
rai-guard: Runtime Responsible AI compliance evidence layer.

Usage:
    from raiguard import instrument, AIGuard
    from raiguard.middleware import AIGuardMiddleware
"""

from raiguard.instrument import instrument, AIGuard
from raiguard.checks.base import CheckResult, Severity

__all__ = ["instrument", "AIGuard", "CheckResult", "Severity"]
__version__ = "0.1.0"
