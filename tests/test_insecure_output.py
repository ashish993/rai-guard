"""Tests for insecure output check."""
from raiguard.checks.insecure_output import InsecureOutputCheck


def test_clean_output_passes():
    check = InsecureOutputCheck()
    result = check.check_output("The answer is 42.")
    assert result.passed


def test_sql_injection_detected():
    check = InsecureOutputCheck()
    result = check.check_output("Run: SELECT * FROM users WHERE 1=1; DROP TABLE users;")
    assert not result.passed


def test_xss_detected():
    check = InsecureOutputCheck()
    result = check.check_output("Use this code: <script>alert(document.cookie)</script>")
    assert not result.passed


def test_shell_injection_detected():
    check = InsecureOutputCheck()
    result = check.check_output("Run: ls -la; rm -rf /")
    assert not result.passed
