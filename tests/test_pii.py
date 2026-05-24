"""Tests for PII detection check."""
from raiguard.checks.pii import PIICheck


def test_clean_text_passes():
    check = PIICheck()
    result = check.check_input("Explain the concept of machine learning.")
    assert result.passed


def test_ssn_detected():
    check = PIICheck()
    result = check.check_input("My SSN is 123-45-6789")
    assert not result.passed


def test_credit_card_detected():
    check = PIICheck()
    result = check.check_input("Card number: 4111 1111 1111 1111")
    assert not result.passed


def test_email_detected():
    check = PIICheck()
    result = check.check_input("Contact me at john.doe@example.com")
    assert not result.passed


def test_api_key_detected():
    check = PIICheck()
    result = check.check_input("sk-abc1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH")
    assert not result.passed
