"""Tests for passcheck.py. No network, no real passwords — just the math."""

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from passcheck import (charset_size, crack_estimates, entropy_bits,
                       human_time, load_common_passwords, score_password)


def test_charset_size_lowercase_only():
    assert charset_size("abcd") == 26


def test_charset_size_all_classes():
    assert charset_size("aA1!") == 26 + 26 + 10 + 33


def test_entropy_math():
    # 4 lowercase chars: 4 * log2(26)
    expected = 4 * math.log2(26)
    assert entropy_bits("abcd") == expected


def test_entropy_empty():
    assert entropy_bits("") == 0.0


def test_common_password_detected():
    common = load_common_passwords()
    assert "password" in common
    assert "123456" in common
    result = score_password("password", common)
    assert result["score"] <= 10
    assert any("commonly used" in i for i in result["issues"])


def test_strong_password_scores_high():
    common = load_common_passwords()
    result = score_password("xQ9#mZ2!vLp4@wT", common)
    assert result["score"] >= 80
    assert result["label"] == "strong"


def test_short_password_flagged():
    common = load_common_passwords()
    result = score_password("ab12", common)
    assert result["label"] == "weak"
    assert any("short" in i for i in result["issues"])


def test_empty_password():
    result = score_password("", set())
    assert result["score"] == 0
    assert result["label"] == "empty"


def test_variety_suggestion():
    common = load_common_passwords()
    result = score_password("alllowercaseletters", common)
    assert any("variety" in i for i in result["issues"])


def test_human_time_units():
    assert human_time(0.001) == "instantly"
    assert "second" in human_time(45)
    assert "minute" in human_time(120)
    assert "hour" in human_time(7200)
    assert "centur" in human_time(10**12)


def test_crack_estimates_labeled():
    est = crack_estimates("aA1!bB2@cC3#")
    assert len(est) == 2
    # offline GPU should always be faster than throttled online
    assert est["offline (fast hash, one GPU)"] != est["online (throttled login)"]
