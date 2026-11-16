"""Tests for passcheck.py. No network, no real passwords — just the math."""

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from passcheck import (charset_size, crack_estimates, deleet, entropy_bits,
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


def test_short_password_suggests_more_length():
    # short passwords used to get the issue ("too short") with no
    # suggestion attached — every other issue class points at a fix
    common = load_common_passwords()
    result = score_password("ab12", common)
    assert any("12 characters" in s for s in result["suggestions"])
    result = score_password("Ab3#xY9zQw", common)
    assert any("short side" in i for i in result["issues"])
    assert any("12 characters" in s for s in result["suggestions"])


def test_long_password_gets_no_length_suggestion():
    common = load_common_passwords()
    result = score_password("xQ9#mZ2!vLp4@wT", common)
    assert not any("12 characters" in s for s in result["suggestions"])


def test_empty_password():
    result = score_password("", set())
    assert result["score"] == 0
    assert result["label"] == "empty"


def test_variety_suggestion():
    common = load_common_passwords()
    result = score_password("alllowercaseletters", common)
    assert any("variety" in i for i in result["issues"])


def test_deleet_normalizes_leetspeak():
    assert deleet("5up3rm4n") == "superman"
    assert deleet("P455W0RD") == "password"
    assert deleet("plain") == "plain"


def test_leetspeak_variant_of_common_password_detected():
    common = load_common_passwords()
    assert "superman" in common
    assert "5up3rm4n" not in common  # catches it only via normalization
    result = score_password("5up3rm4n", common)
    assert result["score"] <= 10
    assert any("leetspeak" in i for i in result["issues"])


def test_random_password_not_flagged_as_leetspeak():
    common = load_common_passwords()
    result = score_password("xQ9#mZ2!vLp4@wT", common)
    assert not any("leetspeak" in i for i in result["issues"])
    assert result["label"] == "strong"


def test_common_password_with_extras_still_flagged():
    # "password123!" used to score 64 ("good"): the bare word plus a
    # sequence and a symbol is still a leaked password at heart.
    common = load_common_passwords()
    result = score_password("password123!", common)
    assert result["score"] <= 25
    assert result["label"] == "weak"
    assert any("password" in i and "contains" in i for i in result["issues"])


def test_embedded_common_word_flagged():
    common = load_common_passwords()
    assert "dragon" in common
    result = score_password("dragonfly99!", common)
    assert result["score"] <= 25
    assert any("'dragon'" in i for i in result["issues"])


def test_leetspeak_embedded_common_word_flagged():
    # leet form of the word, with extras: "5up3rm4n" + "99!"
    common = load_common_passwords()
    result = score_password("5up3rm4n99!", common)
    assert result["score"] <= 25
    assert any("'superman'" in i for i in result["issues"])


def test_short_common_words_do_not_false_positive():
    # short list entries ("solo", "007") must not flag unrelated passwords
    common = load_common_passwords()
    result = score_password("xQ9#mZ2!vLp4@wT", common)
    assert result["label"] == "strong"
    assert not any("contains" in i for i in result["issues"])


def test_human_time_units():
    assert human_time(0.001) == "instantly"
    assert "second" in human_time(45)
    assert "minute" in human_time(120)
    assert "hour" in human_time(7200)
    assert "centur" in human_time(10**12)
    # regression: one century used to render as "~1 centurie"
    assert human_time(100 * 365.25 * 86400) == "~1 century"
    assert human_time(300 * 365.25 * 86400) == "~3 centuries"


def test_crack_estimates_labeled():
    est = crack_estimates("aA1!bB2@cC3#")
    assert len(est) == 2
    # offline GPU should always be faster than throttled online
    assert est["offline (fast hash, one GPU)"] != est["online (throttled login)"]


def test_crack_estimates_very_long_password():
    # a 200-char mixed password used to raise OverflowError: the
    # keyspace (95**200) doesn't fit in a float
    est = crack_estimates("Aa1!" * 50)
    assert len(est) == 2
    for when in est.values():
        assert "10^" in when and "centuries" in when


def test_human_time_huge_value_uses_powers_of_ten():
    # a 200-char lowercase password fits in a float but used to render
    # as a 280-digit count of centuries
    when = human_time(10.0 ** 300)
    assert "10^" in when and "centuries" in when
    # ordinary huge-but-sane values still render as exact counts
    assert human_time(10**12).endswith("centuries")
