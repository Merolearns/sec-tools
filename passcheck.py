#!/usr/bin/env python3
"""passcheck: password strength analyzer. 100% local, nothing leaves your machine."""

import argparse
import getpass
import math
import os
import sys

COMMON_PASSWORDS_FILE = os.path.join(os.path.dirname(__file__),
                                      "common_passwords.txt")

# rough guess rates for crack-time estimates — labeled as rough on purpose
GUESS_RATES = {
    "online (throttled login)": 10,
    "offline (fast hash, one GPU)": 10_000_000_000,
}

SYMBOLS = set("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ")


def load_common_passwords():
    try:
        with open(COMMON_PASSWORDS_FILE) as f:
            return {line.strip().lower() for line in f if line.strip()}
    except OSError:
        return set()  # list missing: skip the check, don't crash


def charset_size(password):
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(c in SYMBOLS for c in password):
        size += 33
    # anything else (unicode etc.) — be generous
    if any(not (c.islower() or c.isupper() or c.isdigit() or c in SYMBOLS)
           for c in password):
        size += 100
    return size


def entropy_bits(password):
    """Shannon-style estimate: length * log2(charset). Upper bound, really."""
    size = charset_size(password)
    if size == 0:
        return 0.0
    return len(password) * math.log2(size)


def human_time(seconds):
    if seconds < 1:
        return "instantly"
    units = [("centuries", 100 * 365.25 * 86400), ("years", 365.25 * 86400),
             ("days", 86400), ("hours", 3600), ("minutes", 60),
             ("seconds", 1)]
    for name, length in units:
        if seconds >= length:
            value = seconds / length
            # pluralize sensibly for 1
            label = name[:-1] if abs(value - 1) < 0.05 else name
            return f"~{value:,.0f} {label}"
    return "instantly"


def score_password(password, common):
    issues = []
    suggestions = []

    if not password:
        return {"score": 0, "label": "empty", "entropy": 0.0,
                "issues": ["password is empty"],
                "suggestions": ["use a password manager and generate one"]}

    lowered = password.lower()
    if lowered in common:
        issues.append("this is one of the most commonly used passwords — "
                      "attackers try it first")
        suggestions.append("pick something that isn't on every leaked list")

    length = len(password)
    if length < 8:
        issues.append(f"too short ({length} chars)")
    elif length < 12:
        issues.append("on the short side")

    variety = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(c in SYMBOLS for c in password),
    ])
    if variety < 3:
        issues.append("low character variety")
        missing = []
        if not any(c.islower() for c in password):
            missing.append("lowercase")
        if not any(c.isupper() for c in password):
            missing.append("uppercase")
        if not any(c.isdigit() for c in password):
            missing.append("digits")
        if not any(c in SYMBOLS for c in password):
            missing.append("symbols")
        suggestions.append("mix in " + ", ".join(missing))

    # naive repetition check
    if len(set(lowered)) < length / 2:
        issues.append("lots of repeated characters")

    # keyboard-walk-ish sequences
    seqs = ["123", "abc", "qwe", "asd", "zxc", "987", "321"]
    if any(s in lowered for s in seqs):
        issues.append("contains a common sequence")
        suggestions.append("avoid keyboard patterns and counting sequences")

    if length >= 12 and not issues:
        suggestions.append("looks solid — a password manager + MFA is still "
                           "the real win")

    entropy = entropy_bits(password)

    # score out of 100, deliberately simple
    score = 0
    score += min(length, 20) * 2.5            # up to 50 for length
    score += variety * 7.5                    # up to 30 for variety
    score += min(entropy / 128 * 20, 20)      # up to 20 for entropy
    if lowered in common:
        score = min(score, 10)
    score = max(0, min(100, round(score)))

    if score < 30:
        label = "weak"
    elif score < 60:
        label = "fair"
    elif score < 80:
        label = "good"
    else:
        label = "strong"

    return {"score": score, "label": label, "entropy": entropy,
            "issues": issues, "suggestions": suggestions}


def crack_estimates(password):
    """Rough brute-force times. Assumes random password — real attackers
    are smarter (dictionaries, patterns), so treat these as optimistic."""
    size = charset_size(password)
    combos = size ** len(password) if size else 0
    out = {}
    for name, rate in GUESS_RATES.items():
        # average case: half the keyspace
        out[name] = human_time(combos / 2 / rate) if combos else "instantly"
    return out


def main():
    parser = argparse.ArgumentParser(
        description="passcheck: analyze password strength locally "
                    "(nothing is sent anywhere)")
    parser.add_argument("--password",
                        help="password to check (visible in shell history — "
                             "prefer the interactive prompt)")
    args = parser.parse_args()

    if args.password is not None:
        password = args.password
    else:
        try:
            password = getpass.getpass("password to check: ")
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(1)

    common = load_common_passwords()
    result = score_password(password, common)

    print(f"\nscore: {result['score']}/100 ({result['label']})")
    print(f"entropy: ~{result['entropy']:.1f} bits (rough estimate)")
    print("\nestimated brute-force time (rough, assumes random password):")
    for name, when in crack_estimates(password).items():
        print(f"  {name}: {when}")
    if result["issues"]:
        print("\nissues:")
        for issue in result["issues"]:
            print(f"  - {issue}")
    if result["suggestions"]:
        print("\nsuggestions:")
        for s in result["suggestions"]:
            print(f"  - {s}")
    print()


if __name__ == "__main__":
    main()
