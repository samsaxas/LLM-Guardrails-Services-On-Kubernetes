"""Generate fake-but-realistic credentials at runtime.

Test data never contains literal key-shaped strings, so the repo cannot trip
GitHub push protection / secret scanners, and nobody mistakes a fixture for a leak.
"""
import random
import re
import string

_ALNUM = string.ascii_letters + string.digits
_UPPER_DIGITS = string.ascii_uppercase + string.digits


def _r(rng: random.Random, n: int, alphabet: str = _ALNUM) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def make_fakes(seed: int = 7) -> dict[str, str]:
    rng = random.Random(seed)
    return {
        "OPENAI_KEY": "sk-" + _r(rng, 48),
        "ANTHROPIC_KEY": "sk-ant-api03-" + _r(rng, 40, _ALNUM + "-_"),
        "AWS_KEY": "AKIA" + _r(rng, 16, _UPPER_DIGITS),
        "GITHUB_TOKEN": "ghp_" + _r(rng, 36),
        "JWT": "eyJ" + _r(rng, 20) + "." + "eyJ" + _r(rng, 30) + "." + _r(rng, 30),
        "STRIPE_KEY": "sk_test_" + _r(rng, 24),
        "GOOGLE_KEY": "AIza" + _r(rng, 35, _ALNUM + "-_"),
        "SLACK_TOKEN": "xoxb-" + _r(rng, 12, string.digits) + "-" + _r(rng, 24),
        "HEX32": "a1" + _r(rng, 30, "0123456789abcdef"),
        "PEM_HEADER": "-----BEGIN " + "RSA PRIVATE KEY-----",
        "OPENSSH_HEADER": "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
    }


def expand(text: str, fakes: dict[str, str] | None = None) -> str:
    fakes = fakes or make_fakes()
    return re.sub(r"\{\{([A-Z0-9_]+)\}\}", lambda m: fakes[m.group(1)], text)
