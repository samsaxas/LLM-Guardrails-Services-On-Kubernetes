"""Rule-based guardrails engine.

Pure Python (standard library only) so it can be unit-tested, evaluated and
benchmarked without the web stack. The FastAPI layer in ``app/main.py`` is a
thin wrapper around :class:`GuardrailsEngine`.

Detection categories
--------------------
injection : prompt-injection / jailbreak / system-prompt-leak patterns
secret    : API keys, tokens, private-key headers, ``password=...`` style values
email     : e-mail addresses
phone     : phone numbers (international, US-style and Indian mobile formats)
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

VALID_CATEGORIES = ("injection", "secret", "email", "phone")


@dataclass(frozen=True)
class Finding:
    category: str
    rule: str
    start: int | None = None  # span in the ORIGINAL text (secrets / PII only)
    end: int | None = None


@dataclass
class CheckResult:
    decision: str  # "allow" | "block"
    findings: list[Finding]

    @property
    def reasons(self) -> list[str]:
        seen: list[str] = []
        for f in self.findings:
            r = f"{f.category}:{f.rule}"
            if r not in seen:
                seen.append(r)
        return seen


# --------------------------------------------------------------------------
# Prompt-injection rules (run on normalised, lower-cased text)
# --------------------------------------------------------------------------
_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u2060\ufeff\u00ad]")
_WS = re.compile(r"\s+")

_INJECTION_RULES: list[tuple[str, str]] = [
    ("ignore_previous_instructions",
     r"\b(?:ignore|disregard|forget|override|skip|neglect)\s+(?:all\s+|any\s+|every\s+|the\s+|your\s+|my\s+)*"
     r"(?:previous|prior|above|earlier|preceding|former|foregoing|initial|original)\s+(?:\w+\s+)?"
     r"(?:instructions?|prompts?|rules|directions|guidelines|context|commands)\b"),
    ("ignore_everything_above",
     r"\b(?:ignore|disregard|forget)\s+(?:everything|anything|all)\s+(?:above|before|you\s+(?:were\s+told|know|have\s+been\s+told))"),
    ("ignore_safety_rules",
     r"\b(?:ignore|disregard|forget|stop\s+following|do\s+not\s+follow|don't\s+follow|never\s+follow)\s+"
     r"(?:all\s+|any\s+|the\s+|these\s+|those\s+)*(?:safety|content|ethical|moral)\s+"
     r"(?:rules|guidelines|policy|policies|restrictions|protocols|filters)\b"),
    ("ignore_your_rules",
     r"\b(?:ignore|disregard|forget|stop\s+following|do\s+not\s+follow|don't\s+follow|never\s+follow)\s+"
     r"(?:all\s+|any\s+)*your\s+(?:\w+\s+)?(?:rules|guidelines|restrictions|programming|training|instructions|policies|policy)\b"),
    ("reveal_system_prompt",
     r"\b(?:reveal|show|print|repeat|output|display|leak|disclose|expose|dump|tell\s+me|give\s+me|share|write\s+out)\s+"
     r"(?:me\s+)?(?:your|the)\s+(?:system|hidden|secret|initial|original|developer|internal|full|exact)\s+"
     r"(?:prompt|instructions?|message|rules|configuration)\b"),
    ("reveal_your_instructions",
     r"\b(?:reveal|print|repeat|leak|disclose|expose|dump)\s+(?:me\s+)?your\s+(?:instructions|prompt|rules|guidelines|configuration)\b"),
    ("ask_system_prompt",
     r"\bwhat\s+(?:is|are|was|were)\s+your\s+(?:system\s+prompt|initial\s+instructions|hidden\s+instructions|original\s+instructions)\b"),
    ("repeat_text_above",
     r"\b(?:repeat|print|output|copy|reproduce)\s+(?:everything|all|the\s+(?:text|words|content|conversation))\s+(?:above|before)\b"),
    ("persona_jailbreak",
     r"\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as|behave\s+as)\s+"
     r"(?:an?\s+|the\s+|in\s+)?(?:dan|evil|unrestricted|unfiltered|uncensored|jailbroken|developer\s+mode)\b"),
    ("do_anything_now", r"\bdo\s+anything\s+now\b"),
    ("special_mode",
     r"\b(?:dan|developer|god|sudo|admin|debug|maintenance)\s+mode\s+(?:enabled|activated|on|engaged)\b"
     r"|\b(?:enable|enter|activate|switch\s+to|turn\s+on)\s+(?:a\s+)?(?:dan|developer|god|sudo|jailbreak|unrestricted|unfiltered|maintenance|debug)\s+mode\b"),
    ("answer_without_restrictions",
     r"\b(?:answer|respond|reply|behave|operate|act)\s+(?:\w+\s+){0,4}(?:without|with\s+no)\s+(?:any\s+|your\s+|the\s+|all\s+)*"
     r"(?:restrictions?|filters?|limitations?|guidelines|censorship|rules|ethical\s+\w+|safety\s+\w+)\b"),
    ("no_longer_bound", r"\bno\s+longer\s+(?:bound|restricted|limited|constrained)\s+by\b"),
    ("pretend_no_rules",
     r"\bpretend\s+(?:that\s+)?(?:you\s+)?(?:have|had|are|were)\s+(?:no|not\s+bound|free\s+of|without)\s+(?:\w+\s+)?"
     r"(?:rules|restrictions|limits|limitations|guidelines|filters)\b"
     r"|\bif\s+you\s+had\s+no\s+(?:rules|restrictions|limits|guidelines)\b"),
    ("bypass_safety",
     r"\b(?:bypass|circumvent|evade|get\s+around|disable|turn\s+off|deactivate|switch\s+off)\s+"
     r"(?:all\s+|any\s+|your\s+|the\s+|these\s+)*(?:safety|content|ethical|moderation)\s+"
     r"(?:filters?|guardrails?|moderation|safeguards?|restrictions|protections?|checks|policies|policy|programming|alignment)\b"),
    ("bypass_guardrails",
     r"\b(?:bypass|circumvent|evade|get\s+around|disable|turn\s+off|deactivate|switch\s+off)\s+"
     r"(?:all\s+|any\s+|your\s+|the\s+|these\s+)*(?:guardrails?|safeguards?|content\s+moderation|alignment)\b"),
    ("override_programming",
     r"\boverride\s+(?:your|the|all|any)\s+(?:\w+\s+)?(?:programming|safety|instructions|restrictions|rules|configuration|settings|guidelines|training|directives)\b"),
    ("new_instructions",
     r"\b(?:new|updated|revised|additional)\s+(?:system\s+)?(?:instructions?|directives?|orders)\s*(?::|follow)"
     r"|\bnew\s+system\s+(?:message|prompt)\s*:|\bsystem\s+override\b"),
    ("chat_template_tokens",
     r"<\|(?:im_start|im_end|system|endoftext|assistant|user)\|>|\[/?inst\]|<<\s*/?sys\s*>>|</?\s*system\s*>"),
    ("role_header", r"(?:^|\s)#{2,}\s*(?:system|instruction|assistant)\s*:"),
    ("exfil_markdown_image", r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]*=[^)\s]*\)"),
    ("exfil_send_data",
     r"\b(?:send|post|forward|upload|exfiltrate|transmit)\s+(?:the\s+|this\s+|all\s+|my\s+|your\s+)*"
     r"(?:conversation|chat|history|data|context|system\s+prompt|secrets?|credentials)\s+to\s+(?:https?://|\w+@)"),
    ("prompt_leak_phrase",
     r"\b(?:here\s+is|here's|this\s+is|my)\s+(?:my\s+|the\s+)?(?:system\s+prompt|hidden\s+instructions|initial\s+instructions)\s*[:\-]"),
]
_INJECTION = [(name, re.compile(pat)) for name, pat in _INJECTION_RULES]

# --------------------------------------------------------------------------
# Secret rules (run on original text)
# --------------------------------------------------------------------------
_SECRET_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("openai_or_anthropic_key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[0-9a-zA-Z]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("generic_secret_assignment", re.compile(
        r"\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token|auth[_-]?token|token|passwd|password|pwd)\b"
        r"\s*[:=]\s*[\"']?(?=[A-Za-z0-9_\-/+=!@#$%^&*]*\d)[A-Za-z0-9_\-/+=!@#$%^&*]{16,}",
        re.IGNORECASE)),
]

# --------------------------------------------------------------------------
# PII rules
# --------------------------------------------------------------------------
_EMAIL = re.compile(r"(?<![\w.+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b")
_PHONE_CANDIDATE = re.compile(r"(?<![\w.])\+?\(?\d[\d\s().\-]{7,17}\d(?![\w])")
_DATE_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}")
_IP_LIKE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_INDIAN_MOBILE = re.compile(r"^(?:91)?[6-9]\d{9}$")
_BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def normalise(text: str) -> str:
    """NFKC-fold, strip zero-width chars, collapse whitespace, lower-case."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    return _WS.sub(" ", text).strip().lower()


def _scan_injection(norm: str, prefix: str = "") -> list[Finding]:
    return [Finding("injection", prefix + name) for name, rx in _INJECTION if rx.search(norm)]


def _decode_base64_blobs(text: str) -> list[str]:
    out: list[str] = []
    for m in _BASE64_BLOB.finditer(text):
        blob = m.group(0)
        blob += "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(blob, validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in decoded)
        if decoded and printable / len(decoded) > 0.9:
            out.append(decoded)
    return out


def _phone_ok(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    if not 10 <= len(digits) <= 13:
        return False
    if _DATE_LIKE.match(raw) or _IP_LIKE.match(raw):
        return False
    if _INDIAN_MOBILE.match(digits):
        return True
    return bool(re.search(r"[\s().\-]", raw)) or raw.startswith("+")


def _find_pii_and_secrets(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for name, rx in _SECRET_RULES:
        for m in rx.finditer(text):
            findings.append(Finding("secret", name, m.start(), m.end()))
    for m in _EMAIL.finditer(text):
        findings.append(Finding("email", "email_address", m.start(), m.end()))
    for m in _PHONE_CANDIDATE.finditer(text):
        if _phone_ok(m.group(0)):
            findings.append(Finding("phone", "phone_number", m.start(), m.end()))
    return findings


class GuardrailsEngine:
    """Scan text and return an allow/block decision plus findings."""

    def __init__(self, block_categories: tuple[str, ...] | list[str] = VALID_CATEGORIES):
        unknown = set(block_categories) - set(VALID_CATEGORIES)
        if unknown:
            raise ValueError(f"unknown categories: {sorted(unknown)}")
        self.block_categories = frozenset(block_categories)

    def check(self, text: str) -> CheckResult:
        norm = normalise(text)
        findings = _scan_injection(norm)
        for decoded in _decode_base64_blobs(text):
            findings += _scan_injection(normalise(decoded), prefix="encoded:")
        findings += _find_pii_and_secrets(text)
        blocked = any(f.category in self.block_categories for f in findings)
        return CheckResult("block" if blocked else "allow", findings)

    @staticmethod
    def redact(text: str, findings: list[Finding]) -> str:
        """Mask secret/PII spans. Injection findings have no span and are left as-is."""
        spans = sorted((f for f in findings if f.start is not None), key=lambda f: (f.start, -f.end))
        out, cursor = [], 0
        for f in spans:
            if f.start < cursor:  # overlaps a span already masked
                continue
            out.append(text[cursor:f.start])
            out.append(f"[REDACTED:{f.category}]")
            cursor = f.end
        out.append(text[cursor:])
        return "".join(out)
