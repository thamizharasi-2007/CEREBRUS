from __future__ import annotations

import base64
import json
import re
import unicodedata
from typing import Any

from cerebrus import detect_injection


# ============================================================
# UNICODE NORMALIZATION
# ============================================================

_ZERO_WIDTH = re.compile(
    r"[\u200b-\u200f\u2060\ufeff]"
)


def normalize_untrusted_text(value: str) -> str:
    """
    Normalize Unicode before security inspection.

    This helps detect simple Unicode / zero-width
    obfuscation attempts.
    """

    value = unicodedata.normalize(
        "NFKC",
        str(value)
    )

    value = _ZERO_WIDTH.sub(
        "",
        value
    )

    return value


# ============================================================
# BASE64 DETECTION
# ============================================================

_B64 = re.compile(
    r"(?<![A-Za-z0-9+/])"
    r"([A-Za-z0-9+/]{40,}={0,2})"
    r"(?![A-Za-z0-9+/])"
)


def _decode_base64_candidates(
    text: str
) -> list[str]:

    decoded = []

    for candidate in _B64.findall(text):

        try:

            raw = base64.b64decode(
                candidate,
                validate=True
            )

            if 8 <= len(raw) <= 10000:

                decoded_text = raw.decode(
                    "utf-8",
                    errors="ignore"
                )

                if decoded_text.strip():

                    decoded.append(
                        decoded_text
                    )

        except Exception:
            continue

    return decoded


# ============================================================
# CONTENT INSPECTION
# ============================================================

def inspect_untrusted_content(
    content: Any
) -> dict[str, Any]:

    text = normalize_untrusted_text(
        str(content)
    )

    # Existing Cerebrus detector
    direct_result = detect_injection(
        text
    )

    decoded_hits = []

    # Check possible Base64 payloads
    for decoded in _decode_base64_candidates(
        text
    ):

        result = detect_injection(
            normalize_untrusted_text(
                decoded
            )
        )

        if result["detected"]:
            decoded_hits.append(
                result
            )

    detected = bool(
        direct_result["detected"]
        or decoded_hits
    )

    categories = list(
        direct_result.get(
            "categories",
            []
        )
    )

    matches = dict(
        direct_result.get(
            "matches",
            {}
        )
    )

    if decoded_hits:

        if "obfuscation" not in categories:
            categories.append(
                "obfuscation"
            )

        matches["obfuscation"] = [
            "base64-encoded malicious instruction"
        ]

    return {

        "detected": detected,

        "status": (
            "INJECTION"
            if detected
            else
            "CLEAN"
        ),

        "categories": categories,

        "matches": matches,

        "reason": (
            "Untrusted content contains "
            "instruction-like content that is "
            "not authorized by the original user task."
            if detected
            else
            "No known malicious instruction pattern detected."
        )
    }


# ============================================================
# MALICIOUS INSTRUCTION SANITIZATION
# ============================================================

_INJECTION_LINE = re.compile(
    r"(?im)^\s*(?:"
    r"ignore\s+(?:all\s+|any\s+)?"
    r"(?:previous|prior|earlier)\s+instructions"
    r"|disregard\s+(?:all\s+|any\s+)?"
    r"(?:previous|prior|earlier)\s+instructions"
    r"|override\s+(?:your|the)\s+instructions?"
    r"|forget\s+(?:your|the)\s+instructions?"
    r"|system\s+instruction\s*:"
    r"|new\s+instructions?\s*:"
    r"|reveal\s+(?:your\s+)?"
    r"(?:system\s+prompt|instructions)"
    r"|send\s+(?:this|the|all)\s+"
    r"(?:information|data|contents?)"
    r"|upload\s+(?:this|the|all)\s+"
    r"(?:information|data|contents?)"
    r"|read\s+(?:the\s+)?"
    r"(?:credentials?|passwords?|secrets?|private|confidential)"
    r"|access\s+(?:the\s+)?"
    r"(?:credentials?|passwords?|secrets?|private|confidential)"
    r").*$"
)


def _sanitize_text(
    text: str
) -> tuple[str, bool]:

    normalized = normalize_untrusted_text(
        text
    )

    changed = False

    def replace_instruction(
        match: re.Match[str]
    ) -> str:

        nonlocal changed

        changed = True

        return (
            "[CEREBRUS BLOCKED "
            "UNTRUSTED INSTRUCTION]"
        )

    sanitized = _INJECTION_LINE.sub(
        replace_instruction,
        normalized
    )

    # --------------------------------------------------------
    # Remove encoded malicious instructions
    # --------------------------------------------------------

    for candidate in _B64.findall(
        sanitized
    ):

        try:

            raw = base64.b64decode(
                candidate,
                validate=True
            )

            decoded = raw.decode(
                "utf-8",
                errors="ignore"
            )

            if detect_injection(
                decoded
            )["detected"]:

                sanitized = sanitized.replace(
                    candidate,
                    "[CEREBRUS BLOCKED "
                    "OBFUSCATED INSTRUCTION]"
                )

                changed = True

        except Exception:
            continue

    return sanitized, changed


# ============================================================
# RECURSIVE SANITIZATION
# ============================================================

def sanitize_for_llm(
    value: Any
) -> tuple[Any, bool]:

    # String
    if isinstance(value, str):

        return _sanitize_text(
            value
        )

    # List
    if isinstance(value, list):

        output = []

        changed = False

        for item in value:

            safe_item, item_changed = (
                sanitize_for_llm(item)
            )

            output.append(
                safe_item
            )

            changed = (
                changed
                or item_changed
            )

        return output, changed

    # Dictionary
    if isinstance(value, dict):

        output = {}

        changed = False

        for key, item in value.items():

            safe_item, item_changed = (
                sanitize_for_llm(item)
            )

            output[key] = safe_item

            changed = (
                changed
                or item_changed
            )

        return output, changed

    # Number / boolean / None
    return value, False


# ============================================================
# BUILD SAFE TOOL RESULT
# ============================================================

def build_inspected_result(
    action: dict[str, Any],
    result: Any
) -> dict[str, Any]:

    safe_content, sanitized = (
        sanitize_for_llm(result)
    )

    inspection = (
        inspect_untrusted_content(result)
    )

    return {

        "source":
            action["tool"],

        "trusted":
            False,

        "injection_detected":
            inspection["detected"],

        "injection_categories":
            inspection["categories"],

        "content_sanitized":
            sanitized,

        # IMPORTANT:
        # Only this content reaches the LLM.
        "content":
            safe_content,

        "security_note": (
            "Untrusted instruction content "
            "was removed before the LLM "
            "received this tool result."
            if sanitized
            else
            "Tool result was treated as data, "
            "not as authority."
        )
    }


# ============================================================
# ACTION FINGERPRINT
# ============================================================

def action_fingerprint(
    action: dict[str, Any]
) -> str:

    payload = {

        "tool":
            action.get("tool"),

        "operation":
            action.get("operation"),

        "parameters":
            action.get(
                "parameters",
                {}
            )
    }

    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False
    )