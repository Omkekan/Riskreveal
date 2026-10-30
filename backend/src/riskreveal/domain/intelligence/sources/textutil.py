"""Small helpers for cleaning strings that come from untrusted feeds."""

from __future__ import annotations


def clean_text(value: object, max_len: int) -> str | None:
    """Return ``value`` as a stripped string clipped to ``max_len``, or ``None``.

    * Non-strings and empty strings give ``None``.
    * NUL bytes are removed: PostgreSQL refuses them in text columns, so one
      hostile record could otherwise make a whole import fail.
    * Over-long values are clipped, never rejected, so an oversized field in one
      record cannot break a column limit.
    """
    if not isinstance(value, str):
        return None
    cleaned = value.replace("\x00", "").strip()
    if not cleaned:
        return None
    return cleaned[:max_len]
