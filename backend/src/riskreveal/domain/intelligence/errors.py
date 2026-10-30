"""Errors raised by the threat-intelligence feed code.

Messages are safe to log and to show to the operator running the CLI. They
never contain raw feed content (feeds come from the internet: treat them as
untrusted data) and never contain credentials or database URLs.
"""

from __future__ import annotations


class FeedError(Exception):
    """Base class for every feed problem."""


class FeedFetchError(FeedError):
    """The feed could not be obtained (network, HTTP status, size, local file)."""


class FeedParseError(FeedError):
    """The feed was obtained but is malformed, unsafe, too big or mostly invalid."""
