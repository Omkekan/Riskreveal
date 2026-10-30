"""Threat-intelligence feed sources (parsers and downloaders).

Each source module is split so the risky part is small and testable: a pure
parser (no network, no database) and, separately, ``fetch.py`` for downloads.
"""
