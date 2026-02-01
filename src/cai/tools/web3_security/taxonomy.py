"""Taxonomy mapping helpers (SmartBugs Curated / DASP)."""

from __future__ import annotations

from typing import Dict


DASP_MAP: Dict[str, str] = {
    "reentrancy": "Reentrancy",
    "access_control": "Access Control",
    "upgradeability": "Access Control",
    "arithmetic": "Arithmetic",
    "integer_overflow": "Arithmetic",
    "integer_underflow": "Arithmetic",
    "unchecked_return": "Unchecked Low Level Calls",
    "external_call": "Unchecked Low Level Calls",
    "unchecked_lowlevel": "Unchecked Low Level Calls",
    "dos": "Denial of Service",
    "denial_of_service": "Denial of Service",
    "randomness": "Bad Randomness",
    "oracle": "Bad Randomness",
    "mev": "Front Running",
    "front_running": "Front Running",
    "timestamp": "Time Manipulation",
    "time": "Time Manipulation",
    "short_address": "Short Address",
}


def map_to_dasp(category: str) -> str:
    if not category:
        return "Unknown"
    normalized = category.lower().replace("-", "_").replace(" ", "_")
    return DASP_MAP.get(normalized, "Unknown")
