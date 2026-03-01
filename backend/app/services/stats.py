"""Shared statistical helpers — percentile computation and period parsing.

Used by metrics, exposures, and reports routers. SQLite-compatible
(no percentile_cont function needed).
"""

from typing import Optional


def percentile(sorted_values: list[float], pct: float) -> Optional[float]:
    """Compute percentile from sorted list using linear interpolation."""
    if not sorted_values:
        return None
    n = len(sorted_values)
    k = (n - 1) * pct
    f = int(k)
    c = f + 1
    if c >= n:
        return round(sorted_values[f], 2)
    return round(sorted_values[f] + (k - f) * (sorted_values[c] - sorted_values[f]), 2)


def parse_period(period: str) -> int:
    """Parse period string like '30d' into days. Default 30."""
    period = period.strip().lower()
    if period.endswith("d"):
        try:
            return int(period[:-1])
        except ValueError:
            return 30
    return 30
