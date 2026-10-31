"""Grade connection speed from a latency measurement."""
from . import config


def grade(ms):
    """Return (label, is_bad). is_bad=True means drop it from ready lists."""
    if ms is None:
        return "-", True
    if ms <= config.FAST_MAX:
        return "FAST", False
    if ms <= config.MEDIUM_MAX:
        return "MEDIUM", False
    if ms <= config.SLOW_MAX:
        return "SLOW", False
    return "BAD", True
