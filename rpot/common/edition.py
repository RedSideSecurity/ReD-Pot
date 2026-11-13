"""ReD-Pot edition constants (Community Edition).

The decoy cap is also enforced by the installer constant and the console SQL trigger;
keep MAX_DECOYS equal in all three places.
"""

EDITION = "community"
MAX_DECOYS = 3
UPGRADE_URL = "https://redsidesecurity.com"


class LimitError(ValueError):
    """Raised when an action would exceed the Community Edition decoy cap."""


def limit_message(used: int) -> str:
    """User-facing text shown wherever the decoy cap blocks an action."""
    return (f"ReD-Pot Community Edition supports up to {MAX_DECOYS} decoys in total "
            f"(decoys on this manager plus remote sensors); this install uses {used}. "
            "Remove a decoy, revoke a remote sensor or cancel a pending join first — "
            f"or ask RedSide Security about ReD-Pot Enterprise: {UPGRADE_URL}")
