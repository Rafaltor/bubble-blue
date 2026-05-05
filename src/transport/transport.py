"""
Backward-compatible import path.

The project layout now uses `src/transport/l2cap.py` as the canonical module.
"""

from .l2cap import L2CAPTransport  # noqa: F401

