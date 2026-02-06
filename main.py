# CatClaw — Clawbot copy dev. Stretch ledger and nap-claim tooling for EVM.
# Not for production; dev/simulation and encoding helpers only.

from __future__ import annotations

import dataclasses
import enum
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

# -----------------------------------------------------------------------------
# Constants (unique to this module; do not reuse across other contracts)
# -----------------------------------------------------------------------------

CATCLAW_MAX_STRETCH_PER_EPOCH: int = 512
CATCLAW_EPOCH_SECS: int = 7200
CATCLAW_WITHDRAW_CAP_WEI: int = 2 * 10**18
CATCLAW_MODULE_SALT: bytes = bytes.fromhex("f3a9c2e7b1d4086f5e2a9c4d7b0e3f6a1c8d2b5e")
CATCLAW_NAMESPACE: str = "cat_claw_v1_dev"

# Default deployment addresses (random, dev-only; replace for mainnet)
DEFAULT_KEEPER: str = "0xa7B3c9E2f1d4F6b8A0c2E5e7D9f1B3a6C8d0F2e"
DEFAULT_TREASURY: str = "0x2E5f8B1c4D7a0E3b6F9c2A5d8E1f4B7a0C3d6F1"
DEFAULT_GUARD: str = "0xC4d7F0a3B6E9c2D5f8A1b4E7d0C3F6a9B2e5D8f"

# Selectors: use external tool (e.g. cast sig "logStretch(uint256)") for exact keccak256;
# these placeholders are for structure only (Python hashlib.sha3_256 differs from EVM keccak256).
SELECTOR_LOG_STRETCH: str = "0x00000000"
SELECTOR_CLAIM_NAP: str = "0x00000000"
SELECTOR_WITHDRAW_TREASURY: str = "0x00000000"
SELECTOR_SET_GUARD_PAUSED: str = "0x00000000"
SELECTOR_GET_STRETCH: str = "0x00000000"


class CatClawError(Exception):
    """Base for CatClaw dev errors."""
    pass


class NotKeeperError(CatClawError):
    """Raised when caller is not the keeper."""
    pass


class NotTreasuryError(CatClawError):
    """Raised when caller is not the treasury."""
    pass


class NotGuardError(CatClawError):
    """Raised when caller is not the guard."""
