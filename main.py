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
    pass


class GuardPausedError(CatClawError):
    """Raised when contract is paused."""
    pass


class InvalidStretchIdError(CatClawError):
    """Raised when stretch or nap index is invalid."""
    pass


class StretchAlreadyFinalizedError(CatClawError):
    """Raised when stretch is already finalized."""
    pass


class WithdrawOverCapError(CatClawError):
    """Raised when withdrawal would exceed cap."""
    pass


class ZeroAmountError(CatClawError):
    """Raised when amount or address is zero."""
    pass


class ReentrantError(CatClawError):
    """Raised on reentrancy attempt."""
    pass


# -----------------------------------------------------------------------------
# Enums and data types
# -----------------------------------------------------------------------------

class StretchStatus(enum.IntEnum):
    PENDING = 0
    LOGGED = 1
    FINALIZED = 2


class GuardState(enum.IntEnum):
    ACTIVE = 0
    PAUSED = 1


@dataclass(frozen=True)
class StretchRecord:
    intensity_bps: int
    logged_at: int
    epoch_id: int
    finalized: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intensityBps": self.intensity_bps,
            "loggedAt": self.logged_at,
            "epochId": self.epoch_id,
            "finalized": self.finalized,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> StretchRecord:
        return cls(
            intensity_bps=int(d.get("intensityBps", d.get("intensity_bps", 0))),
            logged_at=int(d.get("loggedAt", d.get("logged_at", 0))),
            epoch_id=int(d.get("epochId", d.get("epoch_id", 0))),
            finalized=bool(d.get("finalized", False)),
        )


@dataclass
class CatClawConfig:
    keeper: str = DEFAULT_KEEPER
    treasury: str = DEFAULT_TREASURY
    guard: str = DEFAULT_GUARD
    genesis_time: int = 0
    withdraw_cap_wei: int = CATCLAW_WITHDRAW_CAP_WEI
    chain_id: int = 1

    def with_genesis(self, ts: int) -> CatClawConfig:
        return dataclasses.replace(self, genesis_time=ts)

    def to_env_dict(self) -> Dict[str, str]:
        return {
            "CATCLAW_KEEPER": self.keeper,
            "CATCLAW_TREASURY": self.treasury,
            "CATCLAW_GUARD": self.guard,
            "CATCLAW_CHAIN_ID": str(self.chain_id),
        }


# -----------------------------------------------------------------------------
# Encoding helpers (ABI-like, for dev simulation)
# -----------------------------------------------------------------------------

def _ensure_hex_address(addr: Union[str, bytes]) -> str:
    if isinstance(addr, bytes):
        return "0x" + addr.hex()
    s = addr.strip()
    if not s.startswith("0x"):
        s = "0x" + s
    return s


def encode_uint256(value: int) -> bytes:
    """Encode uint256 as 32-byte big-endian."""
    return value.to_bytes(32, "big")


def encode_address(addr: Union[str, bytes]) -> bytes:
    """Encode address as 32 bytes (right-padded)."""
    a = _ensure_hex_address(addr)
    if a.startswith("0x"):
        a = a[2:]
    return bytes.fromhex(a).rjust(32, b"\x00")


def encode_bool(value: bool) -> bytes:
    """Encode bool as 32 bytes."""
    return (1 if value else 0).to_bytes(32, "big")


def encode_log_stretch(intensity_bps: int) -> bytes:
    """Encode calldata for logStretch(uint256)."""
    return bytes.fromhex(SELECTOR_LOG_STRETCH[2:]) + encode_uint256(intensity_bps)


def encode_claim_nap(nap_index: int) -> bytes:
    """Encode calldata for claimNap(uint256)."""
    return bytes.fromhex(SELECTOR_CLAIM_NAP[2:]) + encode_uint256(nap_index)


def encode_withdraw_treasury(to: Union[str, bytes], amount_wei: int) -> bytes:
    """Encode calldata for withdrawTreasury(address,uint256)."""
    return (
        bytes.fromhex(SELECTOR_WITHDRAW_TREASURY[2:])
        + encode_address(to)
        + encode_uint256(amount_wei)
    )


def encode_set_guard_paused(paused: bool) -> bytes:
    """Encode calldata for setGuardPaused(bool)."""
    return bytes.fromhex(SELECTOR_SET_GUARD_PAUSED[2:]) + encode_bool(paused)


def decode_stretch_result(data: bytes) -> Tuple[int, int, int, bool]:
    """Decode getStretch(uint256) return: intensityBps, loggedAt, epochId, finalized."""
    if len(data) < 128:
        raise ValueError("getStretch return data too short")
    intensity_bps = int.from_bytes(data[0:32], "big")
    logged_at = int.from_bytes(data[32:64], "big")
    epoch_id = int.from_bytes(data[64:96], "big")
    finalized = int.from_bytes(data[96:128], "big") != 0
    return (intensity_bps, logged_at, epoch_id, finalized)


# -----------------------------------------------------------------------------
# Epoch and stretch math
# -----------------------------------------------------------------------------

def epoch_at(genesis_time: int, timestamp: int, epoch_secs: int = CATCLAW_EPOCH_SECS) -> int:
    """Return epoch index for given timestamp."""
    if timestamp < genesis_time:
        return 0
    return (timestamp - genesis_time) // epoch_secs


def clamp_intensity_bps(bps: int, max_bps: int = 10000) -> int:
    """Clamp intensity to [0, max_bps]."""
    if bps < 0:
        return 0
    return min(bps, max_bps)


def next_stretch_id(current: int) -> int:
    """Next stretch id (simulation)."""
    return current + 1


# -----------------------------------------------------------------------------
# In-memory dev simulation (no chain)
# -----------------------------------------------------------------------------

@dataclass
class SimulatedStretch:
    stretch_id: int
    record: StretchRecord


@dataclass
class SimulatedNap:
    nap_index: int
    reward_wei: int
    claimed: bool


class CatClawSimulator:
    """In-memory simulator for CatClaw logic (Clawbot copy dev)."""

    def __init__(self, config: Optional[CatClawConfig] = None):
        self.config = config or CatClawConfig()
        self._stretches: Dict[int, StretchRecord] = {}
        self._naps: Dict[int, int] = {}
        self._nap_claim_count: Dict[str, int] = {}
        self._total_withdrawn_wei: int = 0
        self._next_stretch_id: int = 0
        self._guard_paused: bool = False
        self._reentrancy_lock: int = 0

    def set_genesis(self, ts: int) -> None:
        self.config = self.config.with_genesis(ts)

    def log_stretch(self, intensity_bps: int, caller: str, now_ts: int) -> int:
        if caller != self.config.keeper:
            raise NotKeeperError()
        if self._guard_paused:
            raise GuardPausedError()
        if self._reentrancy_lock != 0:
            raise ReentrantError()
        stretch_id = self._next_stretch_id
        self._next_stretch_id += 1
        epoch = epoch_at(self.config.genesis_time, now_ts)
        rec = StretchRecord(
            intensity_bps=clamp_intensity_bps(intensity_bps),
            logged_at=now_ts,
            epoch_id=epoch,
            finalized=True,
        )
        self._stretches[stretch_id] = rec
        return stretch_id

    def get_stretch(self, stretch_id: int) -> Optional[StretchRecord]:
        return self._stretches.get(stretch_id)

    def set_nap_reward(self, nap_index: int, reward_wei: int, caller: str) -> None:
        if caller != self.config.keeper:
            raise NotKeeperError()
        self._naps[nap_index] = reward_wei

    def claim_nap(self, nap_index: int, claimant: str) -> int:
        if self._guard_paused:
            raise GuardPausedError()
        if self._reentrancy_lock != 0:
            raise ReentrantError()
        reward = self._naps.get(nap_index, 0)
        if reward == 0:
            raise InvalidStretchIdError()
        self._naps[nap_index] = 0
        self._nap_claim_count[claimant] = self._nap_claim_count.get(claimant, 0) + 1
        return reward

    def withdraw_treasury(self, to: str, amount_wei: int, caller: str) -> None:
        if caller != self.config.treasury:
            raise NotTreasuryError()
        if not to or amount_wei == 0:
            raise ZeroAmountError()
        if self._total_withdrawn_wei + amount_wei > self.config.withdraw_cap_wei:
            raise WithdrawOverCapError()
        if self._reentrancy_lock != 0:
            raise ReentrantError()
        self._total_withdrawn_wei += amount_wei

    def set_guard_paused(self, paused: bool, caller: str) -> None:
        if caller != self.config.guard:
            raise NotGuardError()
        self._guard_paused = paused

    def total_withdrawn_wei(self) -> int:
        return self._total_withdrawn_wei

    def nap_claim_count(self, account: str) -> int:
        return self._nap_claim_count.get(account, 0)

    def next_stretch_id(self) -> int:
        return self._next_stretch_id


# -----------------------------------------------------------------------------
# ABI export (minimal, for tooling)
# -----------------------------------------------------------------------------

CATCLAW_ABI_EVENTS: List[Dict[str, Any]] = [
    {
        "type": "event",
        "name": "StretchLogged",
        "inputs": [
            {"name": "stretchId", "type": "uint256", "indexed": True},
            {"name": "intensityBps", "type": "uint256", "indexed": False},
            {"name": "loggedAt", "type": "uint40", "indexed": False},
            {"name": "keeper", "type": "address", "indexed": True},
        ],
    },
    {
        "type": "event",
        "name": "NapClaimed",
        "inputs": [
            {"name": "claimant", "type": "address", "indexed": True},
            {"name": "napIndex", "type": "uint256", "indexed": False},
            {"name": "rewardWei", "type": "uint256", "indexed": False},
        ],
    },
    {
        "type": "event",
        "name": "GuardToggled",
        "inputs": [{"name": "paused", "type": "bool", "indexed": False}],
    },
    {
        "type": "event",
        "name": "TreasuryWithdrawn",
        "inputs": [
            {"name": "to", "type": "address", "indexed": True},
            {"name": "amountWei", "type": "uint256", "indexed": False},
        ],
    },
