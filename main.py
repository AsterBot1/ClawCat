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
]

CATCLAW_ABI_FUNCTIONS: List[Dict[str, Any]] = [
    {"type": "function", "name": "logStretch", "inputs": [{"name": "intensityBps", "type": "uint256"}], "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "getStretch", "inputs": [{"name": "stretchId", "type": "uint256"}], "outputs": [
        {"name": "intensityBps", "type": "uint88"},
        {"name": "loggedAt", "type": "uint40"},
        {"name": "epochId", "type": "uint64"},
        {"name": "finalized", "type": "bool"},
    ]},
    {"type": "function", "name": "claimNap", "inputs": [{"name": "napIndex", "type": "uint256"}]},
    {"type": "function", "name": "setNapReward", "inputs": [{"name": "napIndex", "type": "uint256"}, {"name": "rewardWei", "type": "uint256"}]},
    {"type": "function", "name": "withdrawTreasury", "inputs": [{"name": "to", "type": "address"}, {"name": "amountWei", "type": "uint256"}]},
    {"type": "function", "name": "setGuardPaused", "inputs": [{"name": "paused", "type": "bool"}]},
    {"type": "function", "name": "totalWithdrawnWei", "inputs": [], "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "napClaimCount", "inputs": [{"name": "account", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}]},
]


def get_full_abi() -> List[Dict[str, Any]]:
    """Return combined ABI list for events and functions."""
    return CATCLAW_ABI_EVENTS + CATCLAW_ABI_FUNCTIONS


def write_abi_json(path: str) -> None:
    """Write full ABI to a JSON file."""
    with open(path, "w") as f:
        json.dump(get_full_abi(), f, indent=2)


# -----------------------------------------------------------------------------
# Checksums and validation
# -----------------------------------------------------------------------------

def checksum_address(addr: str) -> str:
    """Return EIP-55 checksummed address (simplified dev version)."""
    a = _ensure_hex_address(addr).lower()
    if a.startswith("0x"):
        a = a[2:]
    if len(a) != 40:
        raise ValueError("Address must be 20 bytes (40 hex chars)")
    return "0x" + a


def validate_intensity_bps(bps: int) -> bool:
    return 0 <= bps <= 10000


def validate_withdraw_cap(amount_wei: int, already_withdrawn: int, cap_wei: int) -> bool:
    return amount_wei > 0 and already_withdrawn + amount_wei <= cap_wei


# -----------------------------------------------------------------------------
# Script / CLI helpers
# -----------------------------------------------------------------------------

def load_config_from_env() -> CatClawConfig:
    """Build config from environment variables."""
    return CatClawConfig(
        keeper=os.environ.get("CATCLAW_KEEPER", DEFAULT_KEEPER),
        treasury=os.environ.get("CATCLAW_TREASURY", DEFAULT_TREASURY),
        guard=os.environ.get("CATCLAW_GUARD", DEFAULT_GUARD),
        chain_id=int(os.environ.get("CATCLAW_CHAIN_ID", "1")),
    )


def run_simulation_example() -> None:
    """Run a short simulation and print results."""
    config = CatClawConfig(genesis_time=1700000000)
    sim = CatClawSimulator(config)
    stretch_id = sim.log_stretch(5000, config.keeper, 1700000100)
    print(f"Logged stretch id={stretch_id}")
    rec = sim.get_stretch(stretch_id)
    assert rec is not None
    print(f"  intensityBps={rec.intensity_bps}, epochId={rec.epoch_id}")
    sim.set_nap_reward(0, 1 * 10**18, config.keeper)
    reward = sim.claim_nap(0, "0x" + "11" * 20)
    print(f"  claimed nap reward={reward}")
    print("Simulation OK.")


# -----------------------------------------------------------------------------
# Batch and bulk helpers
# -----------------------------------------------------------------------------

def batch_encode_log_stretch(intensity_list: List[int]) -> List[bytes]:
    """Encode multiple logStretch calldatas."""
    return [encode_log_stretch(clamp_intensity_bps(bps)) for bps in intensity_list]


def batch_stretch_ids(start_id: int, count: int) -> List[int]:
    """Return list of stretch ids [start_id, start_id+1, ...]."""
    return list(range(start_id, start_id + count))


def compute_epoch_bounds(genesis_time: int, epoch_index: int) -> Tuple[int, int]:
    """Return (start_ts, end_ts) for epoch (inclusive start, exclusive end)."""
    start = genesis_time + epoch_index * CATCLAW_EPOCH_SECS
    return (start, start + CATCLAW_EPOCH_SECS)


def stretches_in_epoch(stretch_records: List[Tuple[int, StretchRecord]], epoch_id: int) -> List[Tuple[int, StretchRecord]]:
    """Filter (stretch_id, record) list by epoch_id."""
    return [(sid, rec) for sid, rec in stretch_records if rec.epoch_id == epoch_id]


# -----------------------------------------------------------------------------
# Event log parsing (topic0 + data; dev only)
# -----------------------------------------------------------------------------

EVENT_STRETCH_LOGGED_TOPIC: str = "0x00000000"
EVENT_NAP_CLAIMED_TOPIC: str = "0x00000000"
EVENT_GUARD_TOGGLED_TOPIC: str = "0x00000000"
EVENT_TREASURY_WITHDRAWN_TOPIC: str = "0x00000000"


def parse_stretch_logged_data(data_hex: str) -> Dict[str, Any]:
    """Parse StretchLogged non-indexed data (intensityBps, loggedAt)."""
    data = bytes.fromhex(data_hex.replace("0x", ""))
    if len(data) < 64:
        return {}
    return {
        "intensityBps": int.from_bytes(data[0:32], "big"),
        "loggedAt": int.from_bytes(data[32:64], "big"),
    }


def parse_nap_claimed_data(data_hex: str) -> Dict[str, Any]:
    """Parse NapClaimed non-indexed data (napIndex, rewardWei)."""
    data = bytes.fromhex(data_hex.replace("0x", ""))
    if len(data) < 64:
        return {}
    return {
        "napIndex": int.from_bytes(data[0:32], "big"),
        "rewardWei": int.from_bytes(data[32:64], "big"),
    }


# -----------------------------------------------------------------------------
# Deployment args builder
# -----------------------------------------------------------------------------

def deployment_args_no_fill() -> Dict[str, Any]:
    """Contract deploys with zero constructor args; addresses are internal."""
    return {}


def deployment_bytecode_placeholder() -> str:
    """Placeholder; real bytecode from compiled CatClaw.sol."""
    return "0x"


# -----------------------------------------------------------------------------
# Chain config presets (for dev / testnets only)
# -----------------------------------------------------------------------------

CHAIN_MAINNET: int = 1
CHAIN_SEPOLIA: int = 11155111
CHAIN_BASE_MAINNET: int = 8453
CHAIN_BASE_SEPOLIA: int = 84532
CHAIN_ANVIL: int = 31337

CHAIN_NAMES: Dict[int, str] = {
    CHAIN_MAINNET: "mainnet",
    CHAIN_SEPOLIA: "sepolia",
    CHAIN_BASE_MAINNET: "base",
    CHAIN_BASE_SEPOLIA: "base_sepolia",
    CHAIN_ANVIL: "anvil",
}


def chain_name(chain_id: int) -> str:
    return CHAIN_NAMES.get(chain_id, f"chain_{chain_id}")


# -----------------------------------------------------------------------------
# Gas and limits (informational)
# -----------------------------------------------------------------------------

ESTIMATE_LOG_STRETCH_GAS: int = 80_000
ESTIMATE_CLAIM_NAP_GAS: int = 65_000
ESTIMATE_WITHDRAW_TREASURY_GAS: int = 55_000
ESTIMATE_SET_GUARD_PAUSED_GAS: int = 45_000


def estimate_batch_log_stretch_gas(n: int) -> int:
    """Rough total gas for n logStretch calls (no batching in contract)."""
    return n * ESTIMATE_LOG_STRETCH_GAS


# -----------------------------------------------------------------------------
# Sanity checks and invariants
# -----------------------------------------------------------------------------

def invariant_total_withdrawn_leq_cap(total_withdrawn: int, cap: int) -> bool:
    return total_withdrawn <= cap


def invariant_stretch_id_monotonic(ids: List[int]) -> bool:
    return all(ids[i] < ids[i + 1] for i in range(len(ids) - 1)) if len(ids) > 1 else True


def invariant_intensity_in_range(rec: StretchRecord) -> bool:
    return 0 <= rec.intensity_bps <= 10000


# -----------------------------------------------------------------------------
# Extra simulation scenarios
# -----------------------------------------------------------------------------

def scenario_full_epoch(genesis: int, num_stretches: int, keeper: str) -> List[Tuple[int, StretchRecord]]:
    """Simulate one epoch of stretches at 100-second intervals."""
    sim = CatClawSimulator(CatClawConfig(genesis_time=genesis, keeper=keeper, treasury=DEFAULT_TREASURY, guard=DEFAULT_GUARD))
    out: List[Tuple[int, StretchRecord]] = []
    for i in range(num_stretches):
        ts = genesis + i * 100
        sid = sim.log_stretch(3000 + i * 100, keeper, ts)
        rec = sim.get_stretch(sid)
        if rec:
            out.append((sid, rec))
    return out


def scenario_nap_claims(nap_indices: List[int], rewards: List[int], claimants: List[str], keeper: str) -> Dict[str, int]:
    """Set nap rewards and simulate claims; return final claim counts per claimant."""
    config = CatClawConfig(keeper=keeper, treasury=DEFAULT_TREASURY, guard=DEFAULT_GUARD)
    sim = CatClawSimulator(config)
    for idx, r in zip(nap_indices, rewards):
        sim.set_nap_reward(idx, r, keeper)
    for idx, claimer in zip(nap_indices, claimants):
        try:
            sim.claim_nap(idx, claimer)
        except (InvalidStretchIdError, GuardPausedError, ReentrantError):
            pass
    return {c: sim.nap_claim_count(c) for c in claimants}


# -----------------------------------------------------------------------------
# Export list for wildcard import
# -----------------------------------------------------------------------------

__all__ = [
    "CATCLAW_MAX_STRETCH_PER_EPOCH",
    "CATCLAW_EPOCH_SECS",
    "CATCLAW_WITHDRAW_CAP_WEI",
    "DEFAULT_KEEPER",
    "DEFAULT_TREASURY",
    "DEFAULT_GUARD",
    "CatClawError",
    "NotKeeperError",
    "NotTreasuryError",
    "NotGuardError",
    "GuardPausedError",
    "InvalidStretchIdError",
    "StretchAlreadyFinalizedError",
    "WithdrawOverCapError",
    "ZeroAmountError",
    "ReentrantError",
    "StretchStatus",
    "GuardState",
    "StretchRecord",
    "CatClawConfig",
    "encode_uint256",
    "encode_address",
    "encode_bool",
