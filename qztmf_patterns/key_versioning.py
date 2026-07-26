"""Key Material Versioning pattern.

Reference implementation of QZTMF Section V.C. Every key in scope is
tagged with algorithm family, parameter set, creation timestamp, expiry,
and the QZTMF phase under which it was provisioned, so an enterprise can
answer "which keys were issued under which migration phase, and which are
overdue for rotation" without cross-referencing multiple systems.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional


@dataclass(frozen=True)
class KeyMaterialRecord:
    key_id: str
    algorithm_family: str  # e.g. "ML-DSA", "ECDSA", "FN-DSA"
    parameter_set: str  # e.g. "ML-DSA-44", "P-256"
    created_at: datetime
    expires_at: datetime
    qztmf_phase: int  # 1-7, per Section IV

    def __post_init__(self) -> None:
        if not (1 <= self.qztmf_phase <= 7):
            raise ValueError("qztmf_phase must be between 1 and 7")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")

    def is_expired(self, as_of: Optional[datetime] = None) -> bool:
        as_of = as_of or datetime.now(timezone.utc)
        return as_of >= self.expires_at

    def days_until_expiry(self, as_of: Optional[datetime] = None) -> int:
        as_of = as_of or datetime.now(timezone.utc)
        return (self.expires_at - as_of).days


class KeyMaterialRegistry:
    """In-memory registry over KeyMaterialRecord entries.

    A production deployment backs this with the enterprise HSM/KMS
    inventory rather than memory; the query surface below (by phase, by
    algorithm family, expiring-soon) is what Phase 1's asset register and
    Phase 6's fallback-rate monitoring both need.
    """

    def __init__(self) -> None:
        self._records: Dict[str, KeyMaterialRecord] = {}

    def register(self, record: KeyMaterialRecord) -> None:
        self._records[record.key_id] = record

    def get(self, key_id: str) -> KeyMaterialRecord:
        return self._records[key_id]

    def by_phase(self, phase: int) -> List[KeyMaterialRecord]:
        return [r for r in self._records.values() if r.qztmf_phase == phase]

    def by_algorithm_family(self, family: str) -> List[KeyMaterialRecord]:
        return [r for r in self._records.values() if r.algorithm_family == family]

    def expiring_within(self, days: int, as_of: Optional[datetime] = None) -> List[KeyMaterialRecord]:
        as_of = as_of or datetime.now(timezone.utc)
        return [r for r in self._records.values() if 0 <= r.days_until_expiry(as_of) <= days]

    def classical_fallback_rate(self, classical_families: Iterable[str] = ("RSA", "ECDSA")) -> float:
        """Fraction of registered keys still on a classical algorithm family.

        QZTMF's Phase 6->7 exit gate requires this to fall below 0.01
        (0.01% of *authentication events*, not of registered keys - this
        helper reports the key-population analogue, which is the metric
        an asset registry can actually compute directly).
        """
        if not self._records:
            return 0.0
        classical = sum(1 for r in self._records.values() if r.algorithm_family in classical_families)
        return classical / len(self._records)
