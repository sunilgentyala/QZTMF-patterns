from datetime import datetime, timedelta, timezone

import pytest

from qztmf_patterns.key_versioning import KeyMaterialRecord, KeyMaterialRegistry


def _record(key_id, family="ML-DSA", phase=3, days_valid=200, created_offset_days=0):
    now = datetime.now(timezone.utc)
    created = now - timedelta(days=created_offset_days)
    return KeyMaterialRecord(
        key_id=key_id,
        algorithm_family=family,
        parameter_set=f"{family}-44",
        created_at=created,
        expires_at=created + timedelta(days=days_valid),
        qztmf_phase=phase,
    )


def test_invalid_phase_rejected():
    with pytest.raises(ValueError):
        _record("k1", phase=8)


def test_expiry_before_creation_rejected():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        KeyMaterialRecord(
            key_id="k1", algorithm_family="ML-DSA", parameter_set="ML-DSA-44",
            created_at=now, expires_at=now - timedelta(days=1), qztmf_phase=3,
        )


def test_registry_queries():
    reg = KeyMaterialRegistry()
    reg.register(_record("k1", family="ML-DSA", phase=3, days_valid=200))
    reg.register(_record("k2", family="ECDSA", phase=1, days_valid=365))
    reg.register(_record("k3", family="ML-DSA", phase=4, days_valid=5))

    assert {r.key_id for r in reg.by_phase(3)} == {"k1"}
    assert {r.key_id for r in reg.by_algorithm_family("ML-DSA")} == {"k1", "k3"}
    assert {r.key_id for r in reg.expiring_within(7)} == {"k3"}


def test_classical_fallback_rate():
    reg = KeyMaterialRegistry()
    reg.register(_record("k1", family="ML-DSA"))
    reg.register(_record("k2", family="ECDSA"))
    reg.register(_record("k3", family="ECDSA"))
    reg.register(_record("k4", family="RSA"))
    assert reg.classical_fallback_rate() == pytest.approx(0.75)


def test_classical_fallback_rate_empty_registry_is_zero():
    assert KeyMaterialRegistry().classical_fallback_rate() == 0.0
