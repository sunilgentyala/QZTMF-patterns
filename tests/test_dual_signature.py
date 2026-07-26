import pytest

from qztmf_patterns.dual_signature import DualSignatureValidator, KeyClass, TokenValidationError


def _fake_verify_factory(valid_signature: bytes):
    def _verify(public_key, message: bytes, signature: bytes) -> bool:
        return signature == valid_signature
    return _verify


def test_pure_pq_path_ignores_classical_verifier():
    pq_sig = b"pq-sig"
    validator = DualSignatureValidator(
        classical_verify=lambda *a: False,  # must never be called on this path
        pq_verify=_fake_verify_factory(pq_sig),
    )
    validator.register_key("pq-key-1", KeyClass.POST_QUANTUM, public_key="pub")
    assert validator.validate("pq-key-1", b"msg", pq_sig) is True


def test_legacy_key_no_extension_accepted_pre_hybrid():
    classical_sig = b"classical-sig"
    validator = DualSignatureValidator(
        classical_verify=_fake_verify_factory(classical_sig),
        pq_verify=lambda *a: False,
    )
    validator.register_key("legacy-1", KeyClass.LEGACY_CLASSICAL, public_key="pub")
    assert validator.validate("legacy-1", b"msg", classical_sig) is True


def test_legacy_key_with_extension_requires_both_signatures():
    classical_sig = b"classical-sig"
    pq_sig = b"pq-sig"
    validator = DualSignatureValidator(
        classical_verify=_fake_verify_factory(classical_sig),
        pq_verify=_fake_verify_factory(pq_sig),
    )
    validator.register_key("legacy-1", KeyClass.LEGACY_CLASSICAL, public_key="pub")
    validator.register_key("legacy-1.ml-dsa-44", KeyClass.POST_QUANTUM, public_key="pq-pub")

    assert validator.validate("legacy-1", b"msg", classical_sig, pq_extension_signature=pq_sig) is True
    assert validator.validate("legacy-1", b"msg", classical_sig, pq_extension_signature=b"wrong") is False


def test_extension_without_registered_pq_companion_raises():
    classical_sig = b"classical-sig"
    validator = DualSignatureValidator(
        classical_verify=_fake_verify_factory(classical_sig),
        pq_verify=lambda *a: True,
    )
    validator.register_key("legacy-1", KeyClass.LEGACY_CLASSICAL, public_key="pub")
    with pytest.raises(TokenValidationError):
        validator.validate("legacy-1", b"msg", classical_sig, pq_extension_signature=b"pq-sig")


def test_unknown_kid_raises():
    validator = DualSignatureValidator(classical_verify=lambda *a: True, pq_verify=lambda *a: True)
    with pytest.raises(TokenValidationError):
        validator.validate("nonexistent", b"msg", b"sig")
