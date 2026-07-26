from qztmf_patterns import AlgorithmAbstractionLayer, SecurityLevel, OperationType


def test_sign_verify_roundtrip_default_backend():
    aal = AlgorithmAbstractionLayer()
    priv, pub = aal.generate_keypair(SecurityLevel.LEVEL_128)
    message = b"QZTMF Phase 3 JWKS rotation test payload"
    sig = aal.sign(SecurityLevel.LEVEL_128, priv, message)
    assert aal.verify(SecurityLevel.LEVEL_128, pub, message, sig)


def test_verify_rejects_tampered_message():
    aal = AlgorithmAbstractionLayer()
    priv, pub = aal.generate_keypair(SecurityLevel.LEVEL_128)
    sig = aal.sign(SecurityLevel.LEVEL_128, priv, b"original")
    assert not aal.verify(SecurityLevel.LEVEL_128, pub, b"tampered", sig)


def test_register_backend_swaps_without_callsite_change():
    aal = AlgorithmAbstractionLayer()

    class _StubPQBackend:
        def generate_keypair(self):
            return ("stub-priv", "stub-pub")

        def sign(self, private_key, message: bytes) -> bytes:
            assert private_key == "stub-priv"
            return b"stub-signature:" + message

        def verify(self, public_key, message: bytes, signature: bytes) -> bool:
            assert public_key == "stub-pub"
            return signature == b"stub-signature:" + message

    aal.register_backend(SecurityLevel.LEVEL_128, OperationType.SIGN, _StubPQBackend())
    priv, pub = aal.generate_keypair(SecurityLevel.LEVEL_128)
    sig = aal.sign(SecurityLevel.LEVEL_128, priv, b"payload")
    assert aal.verify(SecurityLevel.LEVEL_128, pub, b"payload", sig)


def test_unbound_level_raises():
    aal = AlgorithmAbstractionLayer()
    try:
        aal.active_backend(SecurityLevel.LEVEL_256, OperationType.KEY_AGREEMENT)
        assert False, "expected ValueError"
    except ValueError:
        pass
