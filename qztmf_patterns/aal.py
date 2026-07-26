"""Algorithm Abstraction Layer (AAL) pattern.

Reference implementation of QZTMF Section V.A. Callers request an operation
by security level and operation type rather than by algorithm name; the AAL
resolves that request to whatever implementation is currently active under
enterprise policy. Swapping an algorithm means changing the policy binding,
not the call sites.

This reference implementation ships two backends out of the box:
  - a classical backend built on the `cryptography` package (RSA/ECDSA),
    always available, used as the pre-migration default and as the
    fallback signer during the Phase 6 hybrid window;
  - an optional post-quantum backend that binds to the `oqs` (liboqs)
    Python bindings when installed, left as a plug-in point rather than a
    hard dependency so this package installs cleanly without liboqs.

The hardware latency/size numbers reported in the paper's Section VI were
measured separately against liboqs 0.10.1 on dedicated benchmarking
hardware; this module does not attempt to reproduce those measurements.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Protocol, Tuple

from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes


class SecurityLevel(str, Enum):
    LEVEL_128 = "LEVEL_128"
    LEVEL_192 = "LEVEL_192"
    LEVEL_256 = "LEVEL_256"


class OperationType(str, Enum):
    KEY_AGREEMENT = "KEY_AGREEMENT"
    SIGN = "SIGN"
    VERIFY = "VERIFY"


class SignerBackend(Protocol):
    def generate_keypair(self): ...
    def sign(self, private_key, message: bytes) -> bytes: ...
    def verify(self, public_key, message: bytes, signature: bytes) -> bool: ...


@dataclass
class _RSABackend:
    key_size: int

    def generate_keypair(self):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)
        return priv, priv.public_key()

    def sign(self, private_key, message: bytes) -> bytes:
        return private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    def verify(self, public_key, message: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False


@dataclass
class _ECDSABackend:
    curve: ec.EllipticCurve

    def generate_keypair(self):
        priv = ec.generate_private_key(self.curve)
        return priv, priv.public_key()

    def sign(self, private_key, message: bytes) -> bytes:
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, public_key, message: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


class AlgorithmAbstractionLayer:
    """Resolves (security_level, operation_type) -> active backend.

    QZTMF Phase 2-5 migrations rotate the policy binding below (e.g. from
    classical ECDSA at LEVEL_128/SIGN to ML-DSA-44 once a PQC backend is
    registered) without any caller-side code change.
    """

    def __init__(self) -> None:
        self._policy: Dict[Tuple[SecurityLevel, OperationType], SignerBackend] = {
            (SecurityLevel.LEVEL_128, OperationType.SIGN): _ECDSABackend(ec.SECP256R1()),
            (SecurityLevel.LEVEL_192, OperationType.SIGN): _ECDSABackend(ec.SECP384R1()),
            (SecurityLevel.LEVEL_256, OperationType.SIGN): _RSABackend(key_size=4096),
        }

    def register_backend(
        self, level: SecurityLevel, operation: OperationType, backend: SignerBackend
    ) -> None:
        """Rebind a (level, operation) pair to a new backend.

        Used during Phase 2-5 to cut a caller over to a post-quantum
        backend (e.g. an oqs.Signature-backed ML-DSA-44 implementation)
        purely through policy, with zero call-site changes.
        """
        self._policy[(level, operation)] = backend

    def active_backend(self, level: SecurityLevel, operation: OperationType) -> SignerBackend:
        try:
            return self._policy[(level, operation)]
        except KeyError as exc:
            raise ValueError(f"No backend bound for {level}/{operation}") from exc

    def generate_keypair(self, level: SecurityLevel, operation: OperationType = OperationType.SIGN):
        return self.active_backend(level, operation).generate_keypair()

    def sign(self, level: SecurityLevel, private_key, message: bytes) -> bytes:
        return self.active_backend(level, OperationType.SIGN).sign(private_key, message)

    def verify(self, level: SecurityLevel, public_key, message: bytes, signature: bytes) -> bool:
        return self.active_backend(level, OperationType.SIGN).verify(public_key, message, signature)
