"""Dual-Signature Validation pattern.

Reference implementation of QZTMF Section V.B / Phase 6. During the hybrid
transition window, a relying party must accept tokens signed by legacy
RSA/ECDSA keys, tokens signed purely by a post-quantum key, and legacy
tokens carrying a parallel post-quantum signature over the same payload
(the "ext-ml-dsa-sig" extension named in the paper).

This module implements the dispatch logic only: given a token's key ID
(kid) and a registry of known keys, it decides which verification path
applies and calls back into the supplied verifier functions. It does not
implement JWT/JOSE parsing itself, so it can sit in front of any token
library.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Optional


class KeyClass(str, Enum):
    LEGACY_CLASSICAL = "LEGACY_CLASSICAL"
    POST_QUANTUM = "POST_QUANTUM"


class TokenValidationError(Exception):
    pass


@dataclass
class RegisteredKey:
    kid: str
    key_class: KeyClass
    public_key: object


VerifierFn = Callable[[object, bytes, bytes], bool]


class DualSignatureValidator:
    """Routes token validation to the correct signature path by kid.

    Parameters
    ----------
    classical_verify:
        Callable(public_key, message, signature) -> bool for the legacy
        algorithm (e.g. RSA-PSS or ECDSA).
    pq_verify:
        Callable(public_key, message, signature) -> bool for the
        post-quantum algorithm (e.g. ML-DSA-44).
    """

    def __init__(self, classical_verify: VerifierFn, pq_verify: VerifierFn) -> None:
        self._keys: Dict[str, RegisteredKey] = {}
        self._classical_verify = classical_verify
        self._pq_verify = pq_verify

    def register_key(self, kid: str, key_class: KeyClass, public_key: object) -> None:
        self._keys[kid] = RegisteredKey(kid=kid, key_class=key_class, public_key=public_key)

    def validate(
        self,
        kid: str,
        message: bytes,
        primary_signature: bytes,
        pq_extension_signature: Optional[bytes] = None,
    ) -> bool:
        """Validate a token per QZTMF's dual-signature dispatch rule.

        - kid identifies a POST_QUANTUM key: success/failure rests on the
          post-quantum signature alone (Phase 7 target state).
        - kid identifies a LEGACY_CLASSICAL key: the classical signature
          must verify, AND if pq_extension_signature is present it must
          also verify against the same message (Phase 6 hybrid state).
          A legacy key with no PQ extension is accepted (Phase 1-5
          pre-hybrid state) but callers should treat that path as a
          migration-backlog signal, not a steady-state expectation.
        """
        key = self._keys.get(kid)
        if key is None:
            raise TokenValidationError(f"Unknown kid: {kid}")

        if key.key_class is KeyClass.POST_QUANTUM:
            return self._pq_verify(key.public_key, message, primary_signature)

        # LEGACY_CLASSICAL path
        if not self._classical_verify(key.public_key, message, primary_signature):
            return False
        if pq_extension_signature is not None:
            # Phase 6: dual-signature hybrid mode requires both to hold.
            pq_key = self._keys.get(f"{kid}.ml-dsa-44")
            if pq_key is None:
                raise TokenValidationError(
                    f"ext-ml-dsa-sig present but no companion PQ key registered for {kid}"
                )
            return self._pq_verify(pq_key.public_key, message, pq_extension_signature)
        return True
