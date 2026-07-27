# QZTMF Patterns

Reference implementations of the cryptographic agility engineering patterns from the **Quantum-Safe Zero-Trust Migration Framework (QZTMF)**: a seven-phase methodology for migrating enterprise zero-trust architectures to NIST post-quantum cryptographic standards.

Paper: *"Post-Quantum Cryptographic Migration Framework for Enterprise Zero-Trust Security Architectures"* (manuscript in preparation). Site: https://sunilgentyala.github.io/QZTMF-patterns/

## What's here

- **`qztmf_patterns/aal.py`**: Algorithm Abstraction Layer. Resolves cryptographic operations by security level and operation type rather than by algorithm name, so an algorithm rotation is a policy change, not a code change. Ships a classical (RSA/ECDSA) backend via the `cryptography` package and a pluggable interface for a post-quantum backend (e.g. `oqs`-backed ML-DSA).
- **`qztmf_patterns/dual_signature.py`**: Dual-Signature Validation. The kid-based dispatch logic for the Phase 6 hybrid window, where a token may carry a classical signature, a post-quantum signature, or both.
- **`qztmf_patterns/key_versioning.py`**: Key Material Versioning. A tagging schema and query surface (by migration phase, by algorithm family, expiring-soon) for tracking which keys were issued under which QZTMF phase.
- **`qztmf_patterns/qrs.py`**: Quantum Risk Score. The paper's `QRS = 0.5·AQV + 0.3·DSL + 0.2·ESB` asset-prioritization formula, with the weights exposed as a constructor argument rather than a hardcoded constant, since the paper is explicit that the default weights are a starting heuristic, not an empirically derived optimum.

## What's not here

The mTLS handshake latency and X.509 certificate size benchmarks reported in the paper were measured separately against Open Quantum Safe liboqs 0.10.1 on dedicated hardware. This repository does not reproduce those hardware measurements; it provides working reference implementations of the *patterns*, independent of the benchmark numbers.

## Install

```bash
pip install -e ".[dev]"
pytest
```

## Status

Reference/research code accompanying an academic manuscript. Not a production PKI library: enterprise adopters should treat this as a starting point for their own Algorithm Abstraction Layer implementation, not a drop-in dependency.

## Authors

- Sunil Gentyala, IEEE Senior Member, HCLTech (HCL America Inc.), USA
- John Martin, HCLTech, New Zealand
- Floriano Caprio, HCLTech, Italy
- Akhila Kasturi, HCLTech, India
- Suresh Kumar Darisi, HCL, USA

## License

MIT: see `LICENSE`.
