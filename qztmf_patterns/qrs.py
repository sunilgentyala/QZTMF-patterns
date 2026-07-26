"""Quantum Risk Score (QRS) pattern.

Reference implementation of the QZTMF Section IV.A formula:

    QRS = w_aqv * AQV + w_dsl * DSL + w_esb * ESB

The paper's default weights (0.5 / 0.3 / 0.2) are a starting heuristic,
not an empirically derived optimum -- see the paper's Section IV.A and
VII.D for the reasoning and the explicit call for organizations to
recalibrate them against their own risk appetite. This module makes that
recalibration a constructor argument rather than a hardcoded constant.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class QRSWeights:
    aqv: float = 0.5  # algorithm vulnerability to Shor/Grover
    dsl: float = 0.3  # data sensitivity lifetime
    esb: float = 0.2  # enterprise blast radius

    def __post_init__(self) -> None:
        total = self.aqv + self.dsl + self.esb
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"QRS weights must sum to 1.0, got {total}")
        for name, value in (("aqv", self.aqv), ("dsl", self.dsl), ("esb", self.esb)):
            if not (0.0 <= value <= 1.0):
                raise ValueError(f"weight {name}={value} must be within [0, 1]")


class QuantumRiskScore:
    def __init__(self, weights: QRSWeights = QRSWeights()) -> None:
        self.weights = weights

    def score(self, aqv: float, dsl: float, esb: float) -> float:
        """Compute QRS for a single asset.

        aqv, dsl, esb are each expected on a 0.0-1.0 normalized scale
        (e.g. from a 1-5 rubric divided by 5); the function does not
        itself define the rubric, since that is organization-specific by
        design (Section IV.A).
        """
        for name, value in (("aqv", aqv), ("dsl", dsl), ("esb", esb)):
            if not (0.0 <= value <= 1.0):
                raise ValueError(f"{name}={value} must be within [0, 1]")
        return (
            self.weights.aqv * aqv
            + self.weights.dsl * dsl
            + self.weights.esb * esb
        )

    def rank(self, assets: dict) -> list:
        """Rank a {asset_id: (aqv, dsl, esb)} mapping by descending QRS.

        Returns a list of (asset_id, score) tuples, highest risk first --
        this is the ordering Phase 1 hands to Phase 7's deprecation
        schedule.
        """
        scored = [(asset_id, self.score(*values)) for asset_id, values in assets.items()]
        return sorted(scored, key=lambda pair: pair[1], reverse=True)
