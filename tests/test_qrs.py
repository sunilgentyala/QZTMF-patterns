import pytest

from qztmf_patterns.qrs import QuantumRiskScore, QRSWeights


def test_default_weights_sum_to_one():
    w = QRSWeights()
    assert w.aqv == pytest.approx(0.5)
    assert w.dsl == pytest.approx(0.3)
    assert w.esb == pytest.approx(0.2)


def test_weights_must_sum_to_one():
    with pytest.raises(ValueError):
        QRSWeights(aqv=0.5, dsl=0.5, esb=0.5)


def test_score_matches_paper_formula():
    qrs = QuantumRiskScore()
    # Root CA-like asset: max algorithm vulnerability, long data lifetime,
    # high blast radius -> QRS = 0.5*1 + 0.3*1 + 0.2*1 = 1.0
    assert qrs.score(aqv=1.0, dsl=1.0, esb=1.0) == pytest.approx(1.0)
    # Storage-encryption-like asset: Grover-only, short lifetime, low blast
    assert qrs.score(aqv=0.2, dsl=0.1, esb=0.1) == pytest.approx(0.5 * 0.2 + 0.3 * 0.1 + 0.2 * 0.1)


def test_score_rejects_out_of_range_inputs():
    qrs = QuantumRiskScore()
    with pytest.raises(ValueError):
        qrs.score(aqv=1.5, dsl=0.5, esb=0.5)


def test_custom_recalibrated_weights():
    # An organization that recalibrates ESB upward (Section IV.A / VII.D)
    custom = QuantumRiskScore(QRSWeights(aqv=0.4, dsl=0.2, esb=0.4))
    assert custom.score(aqv=1.0, dsl=0.0, esb=1.0) == pytest.approx(0.8)


def test_rank_orders_by_descending_score():
    qrs = QuantumRiskScore()
    assets = {
        "root-ca": (1.0, 1.0, 1.0),
        "storage-encryption": (0.2, 0.1, 0.1),
        "mtls-leaf": (1.0, 0.6, 0.5),
    }
    ranked = qrs.rank(assets)
    assert [asset_id for asset_id, _ in ranked] == ["root-ca", "mtls-leaf", "storage-encryption"]
