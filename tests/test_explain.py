"""Feature-deviation explanations for synthetic and real EXP-0004 alerts."""
from types import SimpleNamespace

import numpy as np
import pytest

from explain import explain_alert, explain_flagged_alerts
from features_windowed import IF_FEATURES, WINDOW_FEATURES
from iforest_detector import DetectorResult
from rules import RuleHit


def synthetic_result(*, flagged=True, rule_hit=None):
    if_idx = [WINDOW_FEATURES.index(feature) for feature in IF_FEATURES]
    mu = np.zeros(len(WINDOW_FEATURES), dtype=float)
    sd = np.ones(len(WINDOW_FEATURES), dtype=float)
    features = {feature: 0.0 for feature in WINDOW_FEATURES}
    features.update({
        "packet_count": 2.0,
        "packets_per_sec": -7.0,
        "bytes_per_sec": 4.0,
        "payload_entropy_mean": -6.0,
        "iat_mean": 3.0,
    })
    hit = rule_hit or RuleHit(fired=False, reasons=[])
    return DetectorResult(
        n_windows=1,
        n_train=0,
        n_val=0,
        n_test=1,
        n_train_normal=0,
        threshold=0.5,
        valid_func_codes=frozenset({0x03, 0x10}),
        valid_addresses=frozenset({4}),
        mu=mu,
        sd=sd,
        if_idx=if_idx,
        y_test=np.array([1]),
        cat_test=np.array([5]),
        base_pred=np.array([0]),
        rule_pred=np.array([int(hit.fired)]),
        if_pred=np.array([int(flagged and not hit.fired)]),
        comb_pred=np.array([int(flagged)]),
        if_scores=np.array([0.8]),
        rule_hits=[hit],
        test_windows=[SimpleNamespace(
            w_index=123,
            t_start=615.0,
            features=features,
        )],
    )


def test_explain_alert_shape_and_highest_deviations():
    explanation = explain_alert(synthetic_result(), 0, top_k=4)

    assert explanation.test_index == 0
    assert explanation.window_index == 123
    assert explanation.timestamp == 615.0
    assert explanation.fired_by_if is True
    assert explanation.fired_by_rule is False
    assert explanation.rule_reasons == ()
    assert len(explanation.top_deviations) == 4
    assert [item.feature for item in explanation.top_deviations] == [
        "packets_per_sec",
        "payload_entropy_mean",
        "bytes_per_sec",
        "iat_mean",
    ]
    assert [item.z_score for item in explanation.top_deviations] == [-7.0, -6.0, 4.0, 3.0]
    assert [item.direction for item in explanation.top_deviations] == [
        "below", "below", "above", "above"
    ]
    assert explanation.summary == (
        "Flagged; the most statistically unusual features were unusually low packet "
        "rate (7.0 standard deviations below the TRAIN-normal mean) and unusually low "
        "mean payload entropy (6.0 standard deviations below the TRAIN-normal mean)."
    )


def test_rule_hit_is_reported_separately_from_statistical_summary():
    hit = RuleHit(
        fired=True,
        reasons=["invalid_function_code=0x88", "novel_address=7"],
    )
    explanation = explain_alert(synthetic_result(rule_hit=hit), 0)

    assert explanation.fired_by_if is False
    assert explanation.fired_by_rule is True
    assert explanation.rule_reasons == (
        "invalid_function_code=0x88",
        "novel_address=7",
    )
    assert "function code" not in explanation.summary
    assert "novel address" not in explanation.summary


@pytest.mark.parametrize("top_k", [2, 6, 3.0, True])
def test_top_k_must_be_an_integer_from_three_through_five(top_k):
    with pytest.raises(ValueError):
        explain_alert(synthetic_result(), 0, top_k=top_k)


def test_unflagged_window_cannot_be_explained_as_an_alert():
    with pytest.raises(ValueError, match="not flagged"):
        explain_alert(synthetic_result(flagged=False), 0)


def test_test_index_is_validated():
    result = synthetic_result()
    with pytest.raises(IndexError):
        explain_alert(result, 1)
    with pytest.raises(TypeError):
        explain_alert(result, 0.0)


def test_real_exp0004_test_alerts_are_all_explained(detector_result):
    explanations = explain_flagged_alerts(detector_result, top_k=5)
    expected_indices = np.flatnonzero(detector_result.comb_pred)

    assert len(explanations) == 783  # EXP-0004: 747 true positives + 36 false positives
    assert len(explanations) == int(detector_result.comb_pred.sum())
    assert [item.test_index for item in explanations] == expected_indices.tolist()
    for item in explanations:
        test_index = item.test_index
        window = detector_result.test_windows[test_index]
        assert item.window_index == window.w_index
        assert item.timestamp == window.t_start
        assert item.fired_by_if == bool(detector_result.if_pred[test_index])
        assert item.fired_by_rule == bool(detector_result.rule_pred[test_index])
        assert item.rule_reasons == tuple(detector_result.rule_hits[test_index].reasons)
        assert len(item.top_deviations) == 5
        magnitudes = [abs(deviation.z_score) for deviation in item.top_deviations]
        assert magnitudes == sorted(magnitudes, reverse=True)
        assert all(np.isfinite(magnitudes))
        assert "most statistically unusual features" in item.summary
