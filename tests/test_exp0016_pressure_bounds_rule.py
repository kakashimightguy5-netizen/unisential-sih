"""EXP-0016: PressureBoundsRule unit tests, a DeterministicRuleLayer regression
test (existing MFCI/Recon/func-code behaviour unchanged), and a slow end-to-end
test of the built rule.
"""
import numpy as np
import pytest

import exp0016_pressure_bounds_rule as exp
from features_windowed import WINDOW_FEATURES, Window
from rules import DeterministicRuleLayer, PressureBoundsRule, RuleHit


def win(w_index, *, func_codes=frozenset({0x03}), addresses=frozenset({4}),
        categories=frozenset({0})):
    return Window(
        w_index=w_index, t_start=w_index * 5.0,
        features={n: 0.0 for n in WINDOW_FEATURES},
        is_attack=int(any(c != 0 for c in categories)), categories=categories,
        func_codes=func_codes, addresses=addresses,
    )


# --------------------------------------------------------- PressureBoundsRule

def test_pressure_bounds_rule_fit_and_evaluate():
    rule = PressureBoundsRule().fit([0.5, 6.9, 38.7, 12.0])
    assert (rule.bounds.low, rule.bounds.high) == (0.5, 38.7)
    assert rule.evaluate(10.0, 20.0).fired is False            # in range
    assert rule.evaluate(0.4, 20.0).fired is True              # below
    assert "pressure_below_train_normal_min" in rule.evaluate(0.4, 20.0).reasons[0]
    assert rule.evaluate(1.0, 40.0).fired is True              # above
    assert rule.evaluate(0.0, 1e30).fired is True              # both -> two reasons
    assert len(rule.evaluate(0.0, 1e30).reasons) == 2
    assert rule.evaluate(None, None).fired is False            # no 0x03 pressure


def test_pressure_bounds_rule_guards():
    with pytest.raises(RuntimeError):
        PressureBoundsRule().evaluate(1.0, 2.0)                # unfitted
    with pytest.raises(ValueError):
        PressureBoundsRule().fit([])                           # no finite values
    with pytest.raises(ValueError):
        PressureBoundsRule().fit([float("inf"), float("nan")])
    # non-finite values are filtered, finite ones kept
    r = PressureBoundsRule().fit([1.0, float("inf"), 5.0, float("nan")])
    assert (r.bounds.low, r.bounds.high) == (1.0, 5.0)


def test_pressure_bounds_rule_predict_batch():
    rule = PressureBoundsRule().fit([1.0, 10.0])
    assert rule.predict([(2.0, 8.0), (0.5, 8.0), (2.0, 99.0), (None, None)]) == [0, 1, 1, 0]


# --------------------------------------------------- DeterministicRuleLayer regression

def test_deterministic_rule_layer_behaviour_is_unchanged():
    """EXP-0016 adds PressureBoundsRule only; the existing rule layer -- func-code
    and novel-address checks that drive MFCI/Recon -- must behave exactly as before."""
    layer = DeterministicRuleLayer().fit([
        win(1, func_codes=frozenset({0x03, 0x10}), addresses=frozenset({4})),
        win(2, func_codes=frozenset({0x03}), addresses=frozenset({4})),
    ])
    assert layer.valid_func_codes == frozenset({0x03, 0x10})
    assert layer.valid_addresses == frozenset({4})

    clean = layer.evaluate(win(10, func_codes=frozenset({0x03, 0x10}), addresses=frozenset({4})))
    assert clean == RuleHit(fired=False, reasons=[])

    bad_fc = layer.evaluate(win(11, func_codes=frozenset({0x03, 0x2b}), addresses=frozenset({4})))
    assert bad_fc.fired is True
    assert bad_fc.reasons == ["invalid_function_code=0x2b"]

    novel_addr = layer.evaluate(win(12, func_codes=frozenset({0x03}), addresses=frozenset({4, 9})))
    assert novel_addr.fired is True
    assert novel_addr.reasons == ["novel_address=9"]

    both = layer.evaluate(win(13, func_codes=frozenset({0x99}), addresses=frozenset({7})))
    assert both.reasons == ["invalid_function_code=0x99", "novel_address=7"]

    assert layer.predict([win(10, func_codes=frozenset({0x03})), win(11, func_codes=frozenset({0x2b}))]) == [0, 1]

    with pytest.raises(RuntimeError):
        DeterministicRuleLayer().evaluate(win(1))


def test_deterministic_rule_layer_source_unchanged_by_pressure_rule_addition():
    import inspect
    src = inspect.getsource(DeterministicRuleLayer)
    assert "PressureBounds" not in src and "pressure" not in src.lower()


# --------------------------------------------------------- helpers

def test_window_pressure_min_max():
    out = exp.window_pressure_min_max({100: [2.0, 5.0, 1.0], 200: [], 300: [float("inf"), 3.0]})
    assert out[100] == (1.0, 5.0, 3)
    assert out[200] == (None, None, 0)
    assert out[300] == (3.0, 3.0, 1)


def test_confusion_arithmetic():
    c = exp.confusion(tp=565, n_pos=715, fp=4, n_neg=4807)
    assert (c["tp"], c["fn"], c["fp"], c["tn"]) == (565, 150, 4, 4803)
    assert c["recall_pct"] == pytest.approx(100 * 565 / 715, abs=0.01)
    assert c["fpr_pct"] == pytest.approx(100 * 4 / 4807, abs=0.001)


# --------------------------------------------------------- integration

@pytest.mark.slow
def test_built_rule_strong_result_and_baseline_delta_reported():
    result = exp.run_experiment()
    assert result["experiment"] == "EXP-0016"
    assert result["detector"]["run_detector_modified"] is False
    assert len(result["detector"]["identity_gates_passed"]) == 3

    rule = result["rule"]
    assert rule["bounds_low"] == pytest.approx(0.4828, abs=0.01)
    assert rule["bounds_high"] == pytest.approx(38.75, abs=0.1)

    dr = result["decision_rule"]
    assert dr["verdict"] in {"STRONG", "ACCEPTABLE", "WEAK / RECONSIDER"}
    assert dr["nmri_pure_recall"] >= 0.50          # pre-registered "strong" recall bar
    assert dr["new_pure_normal_fp_rate"] <= 0.0030  # pre-registered FP bar
    assert dr["verdict"] == "STRONG"

    fp = result["pure_normal_test_false_positives"]
    assert fp["n_windows"] == 4807
    assert fp["exp0004_combined_fp"] == 36          # EXP-0004 frozen Normal FP

    wt = result["whole_test_block_binary_confusion"]
    assert wt["exp0004_frozen"] == {"tn": 4771, "fp": 36, "fn": 3793, "tp": 747}
    # the rule adds true positives and (a few) false positives; report the delta
    d_tn, d_fp, d_fn, d_tp = wt["delta_tn_fp_fn_tp"]
    assert d_tp > 0 and d_fn == -d_tp and d_tn == -d_fp

    nmri_pure = next(c for c in result["per_cohort_test"]
                     if c["category"] == "NMRI" and c["cohort"] == "pure")
    # combined+rule NMRI recall is far above EXP-0004's ~1%
    assert nmri_pure["combined_with_pressure_rule"]["recall"] > \
        nmri_pure["exp0004_combined"]["recall"] + 0.4
