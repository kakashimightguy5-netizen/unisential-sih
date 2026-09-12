"""EXP-0025: RateFloodRule unit tests, a DeterministicRuleLayer/PressureBoundsRule
regression test (existing behaviour unchanged), and slow end-to-end tests of the
saved derived result. FEASIBILITY/WIRING for Type 2 (egress-channel flood) DoS
ONLY — Type 1 (external inbound-flood) DoS is untouched and stays at 0% recall.
"""
import json
from pathlib import Path

import numpy as np
import pytest

from rules import DeterministicRuleLayer, PressureBoundsRule, RateFloodRule, RuleHit

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0025_detector.json"


# --------------------------------------------------------- RateFloodRule

def test_rate_flood_rule_fit_and_evaluate():
    rule = RateFloodRule().fit([0.2, 0.8, 0.5, 0.1])
    assert rule.bound.max_packets_per_sec == 0.8
    assert rule.evaluate(0.8).fired is False           # at bound, not above
    assert rule.evaluate(0.80001).fired is True
    assert "packets_per_sec_above_train_normal_max" in rule.evaluate(2.0).reasons[0]
    assert rule.evaluate(0.0).fired is False


def test_rate_flood_rule_evaluate_none_is_silent():
    rule = RateFloodRule().fit([1.0])
    assert rule.evaluate(None).fired is False


def test_rate_flood_rule_guards():
    with pytest.raises(RuntimeError):
        RateFloodRule().evaluate(1.0)                  # unfitted
    with pytest.raises(ValueError):
        RateFloodRule().fit([])                        # no finite values
    with pytest.raises(ValueError):
        RateFloodRule().fit([float("inf"), float("nan")])
    r = RateFloodRule().fit([1.0, float("inf"), 5.0, float("nan")])
    assert r.bound.max_packets_per_sec == 5.0


def test_rate_flood_rule_predict_batch():
    rule = RateFloodRule().fit([1.0, 2.0])
    assert rule.predict([0.5, 2.0, 2.1, 100.0]) == [0, 0, 1, 1]


# --------------------------------------------------- existing rules regression

def test_deterministic_rule_layer_and_pressure_rule_behaviour_unchanged():
    """EXP-0025 adds RateFloodRule only; DeterministicRuleLayer and
    PressureBoundsRule must behave exactly as before."""
    from features_windowed import WINDOW_FEATURES, Window

    def win(w_index, *, func_codes=frozenset({0x03}), addresses=frozenset({4})):
        return Window(
            w_index=w_index, t_start=w_index * 5.0,
            features={n: 0.0 for n in WINDOW_FEATURES},
            is_attack=0, categories=frozenset({0}),
            func_codes=func_codes, addresses=addresses,
        )

    layer = DeterministicRuleLayer().fit([win(1), win(2, func_codes=frozenset({0x03, 0x10}))])
    assert layer.evaluate(win(3)).fired is False
    assert layer.evaluate(win(4, func_codes=frozenset({0x16}))).fired is True

    pressure = PressureBoundsRule().fit([1.0, 2.0, 3.0])
    assert pressure.evaluate(1.5, 2.5).fired is False
    assert pressure.evaluate(0.5, 2.5).fired is True


# --------------------------------------------------- combined RuleHit composition

def test_three_rule_or_composition():
    """protocol OR pressure OR rate — exactly the composition wired into
    run_detector() (EXP-0025)."""
    a = RuleHit(fired=False, reasons=[])
    b = RuleHit(fired=True, reasons=["pressure_above_train_normal_max=99>38.7"])
    c = RuleHit(fired=False, reasons=[])
    combined = RuleHit(bool(a.fired or b.fired or c.fired), a.reasons + b.reasons + c.reasons)
    assert combined.fired is True
    assert combined.reasons == ["pressure_above_train_normal_max=99>38.7"]

    a = RuleHit(fired=False, reasons=[])
    b = RuleHit(fired=False, reasons=[])
    c = RuleHit(fired=True, reasons=["packets_per_sec_above_train_normal_max=5>0.8"])
    combined = RuleHit(bool(a.fired or b.fired or c.fired), a.reasons + b.reasons + c.reasons)
    assert combined.fired is True
    assert combined.reasons == ["packets_per_sec_above_train_normal_max=5>0.8"]


# --------------------------------------------------- static-analysis / scope discipline

def test_module_never_parses_or_uses_source_field():
    import ast
    import exp0025_dos_rate_rule as mod
    src = Path(mod.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "source":
            pytest.fail("exp0025 must never read record.source")
        if isinstance(node, ast.Name) and node.id == "source":
            pytest.fail("exp0025 must never bind/use a bare 'source' identifier")


def test_module_does_not_touch_closed_lines():
    import exp0025_dos_rate_rule as mod
    src = Path(mod.__file__).read_text(encoding="utf-8")
    for forbidden in ("exp0011", "exp0014", "exp0018", "exp0019", "exp0020",
                       "exp0021", "exp0022", "exp0023", "ack001", "ack002", "app.py"):
        assert forbidden not in src, forbidden


# --------------------------------------------------- slow: saved result replay

@pytest.mark.slow
def test_saved_result_replay():
    if not RESULT_PATH.exists():
        pytest.skip("exp0025_detector.json not present; run ml/exp0025_dos_rate_rule.py first")
    from exp0025_dos_rate_rule import load_payload, load_detector_result

    payload = load_payload()
    assert payload["experiment"] == "EXP-0025"
    assert payload["status"] == "VALIDATED"
    assert "Type 1" in payload["scope_statement"]
    assert payload["derivation_notes"]["no_new_test_scoring_event"] is True

    result = load_detector_result()
    assert int(result.rate_pred.sum()) == 0            # zero effect on real TEST data
    m = result.metrics(result.comb_pred)
    assert (m["tn"], m["fp"], m["fn"], m["tp"]) == (4767, 40, 2166, 2374)  # identical to EXP-0017

    from features_windowed import CATEGORY_NAMES
    dos_idx = np.where(result.cat_test == CATEGORY_NAMES.index("DoS"))[0]
    assert len(dos_idx) > 0
    assert result.comb_pred[dos_idx].sum() == 0        # Type 1 DoS: still 0%, unaffected


@pytest.mark.slow
def test_verification_dose_response_reproduces_high_recall_at_moderate_severity():
    if not RESULT_PATH.exists():
        pytest.skip("exp0025_detector.json not present; run ml/exp0025_dos_rate_rule.py first")
    from exp0025_dos_rate_rule import load_payload
    v = load_payload()["verification"]
    assert v["untouched_real_normal_test_fp"] == 0
    by_severity = {(r["profile"], r["severity_x"]): r for r in v["dose_response"]}
    # at 1x (no injection) the rate rule must be silent -- sanity anchor
    assert by_severity[("A_distinct", 1)]["flagged"] == 0
    # at severity >= 5x, both profiles reach 100% recall (0 false negatives)
    for profile in ("A_distinct", "B_duplicate"):
        row5 = by_severity[(profile, 5)]
        assert row5["confusion_vs_real_normal_test"]["fn"] == 0
        assert row5["confusion_vs_real_normal_test"]["fp"] == 0
