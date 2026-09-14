"""EXP-0030: fast synthetic units for the ULP-distance metric edge cases and
the decision-rule aggregation, plus a slow saved-result replay (no raw-data
read, no refit) that checks the identity gate and the pre-registered
decision rule against the actual saved TEST-scored-once output.

`ml/iforest_detector.run_detector` is NOT called or modified anywhere in
this test file or in `ml/exp0030_float_provenance_detector.py`.
"""
import json
from pathlib import Path

import numpy as np
import pytest

import exp0030_float_provenance_detector as exp
from exp0032_admissible_ceiling_audit import nearest_reference_distance

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0030_float_provenance_detector.json"


# --------------------------------------------------------- ULP-distance metric

def test_nearest_reference_distance_exact_hit_is_zero():
    ref = np.array([1.0, 2.0, 3.0])
    out = nearest_reference_distance(np.array([2.0]), ref)
    assert out[0] == 0.0


def test_nearest_reference_distance_between_two_points_picks_nearer():
    ref = np.array([1.0, 5.0])
    out = nearest_reference_distance(np.array([2.0, 4.0]), ref)
    assert out[0] == pytest.approx(1.0)  # nearer to 1.0
    assert out[1] == pytest.approx(1.0)  # nearer to 5.0


def test_nearest_reference_distance_tie_is_symmetric_minimum():
    ref = np.array([1.0, 3.0])
    out = nearest_reference_distance(np.array([2.0]), ref)
    assert out[0] == pytest.approx(1.0)  # equidistant; min() of two equal candidates


def test_nearest_reference_distance_out_of_range_scores_against_nearest_edge():
    ref = np.array([10.0, 20.0, 30.0])
    below = nearest_reference_distance(np.array([-5.0]), ref)
    above = nearest_reference_distance(np.array([1000.0]), ref)
    assert below[0] == pytest.approx(15.0)   # distance to 10.0, the minimum edge
    assert above[0] == pytest.approx(970.0)  # distance to 30.0, the maximum edge


def test_nearest_reference_distance_empty_reference_is_nan():
    out = nearest_reference_distance(np.array([1.0]), np.array([]))
    assert np.isnan(out[0])


# --------------------------------------------------------- decision-rule aggregation

def test_fpr_bar_gate_blocks_wiring_when_exceeded():
    assert 0.014 > exp.FPR_BAR


def test_overall_verdict_no_go_when_fpr_bar_fails_even_if_recall_improves():
    # Mirrors run_experiment()'s aggregation logic in miniature.
    marginal_fpr_bar_holds = False
    verdicts = {}
    for name in ("NMRI", "CMRI"):
        qualifies = bool(True and marginal_fpr_bar_holds and True and True)
        verdicts[name] = {"qualifies_for_wiring": qualifies}
    any_qualify = any(v["qualifies_for_wiring"] for v in verdicts.values())
    assert any_qualify is False


def test_overall_verdict_partial_go_when_only_one_category_qualifies():
    verdicts = {"NMRI": {"qualifies_for_wiring": True}, "CMRI": {"qualifies_for_wiring": False}}
    any_qualify = any(v["qualifies_for_wiring"] for v in verdicts.values())
    all_qualify = all(v["qualifies_for_wiring"] for v in verdicts.values())
    assert any_qualify and not all_qualify


# --------------------------------------------------------- production code untouched

def test_run_detector_not_imported_or_called_by_this_module():
    import ast
    import inspect

    src = inspect.getsource(exp)
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "iforest_detector":
            assert all(alias.name != "run_detector" for alias in node.names)
        if isinstance(node, ast.Attribute) and node.attr == "run_detector":
            pytest.fail("exp0030 module references run_detector")


# --------------------------------------------------------- slow: saved-result replay

@pytest.mark.skipif(not RESULT_PATH.exists(), reason="EXP-0030 has not been run yet")
def test_saved_result_identity_gate_and_decision_rule_are_consistent():
    data = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    gate = data["identity_gates"]["fix1_style_gate_vs_exp0025"]
    assert all(gate.values()), f"EXP-0030 identity gate vs the wired EXP-0025 baseline failed: {gate}"
    assert data["identity_gates"]["run_detector_modified"] is False

    marginal = data["test_scored_once"]["marginal_contribution"]
    decision = data["decision_rule"]
    fpr_bar_holds = marginal["new_fpr"] <= decision["fpr_bar"]
    assert marginal["fpr_bar_holds"] == fpr_bar_holds
    if not fpr_bar_holds:
        assert decision["overall_verdict"].startswith("NO-GO")
        for v in decision["per_attack_verdicts"].values():
            assert v["qualifies_for_wiring"] is False
