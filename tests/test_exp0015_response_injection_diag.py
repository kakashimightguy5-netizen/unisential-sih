"""Unit + integration proofs for the EXP-0015 NMRI / CMRI diagnostic.

Fast tests cover the stats/confusion helpers on hand-built inputs. The slow test
runs the real EXP-0004 detector and asserts the identity gates + findings.
"""
import numpy as np
import pytest

import exp0015_response_injection_diag as exp
from features_windowed import WINDOW_FEATURES, Window


def win(w_index, *, categories=frozenset({0}), **feat):
    features = {name: 0.0 for name in WINDOW_FEATURES}
    features.update(feat)
    return Window(
        w_index=w_index, t_start=w_index * 5.0, features=features,
        is_attack=int(any(c != 0 for c in categories)), categories=categories,
        func_codes=frozenset({0x03}), addresses=frozenset({4}),
    )


# --------------------------------------------------------------- helpers

def test_grade_effect_boundaries():
    assert exp.grade_effect(0.19) == "negligible"
    assert exp.grade_effect(0.2) == "small"
    assert exp.grade_effect(0.5) == "medium"
    assert exp.grade_effect(0.8) == "large"


def test_cohens_d_matches_manual():
    assert exp.cohens_d({"mean": 10.0, "std": 2.0}, {"mean": 8.0, "std": 2.0}) == pytest.approx(1.0)
    assert exp.cohens_d({"mean": 5.0, "std": 0.0}, {"mean": 5.0, "std": 0.0}) == 0.0


def test_confusion_arithmetic_and_percentages():
    c = exp.confusion(tp=109, n_pos=1131, fp=36, n_neg=4807)
    assert (c["tp"], c["fn"], c["fp"], c["tn"]) == (109, 1022, 36, 4771)
    assert c["recall_pct"] == pytest.approx(100 * 109 / 1131, abs=0.01)
    assert c["precision_pct"] == pytest.approx(100 * 109 / 145, abs=0.01)
    assert c["fpr_pct"] == pytest.approx(100 * 36 / 4807, abs=0.001)


def test_score_distribution_on_known_array():
    d = exp.score_distribution(np.array([0.0, 0.25, 0.5, 0.75, 1.0]))
    assert (d["min"], d["median"], d["max"], d["n"]) == (0.0, 0.5, 1.0, 5)
    assert exp.score_distribution(np.array([])) == {}


def test_nearest_normal_matches_picks_closest_index():
    normal = [win(10), win(20), win(31), win(50)]
    attacks = [win(9), win(21), win(26), win(100)]
    assert [m.w_index for m in exp.nearest_normal_matches(attacks, normal)] == [10, 20, 31, 50]


def test_dominant_vs_containing_selection():
    wins = [
        win(1, categories=frozenset({0, 1})),          # NMRI dominant + containing
        win(2, categories=frozenset({0, 1, 2})),       # NMRI dominant (min), CMRI containing
        win(3, categories=frozenset({0, 2})),          # CMRI dominant + containing
    ]
    assert [w.w_index for w in exp._containing(wins, 2)] == [2, 3]
    assert [w.w_index for w in exp._dominant(wins, 2)] == [3]
    assert [w.w_index for w in exp._dominant(wins, 1)] == [1, 2]


def test_preregistered_constants():
    assert exp.CATEGORIES == {"NMRI": 1, "CMRI": 2}
    assert exp.EXP0004_TEST_CONFUSION == (4771, 36, 3793, 747)
    assert exp.EXP0004_THRESHOLD == 0.6745465823488428


# --------------------------------------------------------------- integration

@pytest.mark.slow
def test_diagnostic_runs_gates_hold_and_direction_is_response_side():
    result = exp.run_diagnostic()
    assert result["experiment"] == "EXP-0015"
    assert result["detector"]["modified"] is False
    assert len(result["detector"]["identity_gates_passed"]) == 3
    assert result["manifest"]["split_id"] == "verified-egress-5s-exp0008-pretest-v1"

    nmri = result["per_category"]["NMRI"]
    cmri = result["per_category"]["CMRI"]
    for b in (nmri, cmri):
        assert "response-side" in b["direction"] and "diode caveat does NOT apply" in b["direction"]

    # known per-category-table cohorts: NMRI dominant TEST 1,131 ; CMRI dominant TEST 1,812
    assert nmri["window_counts"]["dominant_category"]["TEST"] == 1131
    assert cmri["window_counts"]["dominant_category"]["TEST"] == 1812

    for b in (nmri, cmri):
        for cohort in ("containing_cohort", "dominant_cohort", "pure_cohort"):
            blk = b["combined_detector_confusion"][cohort]
            c = blk["combined"]
            assert (c["fp"], c["tn"]) == (36, 4771)          # EXP-0004 frozen Normal split
            assert c["fpr_pct"] == pytest.approx(0.7489, abs=0.001)
            assert c["tp"] + c["fn"] == blk["n_positive"]
            assert c["tp"] <= blk["if_only_tp"] + blk["rule_only_tp"]
        # pure cohort: rule layer cannot fire (no co-occurring foreign func code)
        assert b["combined_detector_confusion"]["pure_cohort"]["rule_only_tp"] == 0
        s = b["if_score_diagnostic"]
        assert s["all_blocks"]["median"] < s["threshold"]

    rows = nmri["feature_diagnostic"]["per_feature"]
    assert len(rows) == len(WINDOW_FEATURES)
    ds = [abs(r["cohens_d_vs_matched_normal"]) for r in rows]
    assert ds == sorted(ds, reverse=True)
