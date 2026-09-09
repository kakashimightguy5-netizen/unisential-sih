"""Unit + integration proofs for the EXP-0014 MSCI / MPCI diagnostic.

Fast tests cover the stats helpers on hand-built inputs. The slow test runs the
real EXP-0004 detector and asserts the identity gates + the diagnostic structure.
"""
import numpy as np
import pytest

import exp0014_cmd_injection_diag as exp
from features_windowed import WINDOW_FEATURES, Window


def test_confusion_percentages_are_consistent():
    c = exp._confusion(tp=20, n_pos=1280, fp=36, n_neg=4807)
    assert (c["tp"], c["fn"], c["fp"], c["tn"]) == (20, 1260, 36, 4771)
    assert c["recall_pct"] == pytest.approx(100 * 20 / 1280, abs=0.01)
    assert c["precision_pct"] == pytest.approx(100 * 20 / 56, abs=0.01)
    assert c["fpr_pct"] == pytest.approx(100 * 36 / 4807, abs=0.001)


def win(w_index, **feat):
    features = {name: 0.0 for name in WINDOW_FEATURES}
    features.update(feat)
    return Window(
        w_index=w_index, t_start=w_index * 5.0, features=features,
        is_attack=0, categories=frozenset({0}),
        func_codes=frozenset({0x03}), addresses=frozenset({4}),
    )


# --------------------------------------------------------------- helpers

def test_grade_effect_boundaries():
    assert exp.grade_effect(0.0) == "negligible"
    assert exp.grade_effect(0.19) == "negligible"
    assert exp.grade_effect(0.2) == "small"
    assert exp.grade_effect(-0.49) == "small"
    assert exp.grade_effect(0.5) == "medium"
    assert exp.grade_effect(-0.79) == "medium"
    assert exp.grade_effect(0.8) == "large"


def test_cohens_d_matches_manual():
    a = {"mean": 10.0, "std": 2.0}
    b = {"mean": 8.0, "std": 2.0}
    assert exp.cohens_d(a, b) == pytest.approx(2.0 / 2.0)
    assert exp.cohens_d({"mean": 5.0, "std": 0.0}, {"mean": 5.0, "std": 0.0}) == 0.0


def test_score_distribution_on_known_array():
    d = exp.score_distribution(np.array([0.0, 0.25, 0.5, 0.75, 1.0]))
    assert d["n"] == 5
    assert d["min"] == 0.0 and d["max"] == 1.0
    assert d["median"] == 0.5
    assert d["mean"] == pytest.approx(0.5)
    assert exp.score_distribution(np.array([])) == {}


def test_nearest_normal_matches_picks_closest_index():
    normal = [win(10), win(20), win(31), win(50)]
    attacks = [win(9), win(21), win(26), win(100)]
    matched = exp.nearest_normal_matches(attacks, normal)
    assert [m.w_index for m in matched] == [10, 20, 31, 50]


def test_feature_summary_shape():
    s = exp.feature_summary([win(1, packet_count=2.0), win(2, packet_count=4.0)])
    assert set(s) == set(WINDOW_FEATURES)
    assert s["packet_count"] == {"mean": 3.0, "std": 1.0, "n": 2}


def test_preregistered_constants():
    assert exp.CATEGORIES == {"MSCI": 3, "MPCI": 4}
    assert exp.EXP0004_TEST_CONFUSION == (4771, 36, 3793, 747)
    assert exp.EXP0004_THRESHOLD == 0.6745465823488428


# --------------------------------------------------------------- integration

@pytest.mark.slow
def test_diagnostic_runs_gates_hold_and_findings_are_structural(tmp_path):
    result = exp.run_diagnostic()
    assert result["experiment"] == "EXP-0014"
    assert result["detector"]["modified"] is False
    assert len(result["detector"]["identity_gates_passed"]) == 3
    assert result["manifest"]["split_id"] == "verified-egress-5s-exp0008-pretest-v1"

    # class-size context: MSCI/MPCI TRAIN populations dwarf DoS's 359
    assert result["class_size_context"]["DoS_containing_windows"]["TRAIN"] == 359

    msci = result["per_category"]["MSCI"]
    mpci = result["per_category"]["MPCI"]
    assert msci["window_counts"]["containing_ge1_frame"] == {
        "TRAIN": 1791, "VALIDATION": 521, "TEST": 462, "GUARD": 0,
    }
    assert mpci["window_counts"]["containing_ge1_frame"] == {
        "TRAIN": 4356, "VALIDATION": 1510, "TEST": 1280, "GUARD": 0,
    }
    # TEST-block combined confusion: FP is EXP-0004's frozen 36 / 4,807 Normal windows
    for block in (msci, mpci):
        cc = block["combined_detector_confusion"]["test_block"]
        assert (cc["fp"], cc["tn"]) == (36, 4771)
        assert cc["recall_pct"] < 5.0 and cc["fpr_pct"] == pytest.approx(0.7489, abs=0.001)

    for block in (msci, mpci):
        s = block["if_score_diagnostic"]
        # IF scores sit down near the Normal-window mean, not near the threshold
        assert s["all_blocks"]["median"] < s["threshold"]
        assert s["all_blocks"]["median"] < s["normal_window_mean_score"] + 0.05
        assert s["all_blocks"]["p90"] < s["threshold"]
        assert s["fraction_if_flag_all_blocks"] < 0.02
        assert -0.2 < s["median_score_position_normal0_threshold1"] < 0.2

    # per-feature rows carry both Cohen's d references and are sorted by |d matched|
    rows = msci["feature_diagnostic"]["per_feature"]
    assert len(rows) == len(WINDOW_FEATURES)
    ds = [abs(r["cohens_d_vs_matched_normal"]) for r in rows]
    assert ds == sorted(ds, reverse=True)
