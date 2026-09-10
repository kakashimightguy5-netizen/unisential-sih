"""EXP-0020: synthetic units for the in-bounds-predecessor gate, the gated rate
feature, per-window max and the (reused) decision rule, plus one slow test that
replays the saved result (no raw-data read).

`ml/iforest_detector.run_detector` is measurement-only here: a source check
asserts this module never imports or calls it.
"""
import ast
import inspect
import json
from pathlib import Path

import numpy as np
import pytest

import exp0020_pressure_rate_gated as exp
import exp0019_pressure_rate_plausibility as exp19

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0020_pressure_rate_gated.json"
BOUNDS = (0.482759, 38.7471)


class _Blocks:
    def __init__(self, train_normal_buckets):
        self.tn = set(train_normal_buckets)

    def label(self, bucket):
        return "train_normal" if bucket in self.tn else "test"


# --------------------------------------------------------------- the gate

def test_eligible_pairs_drops_out_of_bounds_predecessor_and_nonpositive_dt():
    series = [(0.0, 0.40), (2.0, 10.0), (2.0, 11.0), (5.0, 20.0), (9.0, 50.0)]
    out = list(exp.eligible_pairs(series, BOUNDS))
    # (0.40 -> 10): predecessor 0.40 < 0.482759  -> dropped
    # (10 -> 11): dt = 0                          -> dropped
    # (11 -> 20): pred 11 in bounds, dt 3         -> |9|/3 = 3.0 ; buckets 0 -> 1
    # (20 -> 50): pred 20 in bounds, dt 4         -> |30|/4 = 7.5 ; buckets 1 -> 1
    assert [(eb, lb, round(r, 4)) for eb, lb, r in out] == [(0, 1, 3.0), (1, 1, 7.5)]


def test_window_max_gated_rate_keeps_max_and_its_source_bucket():
    series = [(1.0, 10.0), (2.0, 12.0), (7.0, 40.0), (12.0, 5.0)]
    # pairs: (10->12) pred ok dt1 -> 2.0 ; b0->b0 ... floor(2/5)=0
    #        (12->40) pred ok dt5 -> 5.6 ; b0->b1
    #        (40->5)  pred 40 > 38.7471 -> DROPPED
    by_win, src = exp.window_max_gated_rate(series, BOUNDS)
    assert by_win == {0: 2.0, 1: 5.6}
    assert src == {0: 0, 1: 0}


def test_train_normal_gated_rates_requires_both_endpoints_and_the_gate():
    series = [(1.0, 10.0), (2.0, 20.0), (7.0, 30.0), (12.0, 40.0)]
    # pairs: (10->20) b0->b0 ; (20->30) b0->b1 ; (30->40) b1->b2  (all preds in bounds)
    assert list(np.round(exp.train_normal_gated_rates(series, _Blocks({0}), BOUNDS), 4)) == [10.0]
    assert len(exp.train_normal_gated_rates(series, _Blocks({0, 1, 2}), BOUNDS)) == 3


def test_decision_rule_is_the_frozen_exp0019_rule():
    assert exp.classify_verdict is exp19.classify_verdict
    assert exp.classify_verdict(0.30, 0.001, 0.98) == "STRONG"
    assert exp.classify_verdict(0.30, 0.0031, 0.98).startswith("WEAK")
    assert exp.classify_verdict(0.15, 0.001, 0.98) == "ACCEPTABLE"


def test_module_is_measurement_only():
    src = inspect.getsource(exp)
    assert "from iforest_detector import" not in src
    assert "import iforest_detector" not in src
    calls = {
        node.func.id for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "run_detector" not in calls


# --------------------------------------------------------------- slow replay

@pytest.mark.slow
def test_saved_result_identity_and_decision_rule():
    if not RESULT_PATH.exists():
        pytest.skip("EXP-0020 result not generated in this tree")
    r = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert r["experiment"] == "EXP-0020"

    g = r["identity_gates"]
    assert g["comb_equals_protocol_or_pressure_or_if"] is True
    assert g["whole_test_confusion_matches_exp0017"] is True
    assert g["run_detector_modified"] is False
    assert g["exp0017_confusion"] == [4767, 40, 2166, 2374]
    assert g["exp0016_bounds"] == [0.482759, 38.7471]

    dr = r["decision_rule"]
    assert dr["verdict"] in {"STRONG", "ACCEPTABLE", "WEAK / HYPOTHESIS NOT SUPPORTED"}
    assert exp.classify_verdict(
        dr["new_pure_cmri_recall"], dr["new_pure_normal_fp_rate"], dr["combined_precision"]
    ) == dr["verdict"]

    p = r["method"]["train_normal_gated_rate_percentiles"]
    assert p["p50"] <= p["p99"] <= p["p99_9"] <= p["max"]
    assert r["method"]["cutoff_primary_p99_9"] == pytest.approx(p["p99_9"])

    st = r["signal_test"]
    assert 0.0 <= st["p_value"] <= 1.0

    cmp = r["exp0019_comparison"]
    assert cmp["exp0019_verdict"] == "WEAK / HYPOTHESIS NOT SUPPORTED"
    assert set(cmp) >= {
        "exp0019_pure_normal_fp", "exp0020_pure_normal_fp",
        "exp0019_boundary_artifact_fp", "exp0020_boundary_artifact_fp",
    }

    wt = r["whole_test_block_binary_confusion"]
    d_tn, d_fp, d_fn, d_tp = wt["delta_tn_fp_fn_tp"]
    assert d_tp >= 0 and d_fn == -d_tp and d_tn == -d_fp
    assert wt["exp0017_comb"] == {"tn": 4767, "fp": 40, "fn": 2166, "tp": 2374}
