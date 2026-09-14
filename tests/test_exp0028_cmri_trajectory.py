"""EXP-0028: synthetic units for the Normal reference library, DTW / discord
scoring and the in-bounds-predecessor artifact gate, plus one slow saved-result
replay (no raw-data read).

`ml/iforest_detector.run_detector` is measurement-only here: a source check
asserts this module never imports or calls it.
"""
import ast
import inspect
import json
from pathlib import Path

import numpy as np
import pytest

import exp0028_cmri_trajectory as exp

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0028_cmri_trajectory.json"


class _Blocks:
    """Minimal stand-in for exp0019's Blocks: block labels only."""

    def __init__(self, labels):
        self.labels = labels

    def label(self, bucket):
        return self.labels.get(bucket, "other")


# ------------------------------------------------------- contiguous runs

def test_contiguous_runs_splits_on_gap_and_on_keep_index():
    series = [(0.0, 1.0), (3.0, 2.0), (6.0, 3.0), (20.0, 9.0), (23.0, 4.0)]
    # gap_tol=5: the jump from t=6 to t=20 (14s) breaks the run.
    runs = exp.contiguous_runs(series, gap_tol=5.0, keep_index=lambda i: True)
    assert runs == [[0, 1, 2], [3, 4]]


def test_contiguous_runs_excludes_indices_keep_index_rejects():
    series = [(0.0, 1.0), (3.0, 2.0), (6.0, 3.0), (9.0, 4.0)]
    keep = lambda i: i != 2
    runs = exp.contiguous_runs(series, gap_tol=5.0, keep_index=keep)
    assert runs == [[0, 1], [3]]


# ------------------------------------------------------- library construction

def test_build_normal_library_uses_train_normal_contiguous_stretches_only():
    # 60 samples with unique-enough values so >= MIN_LIBRARY_SIZE distinct
    # length-2 sub-sequences survive dedup.
    series = [(3.0 * i, float(i % 40)) for i in range(60)]
    blocks = _Blocks({b: "train_normal" for b in range(0, 60)})
    lib = exp.build_normal_library(series, blocks, gap_tol=5.0, length=2)
    assert lib.shape[1] == 2
    assert lib.shape[0] >= exp.MIN_LIBRARY_SIZE


def test_build_normal_library_dedups_identical_subsequences():
    # A long constant run yields many identical length-3 windows -> after
    # dedup, at most one unique constant sub-sequence plus a handful from the
    # varying prefix, and definitely fewer than the number of raw windows.
    series = [(3.0 * i, 5.0) for i in range(50)]
    blocks = _Blocks({bucket: "train_normal" for bucket in range(0, 60)})
    with pytest.raises(RuntimeError):
        # a single constant value collapses to 1 unique sub-sequence, well
        # below MIN_LIBRARY_SIZE -- dedup is doing its job
        exp.build_normal_library(series, blocks, gap_tol=5.0, length=3)


def test_build_normal_library_raises_when_too_small():
    series = [(0.0, 1.0), (3.0, 2.0)]
    blocks = _Blocks({0: "train_normal"})
    with pytest.raises(RuntimeError):
        exp.build_normal_library(series, blocks, gap_tol=5.0, length=2)


def test_build_normal_library_caps_size_deterministically():
    series = [(3.0 * i, float((i * 37) % 5000) / 100.0) for i in range(2000)]
    blocks = _Blocks({b: "train_normal" for b in range(0, 2000)})
    lib1 = exp.build_normal_library(series, blocks, gap_tol=5.0, length=4)
    lib2 = exp.build_normal_library(series, blocks, gap_tol=5.0, length=4)
    assert lib1.shape[0] <= exp.LIBRARY_MAX_SIZE
    assert np.array_equal(lib1, lib2)          # deterministic subsample


# ------------------------------------------------------- z-normalization

def test_z_normalize_rows_handles_constant_rows():
    mat = np.array([[5.0, 5.0, 5.0], [1.0, 2.0, 3.0]])
    z = exp.z_normalize_rows(mat)
    assert np.allclose(z[0], 0.0)                       # std guarded, no div-by-zero
    assert np.isclose(z[1].mean(), 0.0, atol=1e-9)


# ------------------------------------------------------- distances

def test_dtw_nn_batch_zero_for_identical_sequence_in_library():
    query = np.array([0.0, 1.0, 2.0, 1.0])
    library = np.stack([query, query + 5.0, query * 2])
    d = exp.dtw_nn_batch(query, library)
    assert d == pytest.approx(0.0, abs=1e-9)


def test_dtw_nn_batch_matches_hand_computed_small_case():
    query = np.array([0.0, 2.0])
    library = np.array([[0.0, 0.0]])
    # DP: cost(1,1)=|0-0|=0; cost(1,2)=|0-0|=0+min(0,inf,inf)=0
    # cost(2,1)=|2-0|=2+min(0,inf,inf)=2; cost(2,2)=|2-0|=2+min(0,0,2)=2
    d = exp.dtw_nn_batch(query, library)
    assert d == pytest.approx(2.0)


def test_discord_nn_batch_is_euclidean_nearest_neighbor():
    query = np.array([0.0, 0.0, 0.0])
    library = np.array([[1.0, 0.0, 0.0], [3.0, 4.0, 0.0]])
    d = exp.discord_nn_batch(query, library)
    assert d == pytest.approx(1.0)


# ------------------------------------------------------- threshold fitting

def test_fit_threshold_bounds_empirical_fpr():
    rng = np.random.default_rng(0)
    normal_scores = rng.normal(size=10000)
    threshold, achieved = exp.fit_threshold(normal_scores, max_fpr=0.003)
    assert achieved <= 0.003 + 1e-9
    fired = np.sum(normal_scores > threshold) / len(normal_scores)
    assert fired == pytest.approx(achieved)


def test_fit_threshold_zero_budget_fires_on_nothing():
    scores = np.array([1.0, 2.0, 3.0])
    threshold, achieved = exp.fit_threshold(scores, max_fpr=0.0)
    assert achieved == 0.0
    assert np.sum(scores > threshold) == 0


# ------------------------------------------------------- cohens_d reuse sanity

def test_cohens_d_zero_for_identical_groups():
    assert exp.cohens_d([1, 2, 3], [1, 2, 3]) == 0.0


def test_cohens_d_large_for_well_separated_groups():
    d = exp.cohens_d([10, 11, 12], [0, 1, 2])
    assert d > 3


# ------------------------------------------------------- rule_recall

def test_rule_recall_arithmetic():
    cmri_mask = np.array([True, True, False, True])
    fired = np.array([1, 0, 1, 1])
    hits, n, recall = exp.rule_recall(cmri_mask, fired)
    assert (hits, n) == (2, 3)
    assert recall == pytest.approx(2 / 3)


def test_rule_recall_zero_denominator():
    cmri_mask = np.array([False, False])
    fired = np.array([1, 1])
    hits, n, recall = exp.rule_recall(cmri_mask, fired)
    assert (hits, n, recall) == (0, 0, 0.0)


# ------------------------------------------------------- measurement-only guard

def test_module_is_measurement_only():
    src = inspect.getsource(exp)
    assert "from iforest_detector import" not in src
    assert "import iforest_detector" not in src
    calls = {
        node.func.id for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "run_detector" not in calls


def test_no_forbidden_fields_referenced():
    """No code (as opposed to prose in the module docstring, which explicitly
    disclaims these fields) accesses crc_rate or a 'source' field."""
    tree = ast.parse(inspect.getsource(exp))
    body_without_docstring = ast.Module(body=tree.body[1:], type_ignores=[])
    src_without_docstring = ast.unparse(body_without_docstring)
    for forbidden in ("crc_rate", "'source'", '"source"'):
        assert forbidden not in src_without_docstring


# ------------------------------------------------------- slow replay

@pytest.mark.slow
def test_saved_result_identity_and_decision_rule():
    if not RESULT_PATH.exists():
        pytest.skip("EXP-0028 result not generated in this tree")
    r = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert r["experiment"] == "EXP-0028"

    g = r["identity_gates"]
    assert g["comb_equals_protocol_or_pressure_or_if"] is True
    assert g["whole_test_confusion_matches_exp0017"] is True
    assert g["run_detector_modified"] is False
    assert g["exp0017_confusion"] == [4767, 40, 2166, 2374]

    dr = r["decision_rule"]
    assert dr["verdict"] in {"GO", "NO-GO"}
    expected_go = bool(
        dr["passes_recall_bar"] and dr["passes_fpr_bar"] and dr["artifact_check_clean_or_gated"]
    )
    assert (dr["verdict"] == "GO") is expected_go

    # the val threshold was fit before TEST was scored -- both metrics present
    assert set(r["val_threshold_selection"]) == {"dtw", "discord"}
    assert set(r["test_scoring"]) == {"dtw", "discord"}
    for metric in ("dtw", "discord"):
        assert r["test_scoring"][metric]["test_normal_fpr"] >= 0.0
        for cohort in ("pure_cmri", "dominant_cmri", "containing_cmri"):
            assert 0.0 <= r["test_scoring"][metric][cohort]["recall"] <= 1.0
