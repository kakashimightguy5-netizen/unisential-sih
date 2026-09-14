"""EXP-0032b: synthetic units for the corrected residual-cohort dataset
assembly, verdict computation, and the leave-one-attack-run-out splitter
(Fix 1/2/3), plus one slow saved-result replay (no raw-data read).

`ml/iforest_detector.run_detector` must never be CALLED by this module
(only its already-frozen constants and independently-instantiated
IsolationForest/rule classes are reused) — a source check enforces this.
"""
import ast
import inspect
import json
from pathlib import Path

import numpy as np
import pytest

import exp0032b_ceiling_audit_corrected as exp

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0032b_ceiling_audit_corrected.json"


# ------------------------------------------------------- synthetic cohort-frame helper

def _make_frame(idx, nmri_pure, cmri_pure, normal, missed_by_rule, defined, rows):
    return {
        "idx": np.asarray(idx, dtype=int),
        "nmri_pure": np.asarray(nmri_pure, dtype=bool),
        "cmri_pure": np.asarray(cmri_pure, dtype=bool),
        "normal": np.asarray(normal, dtype=bool),
        "missed_by_rule": np.asarray(missed_by_rule, dtype=bool),
        "defined": np.asarray(defined, dtype=bool),
        "rows": rows,
    }


def _synthetic_row(seed_val: float) -> dict:
    """A full feature row (all F1+F2+F3 names) with distinct deterministic values."""
    row = {}
    for i, name in enumerate(exp.F1_NAMES + exp.F2_NAMES + exp.F3_NAMES):
        row[name] = float(seed_val + i * 0.01)
    return row


# ------------------------------------------------------- _dataset_for

def test_dataset_for_separates_positive_and_negative_by_masks():
    n = 6
    rows = [_synthetic_row(v) for v in range(n)]
    # rows 0,1 are nmri_pure+missed (positive); rows 2..5 normal (negative)
    frame = _make_frame(
        idx=list(range(n)),
        nmri_pure=[True, True, False, False, False, False],
        cmri_pure=[False] * n,
        normal=[False, False, True, True, True, True],
        missed_by_rule=[True, True, False, False, False, False],
        defined=[True] * n,
        rows=rows,
    )
    empty = _make_frame([], [], [], [], [], [], [])
    ds = exp._dataset_for(frame, empty, empty, "nmri_pure", "F1")
    X_tr, y_tr, idx_tr = ds["train"]
    assert int(y_tr.sum()) == 2
    assert len(y_tr) == 6
    assert list(idx_tr) == sorted(idx_tr.tolist())


def test_dataset_for_undefined_rows_excluded():
    n = 3
    rows = [_synthetic_row(v) for v in range(n)]
    frame = _make_frame(
        idx=[0, 1, 2], nmri_pure=[True, False, False], cmri_pure=[False] * 3,
        normal=[False, True, True], missed_by_rule=[True, False, False],
        defined=[True, True, False], rows=rows,
    )
    empty = _make_frame([], [], [], [], [], [], [])
    ds = exp._dataset_for(frame, empty, empty, "nmri_pure", "F1")
    X_tr, y_tr, idx_tr = ds["train"]
    # the undefined normal row (idx 2) must be dropped
    assert 2 not in idx_tr
    assert len(y_tr) == 2


# ------------------------------------------------------- _train_and_score

def test_train_and_score_returns_none_for_single_class():
    X = np.random.default_rng(0).normal(size=(20, 3))
    y = np.zeros(20, dtype=int)
    assert exp._train_and_score(X, y, X) is None


def test_train_and_score_returns_none_for_too_few_rows():
    X = np.random.default_rng(0).normal(size=(5, 3))
    y = np.array([0, 0, 0, 1, 1])
    assert exp._train_and_score(X, y, X) is None


def test_train_and_score_fits_and_scores_when_enough_data():
    rng = np.random.default_rng(0)
    X_pos = rng.normal(loc=5, size=(10, 3))
    X_neg = rng.normal(loc=0, size=(10, 3))
    X = np.vstack([X_pos, X_neg])
    y = np.concatenate([np.ones(10), np.zeros(10)]).astype(int)
    result = exp._train_and_score(X, y, X)
    assert result is not None
    clf, scores = result
    assert len(scores) == len(X)
    # separable synthetic classes -> positives should generally score higher
    assert scores[:10].mean() > scores[10:].mean()


# ------------------------------------------------------- _compute_verdict

def test_compute_verdict_no_go_when_nothing_clears():
    family_results = {
        "F1": {"clears_permutation_null": False, "feature_importances": [], "feature_names": []},
        "F2": {"clears_permutation_null": False, "feature_importances": [], "feature_names": []},
        "F3": {"clears_permutation_null": False, "feature_importances": [], "feature_names": []},
        "combined": {
            "clears_permutation_null": False,
            "feature_names": exp.F1_NAMES, "feature_importances": [1.0] + [0.0] * (len(exp.F1_NAMES) - 1),
        },
    }
    out = exp._compute_verdict(family_results)
    assert out["verdict"] == "NO-GO-CEILING"


def test_compute_verdict_proceed_0030_when_f2_dominant_and_clean():
    names = exp.F1_NAMES + exp.F2_NAMES + exp.F3_NAMES
    importances = [0.0] * len(names)
    ulp_i = names.index("ulp_distance_to_train_normal")
    importances[ulp_i] = 0.9
    family_results = {
        "F1": {"clears_permutation_null": False, "feature_importances": [], "feature_names": []},
        "F2": {"clears_permutation_null": True, "feature_importances": [], "feature_names": []},
        "F3": {"clears_permutation_null": False, "feature_importances": [], "feature_names": []},
        "combined": {
            "clears_permutation_null": True, "feature_names": names, "feature_importances": importances,
        },
    }
    out = exp._compute_verdict(family_results)
    assert out["verdict"] == "PROCEED-0030"
    assert out["dominant_feature_family_combined_model"] == "F2"
    assert out["causality_audit_clean"] is True


def test_compute_verdict_flags_unclean_causality_as_ambiguous():
    names = ["mystery_leaked_field"]
    family_results = {
        "F1": {"clears_permutation_null": False, "feature_importances": [], "feature_names": []},
        "F2": {"clears_permutation_null": False, "feature_importances": [], "feature_names": []},
        "F3": {"clears_permutation_null": False, "feature_importances": [], "feature_names": []},
        "combined": {"clears_permutation_null": True, "feature_names": names, "feature_importances": [1.0]},
    }
    out = exp._compute_verdict(family_results)
    assert out["causality_audit_clean"] is False
    assert out["verdict"].startswith("NO-GO")


# ------------------------------------------------------- leave_one_run_out

def test_leave_one_run_out_identifies_distinct_runs():
    # Two separate contiguous attack runs (idx 0-5 and idx 20-25), well separated,
    # each large enough that holding one out still leaves >= MIN_TRAIN_POSITIVES_FOR_LORO.
    pos_idx = list(range(0, 6)) + list(range(20, 26))
    n_pos = len(pos_idx)
    rng = np.random.default_rng(0)
    # run A clusters around value 5.0, run B clusters around value 5.2 in a
    # feature the F2 family reads (ulp_distance_to_train_normal) -> separable
    # from Normal (clustered around 0.0) regardless of which run is held out.
    pos_rows = []
    for i, ix in enumerate(pos_idx):
        row = _synthetic_row(0.0)
        base = 5.0 if ix < 20 else 5.2
        row["ulp_distance_to_train_normal"] = base + rng.normal(scale=0.01)
        pos_rows.append(row)
    neg_rows = []
    neg_idx = list(range(100, 500))
    for ix in neg_idx:
        row = _synthetic_row(0.0)
        row["ulp_distance_to_train_normal"] = rng.normal(scale=0.01)
        neg_rows.append(row)

    train_frame = _make_frame(
        idx=pos_idx + neg_idx,
        nmri_pure=[True] * n_pos + [False] * len(neg_idx),
        cmri_pure=[False] * (n_pos + len(neg_idx)),
        normal=[False] * n_pos + [True] * len(neg_idx),
        missed_by_rule=[True] * n_pos + [False] * len(neg_idx),
        defined=[True] * (n_pos + len(neg_idx)),
        rows=pos_rows + neg_rows,
    )
    empty = _make_frame([], [], [], [], [], [], [])
    out = exp.leave_one_run_out(train_frame, empty, "nmri_pure", "F2", min_run_size=2)
    assert out["n_runs_evaluated"] == 2
    starts = sorted(r["run_start_w_index"] for r in out["per_run"])
    assert starts == [0, 20]


def test_leave_one_run_out_skips_runs_below_min_size():
    pos_idx = [0, 1]  # single run of size 2, below min_run_size=5
    rows = [_synthetic_row(1.0) for _ in pos_idx]
    neg_idx = list(range(50, 70))
    neg_rows = [_synthetic_row(0.0) for _ in neg_idx]
    train_frame = _make_frame(
        idx=pos_idx + neg_idx,
        nmri_pure=[True, True] + [False] * len(neg_idx),
        cmri_pure=[False] * (2 + len(neg_idx)),
        normal=[False, False] + [True] * len(neg_idx),
        missed_by_rule=[True, True] + [False] * len(neg_idx),
        defined=[True] * (2 + len(neg_idx)),
        rows=rows + neg_rows,
    )
    empty = _make_frame([], [], [], [], [], [], [])
    out = exp.leave_one_run_out(train_frame, empty, "nmri_pure", "F2", min_run_size=5)
    assert out["n_runs_evaluated"] == 0
    assert out["mean_recall"] is None


def test_leave_one_run_out_flags_run_dependence():
    # Runs A and B share ONE informative feature (ulp_distance_to_train_normal);
    # run C's positive signal lives ENTIRELY in a DIFFERENT feature
    # (quantization_distance) that no other run demonstrates. Holding out A or
    # B still leaves the ulp signal learnable from the other -> high recall.
    # Holding out C removes the only run demonstrating the quantization
    # signal -> the model never learns to use that feature -> low recall on
    # C. This is a genuine, not-an-average-illusion, run-dependent outcome.
    rng = np.random.default_rng(2)
    run_a = list(range(0, 8))
    run_b = list(range(20, 28))
    run_c = list(range(40, 48))
    pos_idx = run_a + run_b + run_c
    rows = []
    for ix in pos_idx:
        row = _synthetic_row(0.0)
        if ix in run_c:
            row["ulp_distance_to_train_normal"] = rng.normal(scale=0.01)
            row["quantization_distance"] = 5.0 + rng.normal(scale=0.01)
        else:
            row["ulp_distance_to_train_normal"] = 5.0 + rng.normal(scale=0.01)
            row["quantization_distance"] = rng.normal(scale=0.01)
        rows.append(row)
    neg_idx = list(range(100, 700))
    neg_rows = []
    for _ in neg_idx:
        row = _synthetic_row(0.0)
        row["ulp_distance_to_train_normal"] = rng.normal(scale=0.01)
        row["quantization_distance"] = rng.normal(scale=0.01)
        neg_rows.append(row)
    train_frame = _make_frame(
        idx=pos_idx + neg_idx,
        nmri_pure=[True] * len(pos_idx) + [False] * len(neg_idx),
        cmri_pure=[False] * (len(pos_idx) + len(neg_idx)),
        normal=[False] * len(pos_idx) + [True] * len(neg_idx),
        missed_by_rule=[True] * len(pos_idx) + [False] * len(neg_idx),
        defined=[True] * (len(pos_idx) + len(neg_idx)),
        rows=rows + neg_rows,
    )
    empty = _make_frame([], [], [], [], [], [], [])
    out = exp.leave_one_run_out(train_frame, empty, "nmri_pure", "F2", min_run_size=3,
                               min_train_positives=2)
    assert out["n_runs_evaluated"] == 3
    by_start = {r["run_start_w_index"]: r["held_out_recall"] for r in out["per_run"]}
    # run C (the one whose signal is NOT reproduced by any other run) should
    # recall markedly worse than runs A/B (whose shared signal survives
    # leave-one-out because the other of the pair still demonstrates it).
    assert by_start[40] < by_start[0]
    assert by_start[40] < by_start[20]
    assert out["run_dependent"] is True


# ------------------------------------------------------- measurement-only guard

def test_module_never_calls_run_detector():
    src = inspect.getsource(exp)
    tree = ast.parse(src)
    calls = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "run_detector" not in calls


def test_no_forbidden_fields_referenced():
    tree = ast.parse(inspect.getsource(exp))
    body_without_docstring = ast.Module(body=tree.body[1:], type_ignores=[])
    src_without_docstring = ast.unparse(body_without_docstring)
    for forbidden in ("crc_rate", "'source'", '"source"'):
        assert forbidden not in src_without_docstring


# ------------------------------------------------------- slow replay

@pytest.mark.slow
def test_saved_result_identity_and_decision_rule():
    if not RESULT_PATH.exists():
        pytest.skip("EXP-0032b result not generated in this tree")
    r = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert r["experiment"] == "EXP-0032b"

    g = r["identity_gates"]
    assert g["comb_equals_protocol_or_pressure_or_if"] is True
    assert g["whole_test_confusion_matches_exp0017"] is True
    assert g["run_detector_modified"] is False
    assert g["exp0017_confusion"] == [4767, 40, 2166, 2374]
    fix1_gate = g["fix1_train_val_test_comb_pred_reproduction"]
    assert all(fix1_gate.values())

    assert set(r["per_attack"]) == {"NMRI", "CMRI"}
    for attack, block in r["per_attack"].items():
        assert "final_verdict" in block
        assert block["final_verdict"] in {
            "PROCEED-0030", "PROCEED-0031", "PROCEED-BOTH", "NO-GO-CEILING",
        } or block["final_verdict"].startswith("NO-GO")

    fix2 = r["fix2_control_strength"]
    assert fix2["reduced_counts"] == [60, 20]
    assert fix2["full_counts"] == [200, 50]

    fix3 = r["fix3_leave_one_attack_run_out"]
    assert set(fix3) == {"NMRI", "CMRI"}
    for attack_block in fix3.values():
        assert set(attack_block) == {"F2", "F3"}

    dr = r["decision_rule"]
    assert "overall" in dr and "verdicts" in dr
