"""EXP-0027: unit tests for the co-occurring-category split/breakdown logic,
plus a slow saved-result replay. Descriptive/diagnostic — no detector is
trained here unless the pre-registered gate passed (see docs/EXP0027_RESULTS.md).
"""
import json
from pathlib import Path

import numpy as np
import pytest

import exp0027_msci_realistic_population as exp
from exp0026_window_size import NativeWindow

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0027_msci_realistic_population.json"


# --------------------------------------------------------- other_category_of

def test_other_category_of_excludes_normal_and_msci():
    w = NativeWindow(0, frozenset({0, 3}), [])
    assert exp.other_category_of(w) == frozenset()


def test_other_category_of_includes_co_occurring_attacks():
    w = NativeWindow(0, frozenset({0, 3, 2}), [])
    assert exp.other_category_of(w) == frozenset({2})


def test_other_category_of_multiple_co_occurring():
    w = NativeWindow(0, frozenset({3, 2, 4}), [])
    assert exp.other_category_of(w) == frozenset({2, 4})


# --------------------------------------------------------- split_containing_into_pure_and_mixed

def test_split_pure_and_mixed():
    windows = [
        NativeWindow(0, frozenset({0, 3}), []),        # pure
        NativeWindow(1, frozenset({3}), []),            # pure (no Normal co-occurrence either)
        NativeWindow(2, frozenset({0, 3, 2}), []),      # mixed with CMRI
        NativeWindow(3, frozenset({3, 4}), []),         # mixed with MPCI
    ]
    pure, mixed = exp.split_containing_into_pure_and_mixed(windows)
    assert [w.nb_index for w in pure] == [0, 1]
    assert [w.nb_index for w in mixed] == [2, 3]


def test_split_pure_and_mixed_all_pure():
    windows = [NativeWindow(0, frozenset({0, 3}), [])]
    pure, mixed = exp.split_containing_into_pure_and_mixed(windows)
    assert len(pure) == 1
    assert mixed == []


# --------------------------------------------------------- feature_values

def test_feature_values_skips_windows_with_insufficient_pressure():
    w_ok = NativeWindow(0, frozenset({0}), [(0.0, 1.0), (1.0, 3.0)])
    w_skip = NativeWindow(1, frozenset({0}), [(0.0, 1.0)])  # only 1 sample
    values = exp.feature_values([w_ok, w_skip], {})
    assert values.size == 1
    assert values[0] == pytest.approx(np.std([1.0, 3.0]))


# --------------------------------------------------------- CMRI mechanism split (via run_analysis's inline logic)

def test_other_category_of_identifies_cmri_co_occurrence():
    cmri_id = 2
    w_with_cmri = NativeWindow(0, frozenset({0, 3, 2}), [])
    w_without = NativeWindow(1, frozenset({0, 3, 4}), [])
    assert cmri_id in exp.other_category_of(w_with_cmri)
    assert cmri_id not in exp.other_category_of(w_without)


# --------------------------------------------------------- scope discipline

def test_module_never_parses_or_uses_source_field():
    import ast
    src = Path(exp.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "source":
            pytest.fail("exp0027 must never read record.source")
        if isinstance(node, ast.Name) and node.id == "source":
            pytest.fail("exp0027 must never bind/use a bare 'source' identifier")


def test_module_does_not_import_production_pipeline_or_closed_files():
    src = Path(exp.__file__).read_text(encoding="utf-8")
    for forbidden in ("features_windowed", "run_detector", "iforest_detector",
                       "exp0011", "exp0018", "exp0019", "exp0020", "app"):
        assert f"import {forbidden}" not in src, forbidden
        assert f"from {forbidden} " not in src, forbidden


# --------------------------------------------------------- slow: saved result replay

@pytest.mark.slow
def test_saved_result_replay():
    if not RESULT_PATH.exists():
        pytest.skip("exp0027_msci_realistic_population.json not present; run ml/exp0027_msci_realistic_population.py first")
    data = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert data["experiment"] == "EXP-0027"
    assert data["identity_check_vs_exp0026_pure_cohort"]["within_tolerance"] is True
    gate = data["decision_gate"]
    assert gate["passed"] in (True, False)
    # the realistic population must be at least as large as the pure one
    p = data["populations"]
    assert p["all_containing_msci_vs_pure_normal"]["n_msci"] >= p["pure_msci_vs_pure_normal"]["n_msci"]
    assert "cmri_mechanism_check_informational" in data
