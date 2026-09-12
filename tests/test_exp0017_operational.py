"""Synthetic guard/split/storage checks plus saved operational identity regression."""
import json
from types import SimpleNamespace

import numpy as np
import pytest

import exp0017_operational as exp
from iforest_detector import run_detector


def test_confirmation_rejected_before_any_data_access(monkeypatch):
    monkeypatch.setattr(exp, "load_pretest_split", lambda: pytest.fail("manifest read before confirmation"))
    with pytest.raises(PermissionError, match="confirmation"):
        run_detector()


def test_attempt_ledger_is_exclusive_even_without_output(monkeypatch, tmp_path):
    monkeypatch.setattr(exp, "ATTEMPT_PATH", tmp_path / "attempt.json")
    monkeypatch.setattr(exp, "RESULT_PATH", tmp_path / "result.json")
    exp.begin_evaluation(exp.CONFIRMATION)
    with pytest.raises(FileExistsError):
        exp.begin_evaluation(exp.CONFIRMATION)


def test_manifest_indices_ignore_test_tail_length(monkeypatch):
    split = SimpleNamespace(train_bucket_ids=(1, 3), validation_bucket_ids=(7, 8), final_pretest_bucket_id=8)
    monkeypatch.setattr(exp, "load_pretest_split", lambda: split)
    left = [SimpleNamespace(w_index=i) for i in (1, 3, 5, 7, 8, 11, 15, 20)]
    right = left + [SimpleNamespace(w_index=30), SimpleNamespace(w_index=50)]
    _, tr, va, te = exp.manifest_indices(left)
    _, tr2, va2, te2 = exp.manifest_indices(right)
    assert np.array_equal(tr, tr2) and np.array_equal(va, va2)
    assert [left[i].w_index for i in te] == [20]
    assert [right[i].w_index for i in te2] == [20, 30, 50]
    with pytest.raises(ValueError, match="missing manifest"):
        exp.manifest_indices(left[1:])
    with pytest.raises(ValueError, match="unique"):
        exp.manifest_indices(left + left)


def test_checksum_tampering_rejected(tmp_path):
    path = tmp_path / "result.json"
    path.write_text(json.dumps({"sha256": "wrong", "payload": {}}))
    with pytest.raises(ValueError, match="checksum"):
        exp.load_payload(path)


def test_synthetic_serialization_roundtrip_and_source_identity(monkeypatch, tmp_path):
    from test_explain import synthetic_result
    from features_windowed import Window
    result = synthetic_result()
    w = result.test_windows[0]
    result.test_windows = [Window(w.w_index, w.t_start, w.features, 1,
                                  frozenset({5}), frozenset({3}), frozenset({4}))]
    split = exp.load_pretest_split()
    result.split_id, result.split_sha256 = split.split_id, split.membership_sha256
    monkeypatch.setattr(exp, "RESULT_PATH", tmp_path / "result.json")
    monkeypatch.setattr(exp, "summarize", lambda r: {"status": "VALIDATED", "experiment": "EXP-0017"})
    exp.save_result(result)  # synthetic serialization only, no scoring or data access
    fresh = exp.load_result(exp.RESULT_PATH)
    assert np.array_equal(fresh.if_scores, result.if_scores)
    assert fresh.rule_hits == result.rule_hits
    assert fresh.test_windows == result.test_windows
    with pytest.raises(FileExistsError):
        exp.save_result(result)
    envelope = json.loads(exp.RESULT_PATH.read_text())
    envelope["payload"]["identity"]["source_sha256"]["ml/rules.py"] = "wrong"
    import hashlib
    envelope["sha256"] = hashlib.sha256(exp._encoded(envelope["payload"])).hexdigest()
    exp.RESULT_PATH.write_text(json.dumps(envelope))
    with pytest.raises(ValueError, match="source identity"):
        exp.load_result(exp.RESULT_PATH)


def test_saved_production_output_matches_all_preregistered_gates(detector_result):
    summary = exp.summarize(detector_result)
    assert summary["status"] == "VALIDATED"
    assert all(summary["checks"].values())
    assert np.array_equal(detector_result.rule_pred,
                          detector_result.protocol_pred | detector_result.pressure_pred)
    assert np.array_equal(detector_result.if_pred,
                          (detector_result.if_scores >= detector_result.threshold).astype(int))
    assert all(bool(p) == h.fired for p, h in zip(detector_result.rule_pred, detector_result.rule_hits))


def test_synthetic_pipeline_fits_train_normal_only_and_test_changes_do_not_tune(monkeypatch):
    import iforest_detector as detector
    import exp0016_pressure_bounds_rule as pressure_source
    from features_windowed import WINDOW_FEATURES, Window
    split = SimpleNamespace(train_bucket_ids=(0, 1, 2, 3), validation_bucket_ids=(4, 5),
                            final_pretest_bucket_id=5, split_id="synthetic", membership_sha256="synthetic")
    wins = [Window(i, i * 5., {f: float(i + 1) for f in WINDOW_FEATURES},
                   int(i == 2), frozenset({1} if i == 2 else {0}),
                   frozenset({3}), frozenset({4})) for i in range(10)]
    pressures = {0: [1.], 1: [10.], 2: [999.], 3: [5.], 4: [500.], 8: [11.], 9: [5.]}
    monkeypatch.setattr(exp, "begin_evaluation", lambda confirmation: None)
    monkeypatch.setattr(exp, "save_result", lambda result: None)
    monkeypatch.setattr(exp, "load_pretest_split", lambda: split)
    monkeypatch.setattr(detector, "build_windows", lambda: wins)
    monkeypatch.setattr(pressure_source, "align_egress_pressure", lambda: pressures)
    first = detector.run_detector()
    assert first.pressure_bounds == (1., 10.)
    assert first.pressure_pred.tolist() == [1, 0]
    assert first.n_train_normal == 3
    wins[8].features = {f: 1e6 for f in WINDOW_FEATURES}
    wins[8].is_attack = 1
    pressures[8] = [-1e6]
    second = detector.run_detector()
    assert np.array_equal(first.mu, second.mu) and np.array_equal(first.sd, second.sd)
    assert first.threshold == second.threshold
    assert first.pressure_bounds == second.pressure_bounds
    assert second.pressure_pred.tolist() == [1, 0]


def test_pressure_alert_explains_observed_value_and_bound(detector_result):
    from explain import explain_alert
    pressure_only = np.flatnonzero(detector_result.pressure_pred &
                                  ~(detector_result.protocol_pred | detector_result.if_pred))
    assert len(pressure_only) > 0
    for i in pressure_only:
        explanation = explain_alert(detector_result, int(i))
        assert explanation.fired_by_rule and not explanation.fired_by_if
        assert any(r.startswith("pressure_") and ("<" in r or ">" in r)
                   for r in explanation.rule_reasons)


def test_dashboard_uses_saved_result_with_pressure_limitation(detector_result):
    """Dashboard now loads the EXP-0025 result (protocol OR pressure OR rate OR
    IF) — numerically identical to EXP-0017's on this dataset, since the rate
    rule fires zero times on real captured TEST data. See docs/EXP0025_RESULTS.md."""
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_file(str(exp.ROOT / "app.py")).run(timeout=60)
    assert not app.exception
    assert "EXP-0025" in app.title[0].value
    assert "NOT live packet-byte decoding" in app.info[0].value
    assert any("saved predictions" in c.value for c in app.caption)
