"""EXP-0030c: unit tests for the production F2 feature pipeline
(`ml/float_provenance_features.py`) — reference-set build/save/load
round-trip and `f2_row` feature-order identity. No raw-data read beyond
what the fast fixtures below construct directly.
"""
import json

import numpy as np
import pytest

import float_provenance_features as fpf
from exp0032_admissible_ceiling_audit import F2_NAMES


class _FakeSeriesIndex:
    """Minimal stand-in for exp0032's SeriesIndex, for fast unit tests that
    don't need the real aligned egress pressure series."""

    def __init__(self, values, bucket_by_pos):
        self.values = np.asarray(values, dtype=float)
        self.bucket_by_pos = np.asarray(bucket_by_pos, dtype=int)
        self.positions_by_bucket: dict[int, list[int]] = {}
        for pos, b in enumerate(self.bucket_by_pos):
            self.positions_by_bucket.setdefault(int(b), []).append(pos)


class _FakeBlocks:
    def __init__(self, labels_by_bucket, split_id="test-split", split_sha256="deadbeef"):
        self._labels = labels_by_bucket
        self.split_id = split_id
        self.split_sha256 = split_sha256

    def label(self, bucket):
        return self._labels.get(bucket, "other")


# --------------------------------------------------------- f2_row

def test_f2_row_feature_order_matches_f2_names():
    si = _FakeSeriesIndex(values=[1.0, 2.0, 3.0], bucket_by_pos=[10, 11, 12])
    ref = np.array([1.0, 2.0, 3.0])
    row = fpf.f2_row(si, 12, ref)
    assert list(row.keys()) == list(F2_NAMES)


def test_f2_row_undefined_when_no_own_sample():
    si = _FakeSeriesIndex(values=[1.0], bucket_by_pos=[10])
    ref = np.array([1.0])
    assert fpf.f2_row(si, 999, ref) is None


def test_f2_row_ulp_distance_matches_exact_hit():
    si = _FakeSeriesIndex(values=[5.0], bucket_by_pos=[10])
    ref = np.array([1.0, 5.0, 9.0])
    row = fpf.f2_row(si, 10, ref)
    assert row["ulp_distance_to_train_normal"] == pytest.approx(0.0)


def test_f2_row_uses_trailing_buffer_for_mantissa_entropy():
    values = [1.0] * 40 + [2.0]  # constant buffer -> zero-entropy low mantissa bits, then a jump
    si = _FakeSeriesIndex(values=values, bucket_by_pos=list(range(len(values))))
    ref = np.array(values)
    row_flat = fpf.f2_row(si, len(values) - 2, ref)  # deep in the constant run
    assert row_flat["mantissa_entropy_local"] == pytest.approx(0.0)


# --------------------------------------------------------- reference artifact

def test_build_train_normal_reference_train_normal_only():
    si = _FakeSeriesIndex(
        values=list(range(600)),
        bucket_by_pos=list(range(600)),
    )
    labels = {b: ("train_normal" if b < 550 else "train_attack") for b in range(600)}
    blocks = _FakeBlocks(labels)
    ref = fpf.build_train_normal_reference(si, blocks)
    assert ref.max() < 550
    assert list(ref) == sorted(set(ref.tolist()))  # sorted, deduplicated


def test_build_train_normal_reference_too_few_raises():
    si = _FakeSeriesIndex(values=list(range(10)), bucket_by_pos=list(range(10)))
    blocks = _FakeBlocks({b: "train_normal" for b in range(10)})
    with pytest.raises(RuntimeError):
        fpf.build_train_normal_reference(si, blocks)


def test_save_and_load_reference_round_trip(tmp_path):
    path = tmp_path / "reference.json"
    values = np.array([1.0, 2.5, 3.75])
    blocks = _FakeBlocks({}, split_id="s1", split_sha256="abc123")
    meta = fpf.save_reference(values, blocks, path=path)
    assert meta["n_values"] == 3
    loaded = fpf.load_reference(path=path)
    assert np.array_equal(loaded, values)
    loaded_meta = fpf.load_reference_metadata(path=path)
    assert loaded_meta["split_id"] == "s1"
    assert loaded_meta["split_sha256"] == "abc123"
    assert loaded_meta["provenance"] == fpf.PROVENANCE_STATEMENT
    assert "values" not in loaded_meta


# --------------------------------------------------------- model artifact

def test_save_and_load_model_round_trip(tmp_path):
    pytest.importorskip("xgboost")
    from xgboost import XGBClassifier

    model_path = tmp_path / "model.json"
    meta_path = tmp_path / "model_meta.json"

    X = np.random.default_rng(0).normal(size=(40, len(F2_NAMES)))
    y = (X[:, 0] > 0).astype(int)
    clf = XGBClassifier(n_estimators=5, max_depth=2, random_state=0)
    clf.fit(X, y)

    meta = fpf.save_model(clf, threshold=0.5, feature_names=F2_NAMES,
                          model_path=model_path, metadata_path=meta_path)
    assert meta["threshold"] == 0.5
    assert meta["feature_names"] == list(F2_NAMES)
    assert meta["provenance"] == fpf.PROVENANCE_STATEMENT

    loaded_clf, loaded_threshold, loaded_names = fpf.load_model(
        model_path=model_path, metadata_path=meta_path,
    )
    assert loaded_threshold == 0.5
    assert loaded_names == list(F2_NAMES)
    np.testing.assert_allclose(
        loaded_clf.predict_proba(X)[:, 1], clf.predict_proba(X)[:, 1], atol=1e-6,
    )


def test_load_model_rejects_tampered_model_file(tmp_path):
    pytest.importorskip("xgboost")
    from xgboost import XGBClassifier

    model_path = tmp_path / "model.json"
    meta_path = tmp_path / "model_meta.json"
    X = np.random.default_rng(0).normal(size=(20, len(F2_NAMES)))
    y = (X[:, 0] > 0).astype(int)
    clf = XGBClassifier(n_estimators=3, max_depth=2, random_state=0)
    clf.fit(X, y)
    fpf.save_model(clf, threshold=0.5, feature_names=F2_NAMES,
                   model_path=model_path, metadata_path=meta_path)

    data = json.loads(meta_path.read_text(encoding="utf-8"))
    data["model_sha256"] = "0" * 64
    meta_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError):
        fpf.load_model(model_path=model_path, metadata_path=meta_path)
