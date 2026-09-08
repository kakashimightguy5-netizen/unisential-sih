"""Tests for the isolated EXP-0005 Layer A proof of concept."""

import pytest

from features_txt import FrameRecord
from layer_a_detector import (
    LAYER_A_FEATURES,
    LayerAWindow,
    build_windows,
    contiguous_blocks,
    run_layer_a_detector,
)


def frame(index, timestamp, destination, category=0):
    return FrameRecord(
        record_index=index, frame_id=index, address=4, function_code=0x10,
        frame_len_bytes=8, is_request=int(destination == 3), start_register=0,
        quantity=1, byte_count=-1, length_anomaly=0, rare_function_code=0,
        crc_ok=0, interarrival_seconds=999.0,
        message_entropy_bits_per_byte=2.0, categorized_attack=category,
        specific_attack=18 if category == 6 else 0, source=1,
        destination=destination, timestamp=timestamp,
    )


def synthetic_window(index, *, normal=True, dos=False, value=0.0):
    categories = (
        frozenset({6}) if dos else
        (frozenset({0}) if normal else frozenset({4}))
    )
    return LayerAWindow(
        bucket_index=index, t_start=index * 5.0,
        features={name: value for name in LAYER_A_FEATURES},
        categories=categories, destinations=frozenset({1, 3}),
    )


def test_build_windows_keeps_both_directions_and_uses_within_window_iat():
    records = [frame(1, 10.1, 1), frame(2, 10.6, 3), frame(3, 11.1, 1, category=6)]
    windows, n_frames = build_windows(records)

    assert n_frames == 3
    assert len(windows) == 1
    assert windows[0].destinations == frozenset({1, 3})
    assert windows[0].features["packet_count"] == 3.0
    assert windows[0].features["iat_mean"] == pytest.approx(0.5)
    assert windows[0].contains_dos


def test_model_features_exclude_labels_identity_direction_and_time():
    forbidden = {
        "categorized_attack", "specific_attack", "source", "destination",
        "timestamp", "bucket_index",
    }
    assert forbidden.isdisjoint(LAYER_A_FEATURES)


def test_contiguous_split_has_one_window_guard_at_each_boundary():
    train, validation, test = contiguous_blocks(100)
    assert (len(train), len(validation), len(test)) == (59, 18, 19)
    assert train[-1] == 58
    assert validation[0] == 61 and validation[-1] == 78
    assert test[0] == 81


def test_dos_cohort_excludes_other_attack_only_windows():
    windows = [synthetic_window(i) for i in range(100)]
    windows[82] = synthetic_window(82, normal=False, dos=True, value=10.0)
    windows[83] = synthetic_window(83, normal=False, value=10.0)
    result = run_layer_a_detector(windows)

    assert result.n_test_dos == 1
    assert result.n_test_normal == 17
    assert len(result.test_labels) == 18
    assert set(result.metrics) == {
        "precision", "recall", "f1", "fpr", "tn", "fp", "fn", "tp",
    }


def test_empty_windows_are_rejected():
    with pytest.raises(ValueError, match="no Layer A windows"):
        run_layer_a_detector([])
