"""Synthetic integrity proofs for EXP-0008 cadence features."""
from dataclasses import replace
from inspect import signature
from types import MappingProxyType

import numpy as np
import pytest

from exp0008_cadence_features import (
    AUDIT_MIN_FRAMES, CUSUM_ALLOWANCE, BlockData, CadenceBaseline,
    _contiguous_blocks, audit_response_types, build_scoring_windows,
    calculate_baselines, calibrate_cusum_thresholds, canonical_response_type,
    discover_response_types, replay_cusum,
)
from features_txt import FrameRecord


def record(
    index, timestamp, *, function=3, source=3, destination=1, category=0,
    frame_len=None, byte_count=None, length_anomaly=0,
):
    shape = {3: (23, 18), 16: (8, -1)}.get(function, (11, 6))
    return FrameRecord(
        record_index=index, frame_id=index, address=4, function_code=function,
        frame_len_bytes=shape[0] if frame_len is None else frame_len,
        is_request=0, start_register=-1, quantity=-1,
        byte_count=shape[1] if byte_count is None else byte_count,
        length_anomaly=length_anomaly, rare_function_code=0, crc_ok=0,
        interarrival_seconds=0.0, message_entropy_bits_per_byte=0.0,
        categorized_attack=category, specific_attack=0, source=source,
        destination=destination, timestamp=timestamp,
    )


def block(name, rows, category_by_bucket):
    buckets = tuple(sorted(category_by_bucket))
    return BlockData(
        name=name, records=tuple(sorted(rows, key=lambda item: item.timestamp)),
        emitted_buckets=buckets,
        categories=MappingProxyType({
            bucket_index: frozenset(categories)
            for bucket_index, categories in category_by_bucket.items()
        }),
    )


def frozen_map():
    return MappingProxyType({
        (3, 0, 23, 18, 0): 3,
        (16, 0, 8, -1, 0): 16,
    })


def baseline(function=3, expected=2.0, deviation=0.5):
    return CadenceBaseline(
        function, 10, expected, expected, deviation, deviation / expected,
    )


def test_train_discovery_is_exact_immutable_and_rejects_noncanonical_frames():
    train = block("train", [
        record(1, 0.1), record(2, 0.2, function=16),
        record(3, 5.1, function=99, category=6),
        record(4, 5.2, destination=3, category=6),
    ], {0: {0}, 1: {6}})
    type_map = discover_response_types(train)
    assert dict(type_map) == dict(frozen_map())
    with pytest.raises(TypeError):
        type_map[(99, 0, 11, 6, 0)] = 99
    assert canonical_response_type(record(5, 1.0), type_map) == 3
    assert canonical_response_type(record(6, 1.0, destination=3), type_map) is None
    assert canonical_response_type(record(7, 1.0, source=2), type_map) is None
    assert canonical_response_type(record(8, 1.0, frame_len=22), type_map) is None


def test_sufficiency_gate_counts_exactly_train_normal_canonical_frames():
    normal_count = AUDIT_MIN_FRAMES - 1
    rows = [record(i, i * 0.001) for i in range(normal_count)]
    rows.extend(
        record(normal_count + i, 5.0 + i * 0.001, category=6)
        for i in range(20)
    )
    train = block("train", rows, {0: {0}, 1: {6}})
    validation = block("validation", [
        record(20_000, 10.1), record(20_001, 10.2, category=6),
    ], {2: {0, 6}})
    audit = audit_response_types(train, validation, frozen_map())
    assert len(rows) >= AUDIT_MIN_FRAMES
    assert audit["support"]["0x03"]["train"]["normal_frames"] == normal_count
    assert "type 0x03 has insufficient TRAIN-normal frames" in audit["reasons"]


def test_all_four_stages_share_and_call_the_same_canonical_mapper_object():
    stages = (
        audit_response_types, calculate_baselines,
        calibrate_cusum_thresholds, build_scoring_windows,
    )
    assert all(
        signature(stage).parameters["mapper"].default is canonical_response_type
        for stage in stages
    )

    rows = [record(1, 0.1), record(2, 2.1), record(3, 4.1)]
    train = block("train", rows, {0: {0}})
    validation = block("validation", rows, {0: {0}})
    baselines = {3: baseline(), 16: baseline(16)}
    thresholds = {3: 1.0, 16: 1.0}
    calls = []

    def spy(item, mapping):
        calls.append(item.record_index)
        return canonical_response_type(item, mapping)

    audit_response_types(train, validation, frozen_map(), mapper=spy)
    assert calls
    calls.clear()
    calculate_baselines(train, frozen_map(), mapper=spy)
    assert calls
    calls.clear()
    calibrate_cusum_thresholds(train, frozen_map(), baselines, mapper=spy)
    assert calls
    calls.clear()
    build_scoring_windows(train, frozen_map(), baselines, thresholds, mapper=spy)
    assert calls


def test_calibration_and_scoring_call_the_same_replay_function(monkeypatch):
    rows = [record(1, 0.1), record(2, 2.1), record(3, 4.1)]
    train = block("train", rows, {0: {0}})
    baselines = {3: baseline(), 16: baseline(16)}
    original = replay_cusum
    calls = []

    def spy(*args, **kwargs):
        calls.append(kwargs.get("thresholds"))
        return original(*args, **kwargs)

    monkeypatch.setattr("exp0008_cadence_features.replay_cusum", spy)
    thresholds = calibrate_cusum_thresholds(train, frozen_map(), baselines)
    build_scoring_windows(train, frozen_map(), baselines, thresholds)
    assert calls == [None, thresholds]


def test_cusum_state_is_label_independent_and_alarm_does_not_reset():
    rows = [
        record(1, 0.1), record(2, 3.1),
        record(3, 5.1, category=6), record(4, 8.1, category=6),
    ]
    labelled = block("train", rows, {0: {0}, 1: {6}})
    relabelled = block("train", rows, {0: {0}, 1: {0}})
    baselines = {3: baseline(), 16: baseline(16)}
    threshold = {3: 1.0, 16: 1.0}
    left = replay_cusum(labelled, frozen_map(), baselines, threshold)
    right = replay_cusum(relabelled, frozen_map(), baselines, threshold)
    assert left == right
    assert left[0][3][-1]["cusum"] == pytest.approx(1.5)
    assert left[1][3][-1]["cusum"] == pytest.approx(2.5)
    assert left[1][3][-1]["alarm"] == 1.0
    assert left[1][3][-1]["cusum_end"] == pytest.approx(2.5)


def test_contiguous_split_keeps_one_window_guard_at_each_boundary():
    train, validation, test = _contiguous_blocks(100)
    assert train[-1] == 58
    assert validation[0] == 61 and validation[-1] == 78
    assert test[0] == 81
    assert set(range(100)) - set(np.concatenate((train, validation, test))) == {59, 60, 79, 80}
