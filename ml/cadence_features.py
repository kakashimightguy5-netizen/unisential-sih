#!/usr/bin/env python3
"""Query-type-aware egress cadence features for EXP-0007."""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from statistics import mean, median, pstdev
from typing import Iterable

import numpy as np

from features_txt import FrameRecord, iter_records
from layer_a_detector import contiguous_blocks

EGRESS_DESTINATION = 1
WINDOW_SECONDS = 5.0
MIN_FRAMES_PER_WINDOW = 2
DOS_CATEGORY = 6
CADENCE_SOURCE = 3
RESPONSE_TYPES = (0x03, 0x10)
CUSUM_ALLOWANCE = 0.5
AUDIT_MIN_FRAMES = 1_000
AUDIT_MIN_IATS = 200
AUDIT_MIN_WINDOWS = 100
AUDIT_MAX_WEIGHTED_CV_RATIO = 0.80

PER_TYPE_FEATURES = (
    "event_count", "iat_count", "iat_mean", "iat_std", "iat_max",
    "deviation_mean", "positive_deviation_mean", "positive_z_mean",
    "positive_z_max", "missed_cycles_sum", "missed_cycle_event_count",
    "cusum_end", "cusum_max", "cusum_alarm_count",
)
CADENCE_FEATURES = [
    f"func_{function_code:02x}_{name}"
    for function_code in RESPONSE_TYPES for name in PER_TYPE_FEATURES
] + [
    "cadence_event_count_total", "missed_cycles_sum_total",
    "cusum_alarm_count_total", "cusum_max_any_type", "active_type_count",
]


@dataclass(frozen=True)
class CadenceBaseline:
    function_code: int
    count: int
    expected_iat: float
    median_iat: float
    std_iat: float
    cv: float

    @property
    def scale(self) -> float:
        return max(self.std_iat, 1e-6, 0.01 * self.expected_iat)


@dataclass(frozen=True)
class CadenceWindow:
    bucket_index: int
    t_start: float
    features: dict[str, float]
    categories: frozenset[int]

    @property
    def is_pure_normal(self) -> bool:
        return self.categories == frozenset({0})

    @property
    def contains_dos(self) -> bool:
        return DOS_CATEGORY in self.categories


@dataclass
class CadenceDataset:
    windows: list[CadenceWindow]
    frames: list[FrameRecord]
    train: np.ndarray
    validation: np.ndarray
    test: np.ndarray
    baselines: dict[int, CadenceBaseline]
    thresholds: dict[int, float]
    audit: dict


def response_type(record: FrameRecord) -> int | None:
    """Return a fixed response-visible type, rejecting non-egress/ambiguous rows."""
    if record.destination != EGRESS_DESTINATION or record.source != CADENCE_SOURCE:
        return None
    expected_shape = {
        0x03: (0, 23, 18),
        0x10: (0, 8, -1),
    }.get(record.function_code)
    observed_shape = (record.is_request, record.frame_len_bytes, record.byte_count)
    return record.function_code if expected_shape == observed_shape else None


def _window_layout(records: list[FrameRecord]):
    buckets: dict[int, list[FrameRecord]] = defaultdict(list)
    for record in records:
        buckets[math.floor(record.timestamp / WINDOW_SECONDS)].append(record)
    emitted = sorted(
        bucket for bucket, values in buckets.items()
        if len(values) >= MIN_FRAMES_PER_WINDOW
    )
    position = {bucket: index for index, bucket in enumerate(emitted)}
    categories = {
        bucket: frozenset(record.categorized_attack for record in buckets[bucket])
        for bucket in emitted
    }
    train, validation, test = contiguous_blocks(len(emitted))
    return buckets, emitted, position, categories, train, validation, test


def _normal_gaps(
    records: list[FrameRecord], emitted: list[int], categories: dict[int, frozenset[int]],
    block: np.ndarray, key,
) -> dict[int | str, list[float]]:
    allowed = {emitted[index] for index in block}
    gaps: dict[int | str, list[float]] = defaultdict(list)
    previous: dict[int | str, float] = {}
    for record in records:
        if record.source != CADENCE_SOURCE:
            continue
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        stream = key(record)
        if bucket not in allowed or categories.get(bucket) != frozenset({0}):
            previous.clear()
            continue
        if stream in previous:
            gap = record.timestamp - previous[stream]
            if gap > 0:
                gaps[stream].append(gap)
        previous[stream] = record.timestamp
    return gaps


def _stats(function_code: int, gaps: list[float]) -> CadenceBaseline:
    expected = mean(gaps)
    deviation = pstdev(gaps)
    return CadenceBaseline(
        function_code=function_code, count=len(gaps), expected_iat=expected,
        median_iat=median(gaps), std_iat=deviation, cv=deviation / expected,
    )


def audit_response_types(records: Iterable[FrameRecord]) -> dict:
    """Run the frozen TRAIN/VALIDATION response-type sufficiency audit."""
    egress = sorted(
        (record for record in records if record.destination == EGRESS_DESTINATION),
        key=lambda record: (record.timestamp, record.record_index),
    )
    buckets, emitted, position, categories, train, validation, test = _window_layout(egress)
    blocks = {"train": train, "validation": validation}
    shapes = Counter(
        (record.function_code, record.is_request, record.frame_len_bytes, record.byte_count)
        for record in egress if record.source == CADENCE_SOURCE
        and record.categorized_attack == 0
    )
    expected_shapes = {(0x03, 0, 23, 18), (0x10, 0, 8, -1)}
    parser_certain = set(shapes) == expected_shapes

    support = {}
    for function_code in RESPONSE_TYPES:
        support[function_code] = {}
        for name, indices in blocks.items():
            index_set = set(indices.tolist())
            selected = [
                record for record in egress
                if record.source == CADENCE_SOURCE
                and record.function_code == function_code
                and position.get(math.floor(record.timestamp / WINDOW_SECONDS)) in index_set
            ]
            normal_windows = {
                math.floor(record.timestamp / WINDOW_SECONDS) for record in selected
                if categories[math.floor(record.timestamp / WINDOW_SECONDS)] == frozenset({0})
            }
            dos_windows = {
                math.floor(record.timestamp / WINDOW_SECONDS) for record in selected
                if DOS_CATEGORY in categories[math.floor(record.timestamp / WINDOW_SECONDS)]
            }
            support[function_code][name] = {
                "frames": len(selected), "normal_windows": len(normal_windows),
                "dos_windows": len(dos_windows),
            }

    pooled = _normal_gaps(egress, emitted, categories, train, lambda _: "pooled")["pooled"]
    typed = _normal_gaps(egress, emitted, categories, train, lambda record: record.function_code)
    pooled_mean, pooled_std = mean(pooled), pstdev(pooled)
    pooled_summary = {
        "count": len(pooled), "mean": pooled_mean, "median": median(pooled),
        "std": pooled_std, "cv": pooled_std / pooled_mean,
    }
    baselines = {code: _stats(code, typed[code]) for code in RESPONSE_TYPES}
    weighted_cv = sum(b.count * b.cv for b in baselines.values()) / sum(
        b.count for b in baselines.values()
    )
    reasons = []
    if not parser_certain:
        reasons.append("source-3 Normal response shapes are not exactly the two pre-registered shapes")
    for code, baseline in baselines.items():
        train_support = support[code]["train"]
        validation_support = support[code]["validation"]
        if train_support["frames"] < AUDIT_MIN_FRAMES:
            reasons.append(f"function 0x{code:02x} has insufficient TRAIN frames")
        if baseline.count < AUDIT_MIN_IATS:
            reasons.append(f"function 0x{code:02x} has insufficient TRAIN-normal IATs")
        if train_support["normal_windows"] < AUDIT_MIN_WINDOWS:
            reasons.append(f"function 0x{code:02x} has insufficient TRAIN-normal windows")
        for name, values in (("TRAIN", train_support), ("VALIDATION", validation_support)):
            if not values["normal_windows"] or not values["dos_windows"]:
                reasons.append(f"function 0x{code:02x} lacks {name} class overlap")
        if baseline.cv >= pooled_summary["cv"]:
            reasons.append(f"function 0x{code:02x} CV is not below pooled CV")
    weighted_ratio = weighted_cv / pooled_summary["cv"]
    if weighted_ratio > AUDIT_MAX_WEIGHTED_CV_RATIO:
        reasons.append("weighted split CV does not improve pooled CV by at least 20%")

    return {
        "status": "VALIDATED — AUDIT PASS" if not reasons else "STOPPED — AUDIT GATE",
        "passed": not reasons, "reasons": reasons,
        "scope": {"egress_frames": len(egress), "destinations": sorted({r.destination for r in egress})},
        "window_counts": {"total": len(emitted), "train": len(train),
                          "validation": len(validation), "test_unopened": len(test)},
        "response_field": "function_code", "normal_shapes": {
            f"0x{code:02x}/{request}/{length}/{byte_count}": count
            for (code, request, length, byte_count), count in sorted(shapes.items())
        },
        "support": {f"0x{code:02x}": values for code, values in support.items()},
        "pooled_train_normal": pooled_summary,
        "types_train_normal": {
            f"0x{code:02x}": {
                "count": baseline.count, "mean": baseline.expected_iat,
                "median": baseline.median_iat, "std": baseline.std_iat,
                "cv": baseline.cv,
            } for code, baseline in baselines.items()
        },
        "weighted_type_cv": weighted_cv, "weighted_to_pooled_cv_ratio": weighted_ratio,
    }


def _event_values(gap: float, baseline: CadenceBaseline) -> dict[str, float]:
    deviation = gap - baseline.expected_iat
    positive = max(0.0, deviation)
    missed = max(0, round(gap / baseline.expected_iat) - 1)
    return {
        "iat": gap, "deviation": deviation, "positive_deviation": positive,
        "positive_z": positive / baseline.scale, "missed_cycles": float(missed),
    }


def _replay_raw_cusum(
    records: list[FrameRecord], emitted: list[int], block: np.ndarray,
    baselines: dict[int, CadenceBaseline], thresholds: dict[int, float] | None,
):
    allowed = {emitted[index] for index in block}
    events: dict[int, dict[int, list[dict[str, float]]]] = defaultdict(lambda: defaultdict(list))
    states = {code: 0.0 for code in RESPONSE_TYPES}
    previous: dict[int, float] = {}
    for record in records:
        code = response_type(record)
        if code is None:
            continue
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        if bucket not in allowed:
            previous.pop(code, None)
            states[code] = 0.0
            continue
        values = None
        if code in previous:
            gap = record.timestamp - previous[code]
            if gap > 0:
                values = _event_values(gap, baselines[code])
                state = max(0.0, states[code] + values["positive_z"] - CUSUM_ALLOWANCE)
                alarm = bool(thresholds is not None and state >= thresholds[code])
                values.update({"cusum": state, "alarm": float(alarm)})
                states[code] = 0.0 if alarm else state
        previous[code] = record.timestamp
        event = {"event": 1.0, "cusum_end": states[code]}
        if values is not None:
            event.update(values)
        events[bucket][code].append(event)
    return events


def _thresholds(
    records: list[FrameRecord], emitted: list[int], categories: dict[int, frozenset[int]],
    train: np.ndarray, baselines: dict[int, CadenceBaseline],
) -> dict[int, float]:
    allowed = {emitted[index] for index in train}
    states = {code: 0.0 for code in RESPONSE_TYPES}
    previous: dict[int, float] = {}
    maxima: dict[int, dict[int, float]] = defaultdict(dict)
    for record in records:
        code = response_type(record)
        if code is None:
            continue
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        if bucket not in allowed or categories.get(bucket) != frozenset({0}):
            previous.clear()
            states = {item: 0.0 for item in RESPONSE_TYPES}
            continue
        if code in previous:
            gap = record.timestamp - previous[code]
            if gap > 0:
                values = _event_values(gap, baselines[code])
                states[code] = max(
                    0.0, states[code] + values["positive_z"] - CUSUM_ALLOWANCE
                )
                maxima[code][bucket] = max(maxima[code].get(bucket, 0.0), states[code])
        previous[code] = record.timestamp

    output = {}
    for code in RESPONSE_TYPES:
        window_maxima = [maxima[code].get(emitted[index], 0.0) for index in train]
        output[code] = max(
            CUSUM_ALLOWANCE,
            float(np.quantile(window_maxima, 0.99, method="higher")),
        )
    return output


def _aggregate_type(events: list[dict[str, float]], current_state: float) -> dict[str, float]:
    gaps = [event for event in events if "iat" in event]
    iats = [event["iat"] for event in gaps]
    def avg(name: str) -> float:
        return mean(event[name] for event in gaps) if gaps else 0.0
    return {
        "event_count": float(len(events)), "iat_count": float(len(gaps)),
        "iat_mean": mean(iats) if iats else 0.0,
        "iat_std": pstdev(iats) if len(iats) > 1 else 0.0,
        "iat_max": max(iats, default=0.0), "deviation_mean": avg("deviation"),
        "positive_deviation_mean": avg("positive_deviation"),
        "positive_z_mean": avg("positive_z"),
        "positive_z_max": max((event["positive_z"] for event in gaps), default=0.0),
        "missed_cycles_sum": sum(event["missed_cycles"] for event in gaps),
        "missed_cycle_event_count": float(sum(event["missed_cycles"] > 0 for event in gaps)),
        "cusum_end": events[-1]["cusum_end"] if events else current_state,
        "cusum_max": max((event.get("cusum", current_state) for event in events), default=current_state),
        "cusum_alarm_count": sum(event.get("alarm", 0.0) for event in events),
    }


def build_cadence_dataset(records: Iterable[FrameRecord] | None = None) -> CadenceDataset:
    """Build frozen EXP-0007 features after enforcing the audit gate."""
    all_records = list(iter_records() if records is None else records)
    audit = audit_response_types(all_records)
    if not audit["passed"]:
        raise ValueError("response-type audit failed: " + "; ".join(audit["reasons"]))
    egress = sorted(
        (record for record in all_records if record.destination == EGRESS_DESTINATION),
        key=lambda record: (record.timestamp, record.record_index),
    )
    buckets, emitted, _, categories, train, validation, test = _window_layout(egress)
    typed = _normal_gaps(egress, emitted, categories, train, lambda record: record.function_code)
    baselines = {code: _stats(code, typed[code]) for code in RESPONSE_TYPES}
    thresholds = _thresholds(egress, emitted, categories, train, baselines)
    block_events = {}
    for name, block in (("train", train), ("validation", validation), ("test", test)):
        block_events[name] = _replay_raw_cusum(egress, emitted, block, baselines, thresholds)

    block_by_index = {index: name for name, block in (
        ("train", train), ("validation", validation), ("test", test)
    ) for index in block}
    states = {name: {code: 0.0 for code in RESPONSE_TYPES} for name in block_events}
    windows = []
    for index, bucket in enumerate(emitted):
        name = block_by_index.get(index)
        features = {feature: 0.0 for feature in CADENCE_FEATURES}
        if name is not None:
            active = 0
            for code in RESPONSE_TYPES:
                values = block_events[name][bucket].get(code, [])
                aggregate = _aggregate_type(values, states[name][code])
                states[name][code] = aggregate["cusum_end"]
                if aggregate["event_count"]:
                    active += 1
                for feature, value in aggregate.items():
                    features[f"func_{code:02x}_{feature}"] = float(value)
            features["cadence_event_count_total"] = sum(
                features[f"func_{code:02x}_event_count"] for code in RESPONSE_TYPES
            )
            features["missed_cycles_sum_total"] = sum(
                features[f"func_{code:02x}_missed_cycles_sum"] for code in RESPONSE_TYPES
            )
            features["cusum_alarm_count_total"] = sum(
                features[f"func_{code:02x}_cusum_alarm_count"] for code in RESPONSE_TYPES
            )
            features["cusum_max_any_type"] = max(
                features[f"func_{code:02x}_cusum_max"] for code in RESPONSE_TYPES
            )
            features["active_type_count"] = float(active)
        windows.append(CadenceWindow(
            bucket_index=bucket, t_start=bucket * WINDOW_SECONDS,
            features=features, categories=categories[bucket],
        ))
    return CadenceDataset(
        windows=windows, frames=egress, train=train, validation=validation, test=test,
        baselines=baselines, thresholds=thresholds, audit=audit,
    )
