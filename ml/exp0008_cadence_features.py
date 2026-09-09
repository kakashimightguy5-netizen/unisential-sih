#!/usr/bin/env python3
"""Leakage-controlled egress cadence features for EXP-0008."""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from statistics import mean, median, pstdev
from types import MappingProxyType
from typing import Callable, Iterable, Mapping

import numpy as np

from features_txt import FrameRecord, iter_records

EGRESS_DESTINATION = 1
CADENCE_SOURCE = 3
DOS_CATEGORY = 6
WINDOW_SECONDS = 5.0
MIN_FRAMES_PER_WINDOW = 2
TRAIN_FRAC = 0.60
VALIDATION_FRAC = 0.20
GUARD_WINDOWS = 1
CUSUM_ALLOWANCE = 0.5
AUDIT_MIN_FRAMES = 1_000
AUDIT_MIN_IATS = 200
AUDIT_MIN_WINDOWS = 100
AUDIT_MAX_WEIGHTED_CV_RATIO = 0.80

Shape = tuple[int, int, int, int, int]
TypeMap = Mapping[Shape, int]
Mapper = Callable[[FrameRecord, TypeMap], int | None]

PER_TYPE_FEATURES = (
    "event_count", "iat_count", "iat_mean", "iat_std", "iat_max",
    "deviation_mean", "positive_deviation_mean", "positive_z_mean",
    "positive_z_max", "missed_cycles_sum", "missed_cycle_event_count",
    "cusum_end", "cusum_max", "cusum_alarm_count",
)
AGGREGATE_FEATURES = (
    "cadence_event_count_total", "missed_cycles_sum_total",
    "cusum_alarm_count_total", "cusum_max_any_type", "active_type_count",
)


@dataclass(frozen=True)
class CadenceBaseline:
    response_type: int
    count: int
    expected_iat: float
    median_iat: float
    std_iat: float
    cv: float

    @property
    def scale(self) -> float:
        return max(self.std_iat, 1e-6, 0.01 * self.expected_iat)


@dataclass(frozen=True)
class BlockData:
    name: str
    records: tuple[FrameRecord, ...]
    emitted_buckets: tuple[int, ...]
    categories: Mapping[int, frozenset[int]]


@dataclass(frozen=True)
class PreTestInputs:
    train: BlockData
    validation: BlockData
    total_egress_frames: int
    total_emitted_windows: int
    train_window_count: int
    validation_window_count: int
    test_window_count: int


@dataclass(frozen=True)
class CadenceWindow:
    bucket_index: int
    features: Mapping[str, float]
    categories: frozenset[int]

    @property
    def is_pure_normal(self) -> bool:
        return self.categories == frozenset({0})

    @property
    def contains_dos(self) -> bool:
        return DOS_CATEGORY in self.categories


@dataclass(frozen=True)
class PreTestArtifacts:
    inputs: PreTestInputs
    type_map: TypeMap
    response_types: tuple[int, ...]
    audit: Mapping
    baselines: Mapping[int, CadenceBaseline]
    thresholds: Mapping[int, float]
    feature_names: tuple[str, ...]
    train_windows: tuple[CadenceWindow, ...]
    validation_windows: tuple[CadenceWindow, ...]


def _shape(record: FrameRecord) -> Shape:
    return (
        record.function_code, record.is_request, record.frame_len_bytes,
        record.byte_count, record.length_anomaly,
    )


def canonical_response_type(record: FrameRecord, type_map: TypeMap) -> int | None:
    """Map one parser-certain source-3 egress frame through the frozen TRAIN map."""
    if record.destination != EGRESS_DESTINATION or record.source != CADENCE_SOURCE:
        return None
    return type_map.get(_shape(record))


def _contiguous_blocks(n: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    first = int(n * TRAIN_FRAC)
    second = int(n * (TRAIN_FRAC + VALIDATION_FRAC))
    return (
        np.arange(0, first - GUARD_WINDOWS),
        np.arange(first + GUARD_WINDOWS, second - GUARD_WINDOWS),
        np.arange(second + GUARD_WINDOWS, n),
    )


def partition_pretest_inputs(
    records: Iterable[FrameRecord] | None = None,
) -> PreTestInputs:
    """Partition by egress window layout while retaining no TEST record values."""
    egress = sorted(
        (
            record for record in (iter_records() if records is None else records)
            if record.destination == EGRESS_DESTINATION
        ),
        key=lambda record: (record.timestamp, record.record_index),
    )
    buckets: dict[int, list[FrameRecord]] = defaultdict(list)
    for record in egress:
        buckets[math.floor(record.timestamp / WINDOW_SECONDS)].append(record)
    emitted = tuple(sorted(
        bucket for bucket, values in buckets.items()
        if len(values) >= MIN_FRAMES_PER_WINDOW
    ))
    train_indices, validation_indices, test_indices = _contiguous_blocks(len(emitted))

    def make_block(name: str, indices: np.ndarray) -> BlockData:
        selected = tuple(emitted[index] for index in indices)
        if not selected:
            return BlockData(name, (), (), MappingProxyType({}))
        low, high = selected[0], selected[-1]
        block_records = tuple(
            record for record in egress
            if low <= math.floor(record.timestamp / WINDOW_SECONDS) <= high
        )
        categories = MappingProxyType({
            bucket: frozenset(record.categorized_attack for record in buckets[bucket])
            for bucket in selected
        })
        return BlockData(name, block_records, selected, categories)

    return PreTestInputs(
        train=make_block("train", train_indices),
        validation=make_block("validation", validation_indices),
        total_egress_frames=len(egress), total_emitted_windows=len(emitted),
        train_window_count=len(train_indices),
        validation_window_count=len(validation_indices),
        test_window_count=len(test_indices),
    )


def discover_response_types(train: BlockData) -> TypeMap:
    """Discover immutable exact shapes from TRAIN pure-Normal rows only."""
    allowed = set(train.emitted_buckets)
    shapes = {
        _shape(record) for record in train.records
        if math.floor(record.timestamp / WINDOW_SECONDS) in allowed
        and train.categories[math.floor(record.timestamp / WINDOW_SECONDS)] == frozenset({0})
        and record.destination == EGRESS_DESTINATION
        and record.source == CADENCE_SOURCE
    }
    ordered = sorted(shapes)
    return MappingProxyType({shape: shape[0] for shape in ordered})


def _normal_gaps(
    block: BlockData, type_map: TypeMap, *, pooled: bool = False,
    mapper: Mapper = canonical_response_type,
) -> dict[int | str, list[float]]:
    emitted = set(block.emitted_buckets)
    previous: dict[int | str, float] = {}
    gaps: dict[int | str, list[float]] = defaultdict(list)
    for record in block.records:
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        response_type = mapper(record, type_map)
        if (
            bucket not in emitted
            or block.categories[bucket] != frozenset({0})
        ):
            previous.clear()
            continue
        if response_type is None:
            continue
        stream: int | str = "pooled" if pooled else response_type
        if stream in previous:
            gap = record.timestamp - previous[stream]
            if gap > 0:
                gaps[stream].append(gap)
        previous[stream] = record.timestamp
    return gaps


def _baseline(response_type: int, gaps: list[float]) -> CadenceBaseline:
    expected = mean(gaps)
    deviation = pstdev(gaps)
    return CadenceBaseline(
        response_type=response_type, count=len(gaps), expected_iat=expected,
        median_iat=median(gaps), std_iat=deviation, cv=deviation / expected,
    )


def calculate_baselines(
    train: BlockData, type_map: TypeMap,
    mapper: Mapper = canonical_response_type,
) -> Mapping[int, CadenceBaseline]:
    """Fit per-type baselines from canonical TRAIN-normal gaps."""
    response_types = tuple(sorted(set(type_map.values())))
    gaps = _normal_gaps(train, type_map, mapper=mapper)
    return MappingProxyType({
        response_type: _baseline(response_type, gaps[response_type])
        for response_type in response_types if gaps[response_type]
    })


def audit_response_types(
    train: BlockData, validation: BlockData, type_map: TypeMap,
    mapper: Mapper = canonical_response_type,
) -> dict:
    """Apply the frozen TRAIN support/tightening and VALIDATION overlap gate."""
    response_types = tuple(sorted(set(type_map.values())))
    support: dict[int, dict[str, dict[str, int]]] = {}
    for response_type in response_types:
        support[response_type] = {}
        for block in (train, validation):
            normal_frames = 0
            normal_windows: set[int] = set()
            dos_windows: set[int] = set()
            for record in block.records:
                bucket = math.floor(record.timestamp / WINDOW_SECONDS)
                if bucket not in block.categories:
                    continue
                if mapper(record, type_map) != response_type:
                    continue
                categories = block.categories[bucket]
                if categories == frozenset({0}):
                    normal_frames += 1
                    normal_windows.add(bucket)
                if DOS_CATEGORY in categories:
                    dos_windows.add(bucket)
            support[response_type][block.name] = {
                "normal_frames": normal_frames,
                "normal_windows": len(normal_windows),
                "dos_windows": len(dos_windows),
            }

    typed_gaps = _normal_gaps(train, type_map, mapper=mapper)
    pooled_gaps = _normal_gaps(train, type_map, pooled=True, mapper=mapper)["pooled"]
    reasons: list[str] = []
    if len(type_map) != 2 or len(response_types) != 2:
        reasons.append("TRAIN pure-Normal discovery did not yield exactly two unique parser-certain types")
    if not pooled_gaps:
        reasons.append("pooled TRAIN-normal canonical population has no eligible IATs")

    baselines: dict[int, CadenceBaseline] = {}
    for response_type in response_types:
        gaps = typed_gaps[response_type]
        train_support = support[response_type]["train"]
        validation_support = support[response_type]["validation"]
        if train_support["normal_frames"] < AUDIT_MIN_FRAMES:
            reasons.append(f"type 0x{response_type:02x} has insufficient TRAIN-normal frames")
        if len(gaps) < AUDIT_MIN_IATS:
            reasons.append(f"type 0x{response_type:02x} has insufficient TRAIN-normal IATs")
        if train_support["normal_windows"] < AUDIT_MIN_WINDOWS:
            reasons.append(f"type 0x{response_type:02x} has insufficient TRAIN-normal windows")
        for name, values in (("TRAIN", train_support), ("VALIDATION", validation_support)):
            if not values["normal_windows"] or not values["dos_windows"]:
                reasons.append(f"type 0x{response_type:02x} lacks {name} class overlap")
        if gaps:
            baselines[response_type] = _baseline(response_type, gaps)

    pooled_summary = None
    weighted_cv = None
    weighted_ratio = None
    if pooled_gaps:
        pooled_expected = mean(pooled_gaps)
        pooled_std = pstdev(pooled_gaps)
        pooled_cv = pooled_std / pooled_expected
        pooled_summary = {
            "count": len(pooled_gaps), "mean": pooled_expected,
            "median": median(pooled_gaps), "std": pooled_std, "cv": pooled_cv,
        }
        for response_type, baseline in baselines.items():
            if baseline.cv >= pooled_cv:
                reasons.append(f"type 0x{response_type:02x} CV is not below pooled CV")
        if baselines:
            total = sum(item.count for item in baselines.values())
            weighted_cv = sum(item.count * item.cv for item in baselines.values()) / total
            weighted_ratio = weighted_cv / pooled_cv
            if weighted_ratio > AUDIT_MAX_WEIGHTED_CV_RATIO:
                reasons.append("weighted type CV does not improve pooled CV by at least 20%")

    return {
        "status": "VALIDATED — AUDIT PASS" if not reasons else "STOPPED — AUDIT GATE",
        "passed": not reasons, "reasons": reasons,
        "discovery_population": "TRAIN pure-Normal source-3 egress frames only",
        "type_shapes": {
            f"0x{response_type:02x}": [list(shape) for shape, mapped in type_map.items()
                                     if mapped == response_type]
            for response_type in response_types
        },
        "support": {
            f"0x{response_type:02x}": values
            for response_type, values in support.items()
        },
        "pooled_train_normal": pooled_summary,
        "types_train_normal": {
            f"0x{response_type:02x}": {
                "count": baseline.count, "mean": baseline.expected_iat,
                "median": baseline.median_iat, "std": baseline.std_iat,
                "cv": baseline.cv,
            } for response_type, baseline in baselines.items()
        },
        "weighted_type_cv": weighted_cv,
        "weighted_to_pooled_cv_ratio": weighted_ratio,
    }


def _event_values(gap: float, baseline: CadenceBaseline) -> dict[str, float]:
    deviation = gap - baseline.expected_iat
    positive = max(0.0, deviation)
    return {
        "iat": gap, "deviation": deviation, "positive_deviation": positive,
        "positive_z": positive / baseline.scale,
        "missed_cycles": float(max(0, round(gap / baseline.expected_iat) - 1)),
    }


def replay_cusum(
    block: BlockData, type_map: TypeMap,
    baselines: Mapping[int, CadenceBaseline],
    thresholds: Mapping[int, float] | None = None,
    mapper: Mapper = canonical_response_type,
) -> Mapping[int, Mapping[int, tuple[Mapping[str, float], ...]]]:
    """Replay the one EXP-0008 state process; labels never alter its trajectory."""
    response_types = tuple(sorted(baselines))
    states = {response_type: 0.0 for response_type in response_types}
    previous: dict[int, float] = {}
    emitted = set(block.emitted_buckets)
    mutable: dict[int, dict[int, list[dict[str, float]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for record in block.records:
        response_type = mapper(record, type_map)
        if response_type not in baselines:
            continue
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        values: dict[str, float] = {
            "event": 1.0, "cusum": states[response_type],
            "cusum_end": states[response_type], "alarm": 0.0,
        }
        if response_type in previous:
            gap = record.timestamp - previous[response_type]
            if gap > 0:
                values.update(_event_values(gap, baselines[response_type]))
                states[response_type] = max(
                    0.0,
                    states[response_type] + values["positive_z"] - CUSUM_ALLOWANCE,
                )
                values["cusum"] = states[response_type]
                values["cusum_end"] = states[response_type]
                values["alarm"] = float(
                    thresholds is not None
                    and states[response_type] >= thresholds[response_type]
                )
        previous[response_type] = record.timestamp
        if bucket in emitted:
            mutable[bucket][response_type].append(values)
    return MappingProxyType({
        bucket: MappingProxyType({
            response_type: tuple(events)
            for response_type, events in by_type.items()
        }) for bucket, by_type in mutable.items()
    })


def calibrate_cusum_thresholds(
    train: BlockData, type_map: TypeMap,
    baselines: Mapping[int, CadenceBaseline],
    mapper: Mapper = canonical_response_type,
) -> Mapping[int, float]:
    """Calibrate on TRAIN-normal maxima from the shared replay path."""
    replay = replay_cusum(train, type_map, baselines, mapper=mapper)
    output: dict[int, float] = {}
    for response_type in baselines:
        maxima = []
        for bucket in train.emitted_buckets:
            if train.categories[bucket] != frozenset({0}):
                continue
            events = replay.get(bucket, {}).get(response_type, ())
            maxima.append(max((event["cusum"] for event in events), default=0.0))
        output[response_type] = max(
            CUSUM_ALLOWANCE,
            float(np.quantile(maxima, 0.99, method="higher")),
        )
    return MappingProxyType(output)


def feature_names_for(response_types: Iterable[int]) -> tuple[str, ...]:
    return tuple(
        f"func_{response_type:02x}_{name}"
        for response_type in sorted(response_types) for name in PER_TYPE_FEATURES
    ) + AGGREGATE_FEATURES


def _aggregate(events: tuple[Mapping[str, float], ...]) -> dict[str, float]:
    gaps = [event for event in events if "iat" in event]
    iats = [event["iat"] for event in gaps]

    def average(name: str) -> float:
        return mean(event[name] for event in gaps) if gaps else 0.0

    return {
        "event_count": float(len(events)), "iat_count": float(len(gaps)),
        "iat_mean": mean(iats) if iats else 0.0,
        "iat_std": pstdev(iats) if len(iats) > 1 else 0.0,
        "iat_max": max(iats, default=0.0),
        "deviation_mean": average("deviation"),
        "positive_deviation_mean": average("positive_deviation"),
        "positive_z_mean": average("positive_z"),
        "positive_z_max": max((event["positive_z"] for event in gaps), default=0.0),
        "missed_cycles_sum": sum(event["missed_cycles"] for event in gaps),
        "missed_cycle_event_count": float(sum(event["missed_cycles"] > 0 for event in gaps)),
        "cusum_end": events[-1]["cusum_end"] if events else 0.0,
        "cusum_max": max((event["cusum"] for event in events), default=0.0),
        "cusum_alarm_count": sum(event["alarm"] for event in events),
    }


def build_scoring_windows(
    block: BlockData, type_map: TypeMap,
    baselines: Mapping[int, CadenceBaseline], thresholds: Mapping[int, float],
    mapper: Mapper = canonical_response_type,
) -> tuple[CadenceWindow, ...]:
    """Build frozen features via the canonical mapper and shared CUSUM replay."""
    response_types = tuple(sorted(baselines))
    names = feature_names_for(response_types)
    replay = replay_cusum(
        block, type_map, baselines, thresholds=thresholds, mapper=mapper,
    )
    windows: list[CadenceWindow] = []
    for bucket in block.emitted_buckets:
        features = {name: 0.0 for name in names}
        active = 0
        for response_type in response_types:
            aggregate = _aggregate(replay.get(bucket, {}).get(response_type, ()))
            if aggregate["event_count"]:
                active += 1
            for name, value in aggregate.items():
                features[f"func_{response_type:02x}_{name}"] = float(value)
        features["cadence_event_count_total"] = sum(
            features[f"func_{response_type:02x}_event_count"]
            for response_type in response_types
        )
        features["missed_cycles_sum_total"] = sum(
            features[f"func_{response_type:02x}_missed_cycles_sum"]
            for response_type in response_types
        )
        features["cusum_alarm_count_total"] = sum(
            features[f"func_{response_type:02x}_cusum_alarm_count"]
            for response_type in response_types
        )
        features["cusum_max_any_type"] = max(
            (features[f"func_{response_type:02x}_cusum_max"] for response_type in response_types),
            default=0.0,
        )
        features["active_type_count"] = float(active)
        windows.append(CadenceWindow(
            bucket_index=bucket, features=MappingProxyType(features),
            categories=block.categories[bucket],
        ))
    return tuple(windows)


def prepare_pretest_artifacts(
    records: Iterable[FrameRecord] | None = None,
) -> PreTestArtifacts:
    """Create all frozen artifacts without retaining or scoring TEST records."""
    inputs = partition_pretest_inputs(records)
    type_map = discover_response_types(inputs.train)
    audit = audit_response_types(inputs.train, inputs.validation, type_map)
    if not audit["passed"]:
        raise ValueError("response-type audit failed: " + "; ".join(audit["reasons"]))
    baselines = calculate_baselines(inputs.train, type_map)
    thresholds = calibrate_cusum_thresholds(inputs.train, type_map, baselines)
    response_types = tuple(sorted(baselines))
    return PreTestArtifacts(
        inputs=inputs, type_map=type_map, response_types=response_types,
        audit=MappingProxyType(audit), baselines=baselines, thresholds=thresholds,
        feature_names=feature_names_for(response_types),
        train_windows=build_scoring_windows(
            inputs.train, type_map, baselines, thresholds,
        ),
        validation_windows=build_scoring_windows(
            inputs.validation, type_map, baselines, thresholds,
        ),
    )
