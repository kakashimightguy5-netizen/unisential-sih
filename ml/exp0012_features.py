#!/usr/bin/env python3
"""Strictly causal prior-window lag and trend features for EXP-0012."""
from __future__ import annotations

from statistics import pvariance
from types import MappingProxyType
from typing import Iterable, Sequence

import numpy as np

from exp0008_cadence_features import CadenceWindow

HISTORY_WINDOWS = 5
DEVIATION_FEATURES = (
    "func_03_deviation_mean",
    "func_10_deviation_mean",
)


def _prefix(deviation_name: str) -> str:
    return deviation_name.removesuffix("_deviation_mean") + "_deviation"


def lag_feature_names(
    deviation_features: Iterable[str] = DEVIATION_FEATURES,
) -> tuple[str, ...]:
    names: list[str] = []
    for deviation_name in deviation_features:
        prefix = _prefix(deviation_name)
        names.extend(f"{prefix}_lag_{lag}" for lag in range(1, HISTORY_WINDOWS + 1))
        names.extend((
            f"{prefix}_prior_5_slope",
            f"{prefix}_prior_5_direction",
            f"{prefix}_prior_5_variance",
        ))
    return tuple(names)


LAG_FEATURE_NAMES = lag_feature_names()


def _trend(values: Sequence[float]) -> tuple[float, float, float]:
    """Summarize five chronologically ordered prior values."""
    slope = float(np.polyfit(np.arange(len(values), dtype=float), values, 1)[0])
    direction = float((slope > 0.0) - (slope < 0.0))
    return slope, direction, float(pvariance(values))


def augment_sequence(
    windows: Sequence[CadenceWindow],
    deviation_features: Sequence[str] = DEVIATION_FEATURES,
) -> tuple[tuple[CadenceWindow, ...], int]:
    """Add history from prior windows only; exclude the first five rows."""
    augmented: list[CadenceWindow] = []
    for index in range(HISTORY_WINDOWS, len(windows)):
        current = windows[index]
        features = dict(current.features)
        for deviation_name in deviation_features:
            chronological = [
                float(windows[prior].features[deviation_name])
                for prior in range(index - HISTORY_WINDOWS, index)
            ]
            prefix = _prefix(deviation_name)
            for lag in range(1, HISTORY_WINDOWS + 1):
                features[f"{prefix}_lag_{lag}"] = chronological[-lag]
            slope, direction, variance = _trend(chronological)
            features[f"{prefix}_prior_5_slope"] = slope
            features[f"{prefix}_prior_5_direction"] = direction
            features[f"{prefix}_prior_5_variance"] = variance
        augmented.append(CadenceWindow(
            bucket_index=current.bucket_index,
            features=MappingProxyType(features),
            categories=current.categories,
        ))
    return tuple(augmented), min(HISTORY_WINDOWS, len(windows))


def augment_sequences(
    sequences: Iterable[Sequence[CadenceWindow]],
    deviation_features: Sequence[str] = DEVIATION_FEATURES,
) -> tuple[tuple[CadenceWindow, ...], int]:
    """Augment independent blocks without carrying history between them."""
    output: list[CadenceWindow] = []
    excluded = 0
    for sequence in sequences:
        augmented, sequence_excluded = augment_sequence(sequence, deviation_features)
        output.extend(augmented)
        excluded += sequence_excluded
    return tuple(output), excluded
