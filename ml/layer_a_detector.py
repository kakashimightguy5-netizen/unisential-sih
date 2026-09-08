#!/usr/bin/env python3
"""EXP-0005 pre-diode bidirectional DoS detector proof of concept."""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from features_txt import FrameRecord, iter_records

WINDOW_SECONDS = 5.0
MIN_FRAMES_PER_WINDOW = 2
TRAIN_FRAC = 0.60
VAL_FRAC = 0.20
GUARD_WINDOWS = 1
TARGET_FPR = 0.01
SEED = 0
DOS_CATEGORY = 6
RESULT_PATH = Path(__file__).resolve().parent.parent / "data" / "experiments" / "exp0005_layer_a_metrics.json"

LAYER_A_FEATURES = [
    "packet_count", "packets_per_sec", "bytes_per_sec", "mean_frame_len",
    "iat_mean", "iat_std", "iat_min", "iat_max", "frac_func_read",
    "frac_func_write", "rare_func_rate", "distinct_frame_ratio",
    "repeat_frame_rate", "payload_entropy_mean", "payload_entropy_std",
]


@dataclass(frozen=True)
class LayerAWindow:
    bucket_index: int
    t_start: float
    features: dict[str, float]
    categories: frozenset[int]
    destinations: frozenset[int]

    @property
    def is_pure_normal(self) -> bool:
        return self.categories == frozenset({0})

    @property
    def contains_dos(self) -> bool:
        return DOS_CATEGORY in self.categories


@dataclass
class LayerAResult:
    n_frames: int
    destinations: frozenset[int]
    n_windows: int
    n_train: int
    n_val: int
    n_test: int
    n_train_normal: int
    n_val_normal: int
    n_test_normal: int
    n_test_dos: int
    threshold: float
    metrics: dict[str, float | int]
    mu: np.ndarray = field(repr=False)
    sd: np.ndarray = field(repr=False)
    test_labels: np.ndarray = field(repr=False)
    test_predictions: np.ndarray = field(repr=False)
    test_scores: np.ndarray = field(repr=False)

    def serializable(self) -> dict:
        return {
            "status": "VALIDATED",
            "experiment": "EXP-0005",
            "architecture": "Layer A pre-diode bidirectional proof of concept",
            "model": {
                "type": "IsolationForest", "n_estimators": 300,
                "max_samples": "auto", "contamination": "auto", "random_state": SEED,
            },
            "features": LAYER_A_FEATURES,
            "counts": {
                "frames": self.n_frames, "directions": sorted(self.destinations),
                "windows": self.n_windows, "train": self.n_train,
                "validation": self.n_val, "test": self.n_test,
                "train_normal": self.n_train_normal,
                "validation_normal": self.n_val_normal,
                "test_normal": self.n_test_normal, "test_dos": self.n_test_dos,
            },
            "threshold": self.threshold,
            "metrics": self.metrics,
            "comparison": {
                "layer_a_exp0005_unit": "DoS-containing vs pure-Normal TEST windows",
                "layer_a_dos_flag_rate": self.metrics["recall"],
                "layer_b_exp0004_unit": "dominant-DoS TEST windows",
                "layer_b_dos_flagged": 0, "layer_b_dos_total": 136,
                "layer_b_dos_flag_rate": 0.0,
            },
            "limitation": (
                "Layer A has bidirectional OT-side visibility that Layer B is "
                "architecturally denied; this does not establish universal DoS detection."
            ),
        }


def contiguous_blocks(n: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    a = int(n * TRAIN_FRAC)
    b = int(n * (TRAIN_FRAC + VAL_FRAC))
    return (
        np.arange(0, a - GUARD_WINDOWS),
        np.arange(a + GUARD_WINDOWS, b - GUARD_WINDOWS),
        np.arange(b + GUARD_WINDOWS, n),
    )


def build_windows(records: Iterable[FrameRecord] | None = None) -> tuple[list[LayerAWindow], int]:
    """Build 5-second windows without applying a direction filter."""
    frames = list(iter_records() if records is None else records)
    frames.sort(key=lambda record: record.timestamp)
    buckets: dict[int, list[FrameRecord]] = {}
    for record in frames:
        buckets.setdefault(math.floor(record.timestamp / WINDOW_SECONDS), []).append(record)

    windows: list[LayerAWindow] = []
    for bucket_index in sorted(buckets):
        bucket = sorted(buckets[bucket_index], key=lambda record: record.timestamp)
        if len(bucket) < MIN_FRAMES_PER_WINDOW:
            continue
        n = len(bucket)
        lengths = [record.frame_len_bytes for record in bucket]
        entropies = [record.message_entropy_bits_per_byte for record in bucket]
        iats = [bucket[i].timestamp - bucket[i - 1].timestamp for i in range(1, n)]
        frame_ids = [record.frame_id for record in bucket]
        repeats = sum(frame_ids[i] == frame_ids[i - 1] for i in range(1, n))
        features = {
            "packet_count": float(n), "packets_per_sec": n / WINDOW_SECONDS,
            "bytes_per_sec": sum(lengths) / WINDOW_SECONDS,
            "mean_frame_len": float(np.mean(lengths)),
            "iat_mean": float(np.mean(iats)), "iat_std": float(np.std(iats)),
            "iat_min": float(min(iats)), "iat_max": float(max(iats)),
            "frac_func_read": sum(record.function_code == 0x03 for record in bucket) / n,
            "frac_func_write": sum(record.function_code == 0x10 for record in bucket) / n,
            "rare_func_rate": sum(record.rare_function_code for record in bucket) / n,
            "distinct_frame_ratio": len(set(frame_ids)) / n,
            "repeat_frame_rate": repeats / (n - 1),
            "payload_entropy_mean": float(np.mean(entropies)),
            "payload_entropy_std": float(np.std(entropies)),
        }
        windows.append(LayerAWindow(
            bucket_index=bucket_index, t_start=bucket_index * WINDOW_SECONDS,
            features=features,
            categories=frozenset(record.categorized_attack for record in bucket),
            destinations=frozenset(record.destination for record in bucket),
        ))
    return windows, len(frames)


def binary_metrics(labels: np.ndarray, predictions: np.ndarray) -> dict[str, float | int]:
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {
        "precision": float(precision), "recall": float(recall), "f1": float(f1),
        "fpr": float(fp / (fp + tn)) if fp + tn else 0.0,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def run_layer_a_detector(
    windows: Iterable[LayerAWindow] | None = None, *, seed: int = SEED,
    target_fpr: float = TARGET_FPR,
) -> LayerAResult:
    if windows is None:
        wins, n_frames = build_windows()
    else:
        wins = sorted(list(windows), key=lambda window: window.bucket_index)
        n_frames = 0
    if not wins:
        raise ValueError("no Layer A windows supplied")

    matrix = np.array(
        [[window.features[name] for name in LAYER_A_FEATURES] for window in wins],
        dtype=float,
    )
    pure_normal = np.array([window.is_pure_normal for window in wins])
    contains_dos = np.array([window.contains_dos for window in wins])
    train, validation, test = contiguous_blocks(len(wins))
    train_normal = train[pure_normal[train]]
    validation_normal = validation[pure_normal[validation]]
    if not len(train_normal) or not len(validation_normal):
        raise ValueError("TRAIN and VALIDATION require pure-Normal windows")

    mu = matrix[train_normal].mean(axis=0)
    sd = matrix[train_normal].std(axis=0)
    sd[sd == 0] = 1.0
    standardized = (matrix - mu) / sd
    model = IsolationForest(
        n_estimators=300, max_samples="auto", contamination="auto",
        random_state=seed, n_jobs=-1,
    )
    model.fit(standardized[train_normal])
    validation_scores = -model.score_samples(standardized[validation_normal])
    threshold = float(np.quantile(validation_scores, 1 - target_fpr))

    cohort = test[pure_normal[test] | contains_dos[test]]
    labels = contains_dos[cohort].astype(int)
    scores = -model.score_samples(standardized[cohort])
    predictions = (scores >= threshold).astype(int)
    metrics = binary_metrics(labels, predictions)
    return LayerAResult(
        n_frames=n_frames,
        destinations=frozenset().union(*(window.destinations for window in wins)),
        n_windows=len(wins), n_train=len(train), n_val=len(validation), n_test=len(test),
        n_train_normal=len(train_normal), n_val_normal=len(validation_normal),
        n_test_normal=int((labels == 0).sum()), n_test_dos=int((labels == 1).sum()),
        threshold=threshold, metrics=metrics, mu=mu, sd=sd,
        test_labels=labels, test_predictions=predictions, test_scores=scores,
    )


def write_result(result: LayerAResult, path: Path = RESULT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.serializable(), indent=2) + "\n", encoding="utf-8")


def main() -> None:
    result = run_layer_a_detector()
    write_result(result)
    print(json.dumps(result.serializable(), indent=2))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
