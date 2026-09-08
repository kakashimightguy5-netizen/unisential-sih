"""Feature-deviation explanations for already-flagged detector windows.

These explanations rank the Isolation Forest input features by absolute z-score from
the frozen TRAIN-normal baseline. They describe statistical unusualness, not model
attribution, attack causality, or root cause. Deterministic rule hits are reported
separately because they are membership tests, not standardized model inputs.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from features_windowed import IF_FEATURES
from iforest_detector import DetectorResult


_FEATURE_LABELS = {
    "packet_count": "packet count",
    "packets_per_sec": "packet rate",
    "bytes_per_sec": "byte rate",
    "mean_frame_len": "mean frame length",
    "iat_mean": "mean inter-arrival time",
    "iat_std": "inter-arrival-time variability",
    "iat_min": "minimum inter-arrival time",
    "iat_max": "maximum inter-arrival time",
    "frac_func_read": "read-function share",
    "frac_func_write": "write-function share",
    "distinct_frame_ratio": "distinct-frame ratio",
    "repeat_frame_rate": "repeated-frame rate",
    "payload_entropy_mean": "mean payload entropy",
    "payload_entropy_std": "payload-entropy variability",
}


@dataclass(frozen=True)
class FeatureDeviation:
    feature: str
    observed: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    direction: str


@dataclass(frozen=True)
class AlertExplanation:
    test_index: int
    window_index: int
    timestamp: float
    fired_by_if: bool
    fired_by_rule: bool
    rule_reasons: tuple[str, ...]
    top_deviations: tuple[FeatureDeviation, ...]
    summary: str


def _validate_top_k(top_k: int) -> None:
    if isinstance(top_k, bool) or not isinstance(top_k, int) or not 3 <= top_k <= 5:
        raise ValueError("top_k must be an integer from 3 through 5")


def _summary(deviations: tuple[FeatureDeviation, ...]) -> str:
    phrases = []
    for deviation in deviations[:2]:
        label = _FEATURE_LABELS.get(
            deviation.feature, deviation.feature.replace("_", " ")
        )
        level = "high" if deviation.z_score >= 0 else "low"
        phrases.append(
            f"unusually {level} {label} "
            f"({abs(deviation.z_score):.1f} standard deviations "
            f"{deviation.direction} the TRAIN-normal mean)"
        )
    return "Flagged; the most statistically unusual features were " + " and ".join(phrases) + "."


def explain_alert(
    result: DetectorResult,
    test_index: int,
    *,
    top_k: int = 3,
) -> AlertExplanation:
    """Explain one combined-detector alert using its frozen TRAIN-normal baseline.

    The returned ranking is descriptive: a large absolute z-score means the feature is
    statistically unusual relative to TRAIN-normal. It is not an Isolation Forest
    feature attribution and does not establish why an attack occurred.
    """
    _validate_top_k(top_k)
    if isinstance(test_index, bool) or not isinstance(test_index, (int, np.integer)):
        raise TypeError("test_index must be an integer")
    test_index = int(test_index)
    if not 0 <= test_index < len(result.test_windows):
        raise IndexError("test_index is outside the TEST result")
    if not bool(result.comb_pred[test_index]):
        raise ValueError("the selected TEST window was not flagged")
    if len(result.if_idx) != len(IF_FEATURES):
        raise ValueError("detector IF feature mapping is inconsistent")

    window = result.test_windows[test_index]
    deviations = []
    for feature_order, (feature, full_index) in enumerate(zip(IF_FEATURES, result.if_idx)):
        observed = float(window.features[feature])
        baseline_mean = float(result.mu[full_index])
        baseline_std = float(result.sd[full_index])
        if not np.isfinite(baseline_std) or baseline_std <= 0:
            raise ValueError(f"invalid frozen baseline standard deviation for {feature}")
        z_score = (observed - baseline_mean) / baseline_std
        if not np.isfinite(z_score):
            raise ValueError(f"non-finite feature deviation for {feature}")
        deviations.append((feature_order, FeatureDeviation(
            feature=feature,
            observed=observed,
            baseline_mean=baseline_mean,
            baseline_std=baseline_std,
            z_score=float(z_score),
            direction="above" if z_score >= 0 else "below",
        )))

    deviations.sort(key=lambda item: (-abs(item[1].z_score), item[0]))
    top_deviations = tuple(item[1] for item in deviations[:top_k])
    rule_hit = result.rule_hits[test_index]

    return AlertExplanation(
        test_index=test_index,
        window_index=int(window.w_index),
        timestamp=float(window.t_start),
        fired_by_if=bool(result.if_pred[test_index]),
        fired_by_rule=bool(rule_hit.fired),
        rule_reasons=tuple(rule_hit.reasons),
        top_deviations=top_deviations,
        summary=_summary(top_deviations),
    )


def explain_flagged_alerts(
    result: DetectorResult,
    *,
    top_k: int = 3,
) -> list[AlertExplanation]:
    """Explain all combined-detector alerts in their original TEST order."""
    _validate_top_k(top_k)
    return [
        explain_alert(result, int(test_index), top_k=top_k)
        for test_index in np.flatnonzero(result.comb_pred)
    ]
