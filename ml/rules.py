#!/usr/bin/env python3
"""
Deterministic rule layer — runs ALONGSIDE the Isolation Forest, not as one of its inputs.

Rationale (EXP-0001 audit / DECISION_LOG 2026-09-04): `function_code_valid` and slave
`address` are *exactly constant* on normal traffic, so an Isolation Forest never draws
a split on them and cannot use them — yet an out-of-profile Modbus function code or a
never-before-seen slave address on the wire is an unambiguous protocol violation. That
is a membership test, not a statistical anomaly: handle it with a hard rule.

Profile (the "valid" sets) is frozen from the TRAIN-normal block only, same discipline
as the IF standardiser. The rule's verdict is OR-ed with the IF's.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RuleHit:
    fired: bool
    reasons: list[str]


class DeterministicRuleLayer:
    def __init__(self) -> None:
        self.valid_func_codes: frozenset[int] = frozenset()
        self.valid_addresses: frozenset[int] = frozenset()
        self._fitted = False

    def fit(self, train_normal_windows) -> "DeterministicRuleLayer":
        fcs: set[int] = set()
        addrs: set[int] = set()
        for w in train_normal_windows:
            fcs |= set(w.func_codes)
            addrs |= set(w.addresses)
        self.valid_func_codes = frozenset(fcs)
        self.valid_addresses = frozenset(addrs)
        self._fitted = True
        return self

    def evaluate(self, window) -> RuleHit:
        if not self._fitted:
            raise RuntimeError("fit() the rule layer on train-normal windows first")
        reasons: list[str] = []
        bad_fc = sorted(set(window.func_codes) - self.valid_func_codes)
        bad_ad = sorted(set(window.addresses) - self.valid_addresses)
        if bad_fc:
            reasons.append("invalid_function_code=" + ",".join(f"0x{c:02x}" for c in bad_fc))
        if bad_ad:
            reasons.append("novel_address=" + ",".join(str(a) for a in bad_ad))
        return RuleHit(fired=bool(reasons), reasons=reasons)

    def predict(self, windows) -> list[int]:
        return [int(self.evaluate(w).fired) for w in windows]


@dataclass(frozen=True)
class PressureBounds:
    low: float
    high: float
    source: str


class PressureBoundsRule:
    """Additive out-of-bounds check on the decoded response pressure value.

    Independent of DeterministicRuleLayer; OR-ed into the operational verdict the
    same way. Added for NMRI (EXP-0016): NMRI is *defined* as naive out-of-bounds
    response injection, and the decoded `0x03` response pressure is a value that is
    exactly bounded on normal traffic — a membership test, like the func-code rule,
    not a statistical anomaly. Bounds are frozen from TRAIN-normal only.

    `evaluate` takes a window's minimum and maximum decoded `0x03` pressure (None
    if the window has no `0x03` response pressure).
    """

    def __init__(self) -> None:
        self.bounds: PressureBounds | None = None
        self._fitted = False

    def fit(
        self,
        train_normal_values,
        *,
        source: str = "TRAIN-normal 0x03 read-response pressure min/max",
    ) -> "PressureBoundsRule":
        finite = [
            float(v) for v in train_normal_values
            if v is not None and float(v) == float(v) and abs(float(v)) != float("inf")
        ]
        if not finite:
            raise ValueError("PressureBoundsRule.fit needs at least one finite value")
        self.bounds = PressureBounds(min(finite), max(finite), source)
        self._fitted = True
        return self

    def evaluate(
        self, window_pressure_min: float | None, window_pressure_max: float | None,
    ) -> RuleHit:
        if not self._fitted or self.bounds is None:
            raise RuntimeError("fit() PressureBoundsRule on train-normal values first")
        if window_pressure_min is None or window_pressure_max is None:
            return RuleHit(fired=False, reasons=[])
        reasons: list[str] = []
        if window_pressure_min < self.bounds.low:
            reasons.append(
                f"pressure_below_train_normal_min={window_pressure_min:.6g}"
                f"<{self.bounds.low:.6g}"
            )
        if window_pressure_max > self.bounds.high:
            reasons.append(
                f"pressure_above_train_normal_max={window_pressure_max:.6g}"
                f">{self.bounds.high:.6g}"
            )
        return RuleHit(fired=bool(reasons), reasons=reasons)

    def predict(self, windows_min_max) -> list[int]:
        return [int(self.evaluate(lo, hi).fired) for lo, hi in windows_min_max]


@dataclass(frozen=True)
class RateBound:
    max_packets_per_sec: float
    source: str


class RateFloodRule:
    """Additive out-of-bounds check on a window's `packets_per_sec` rate.

    Independent of DeterministicRuleLayer/PressureBoundsRule, OR-ed into the
    operational verdict the same way. Added for EXP-0025: a Type 2 (egress-
    channel/diode-termination) flood — an insider or compromised device flooding
    the OUTBOUND channel itself — pushes `packets_per_sec` above every rate ever
    observed on TRAIN-normal traffic, a membership test like the other two rules,
    not a statistical anomaly. Threshold is frozen from TRAIN-normal only.

    This targets Type 2 DoS ONLY. Type 1 (external inbound-flood) DoS lives
    entirely in the inbound command direction and never crosses the diode, so it
    is invisible to this (or any) egress-side feature — see
    `ml/features_windowed.py` module docstring and EXP-0003/0013.
    """

    def __init__(self) -> None:
        self.bound: RateBound | None = None
        self._fitted = False

    def fit(
        self,
        train_normal_packets_per_sec,
        *,
        source: str = "TRAIN-normal packets_per_sec max",
    ) -> "RateFloodRule":
        finite = [
            float(v) for v in train_normal_packets_per_sec
            if v is not None and float(v) == float(v) and abs(float(v)) != float("inf")
        ]
        if not finite:
            raise ValueError("RateFloodRule.fit needs at least one finite value")
        self.bound = RateBound(max(finite), source)
        self._fitted = True
        return self

    def evaluate(self, packets_per_sec: float) -> RuleHit:
        if not self._fitted or self.bound is None:
            raise RuntimeError("fit() RateFloodRule on train-normal values first")
        if packets_per_sec is None:
            return RuleHit(fired=False, reasons=[])
        reasons: list[str] = []
        if packets_per_sec > self.bound.max_packets_per_sec:
            reasons.append(
                f"packets_per_sec_above_train_normal_max={packets_per_sec:.6g}"
                f">{self.bound.max_packets_per_sec:.6g}"
            )
        return RuleHit(fired=bool(reasons), reasons=reasons)

    def predict(self, packets_per_sec_values) -> list[int]:
        return [int(self.evaluate(v).fired) for v in packets_per_sec_values]


class CmriFloatProvenanceRule:
    """Additive CMRI-ONLY float/representation-provenance rule (EXP-0030c).

    Independent of the other rules; OR-ed into the operational verdict the
    same way. Fires when a fitted XGBoost classifier's score over F2
    (IEEE-754 bit-structure) features of the window's decoded `0x03`
    pressure value exceeds a TRAIN/VAL-fit threshold. Unlike the other rules
    in this file, the "fit" step is NOT a simple TRAIN-normal statistic
    computed inline — it is a full supervised classifier trained on the
    CMRI residual cohort (windows the rest of the wired chain — protocol OR
    pressure OR rate OR IF — already misses) versus Normal, in
    `ml/exp0030c_cmri_production_wiring.py`. This class only WRAPS an
    already-fitted model + threshold (`fit_from_trained`) or loads one from
    the serialized production artifact (`ml/float_provenance_features.py`).

    Framing (repeated per EXP-0030's pre-registration): this rule most
    likely reflects that a forged pressure value was produced by a
    DIFFERENT quantization/generation pipeline than the real sensor, not a
    property of the physical process the sensor measures — float/
    representation-provenance detection, not physical-anomaly detection.

    CMRI ONLY, by explicit pre-registered decision (EXP-0030b: CMRI's
    isolated marginal trade ratio cleared the >=3:1 bar — worst-case
    5.33:1 — GO; NMRI's did not — worst-case 1.19:1 — NO-GO; NMRI is
    explicitly OUT of scope and must never be wired via this class without
    a separate pre-registered decision).
    """

    def __init__(self) -> None:
        self.model = None
        self.threshold: float | None = None
        self.feature_names: list[str] | None = None
        self._fitted = False

    def fit_from_trained(self, model, threshold: float, feature_names) -> "CmriFloatProvenanceRule":
        self.model = model
        self.threshold = float(threshold)
        self.feature_names = list(feature_names)
        self._fitted = True
        return self

    def load_from_artifact(self) -> "CmriFloatProvenanceRule":
        from float_provenance_features import load_model
        model, threshold, feature_names = load_model()
        return self.fit_from_trained(model, threshold, feature_names)

    def evaluate(self, feature_row: dict | None) -> RuleHit:
        if not self._fitted:
            raise RuntimeError("fit_from_trained()/load_from_artifact() CmriFloatProvenanceRule first")
        if feature_row is None:
            return RuleHit(fired=False, reasons=[])
        import numpy as np
        x = np.array([[feature_row[n] for n in self.feature_names]], dtype=float)
        score = float(self.model.predict_proba(x)[0, 1])
        fired = score > self.threshold
        reasons = (
            [f"cmri_float_provenance_score={score:.6g}>{self.threshold:.6g}"] if fired else []
        )
        return RuleHit(fired=fired, reasons=reasons)

    def predict(self, feature_rows) -> list[int]:
        return [int(self.evaluate(r).fired) for r in feature_rows]
