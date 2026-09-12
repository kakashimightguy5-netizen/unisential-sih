#!/usr/bin/env python3
"""Operational egress detector: protocol OR pressure OR rate OR Isolation Forest.

EXP-0017 (protocol OR pressure OR IF) superseded EXP-0004 and scored the one
guarded TEST evaluation on 2026-09-11 (`data/experiments/exp0017_detector.json`).
EXP-0025 (2026-09-12) adds the `rate` (Type 2 egress-flood DoS) term to this
function permanently, for any FUTURE fresh run — but does NOT call
`run_detector()` again itself: TEST must only ever be scored once, and that
budget is already spent. EXP-0025's actual reported numbers are a closed-form
derivation from the frozen EXP-0017 arrays plus the new deterministic rate term
(a function of the already-recorded `packets_per_sec` feature); see
`ml/exp0025_dos_rate_rule.py`. Calling `run_detector()` again will still raise
`FileExistsError` via `exp0017_operational.begin_evaluation`, by design — this
function's code is the correct permanent definition, not a live re-run.

Pressure is ARFF-row-aligned, NOT live packet-byte decoding. The rate rule
targets Type 2 (egress-channel flood) DoS only — Type 1 (external inbound-flood)
DoS remains structurally invisible on the egress side (see
`ml/features_windowed.py` module docstring) and is unaffected.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from features_windowed import (CATEGORY_NAMES, IF_FEATURES,
                               WINDOW_FEATURES, build_windows)
from rules import DeterministicRuleLayer, PressureBoundsRule, RateFloodRule, RuleHit


TRAIN_FRAC, VAL_FRAC = 0.60, 0.20
GUARD_WINDOWS = 1
TARGET_FPR = 0.01
SEED = 0

# No historical comparison constants: EXP-0001/0002 were run on a retracted
# fabricated input. EXP-0004 is a clean rebaseline on the verified dataset.


def contiguous_blocks(n: int):
    """Legacy helper for historical/synthetic callers; EXP-0017 never uses it."""
    a = int(n * TRAIN_FRAC)
    b = int(n * (TRAIN_FRAC + VAL_FRAC))
    return (np.arange(0, a - GUARD_WINDOWS),
            np.arange(a + GUARD_WINDOWS, b - GUARD_WINDOWS),
            np.arange(b + GUARD_WINDOWS, n))


def zfit(X):
    mu, sd = X.mean(axis=0), X.std(axis=0)
    sd[sd == 0] = 1.0
    return mu, sd


def binmetrics(y_true, pred):
    p, r, f1, _ = precision_recall_fscore_support(y_true, pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return dict(p=p, r=r, f1=f1, fpr=fp / (fp + tn) if (fp + tn) else 0.0,
               tn=tn, fp=fp, fn=fn, tp=tp)


def percat(cat_te, pred_te):
    out = {}
    for c in range(8):
        m = cat_te == c
        if m.sum():
            out[CATEGORY_NAMES[c]] = (int(m.sum()), float(pred_te[m].mean()))
    return out


@dataclass
class DetectorResult:
    """Everything a report or a test needs from one detector run. TEST-block arrays
    are all aligned and 0/1 int unless noted."""
    n_windows: int
    n_train: int
    n_val: int
    n_test: int
    n_train_normal: int
    threshold: float
    valid_func_codes: frozenset
    valid_addresses: frozenset
    mu: np.ndarray = field(repr=False)             # train-normal mean, over WINDOW_FEATURES
    sd: np.ndarray = field(repr=False)             # train-normal std (0 -> 1), over WINDOW_FEATURES
    if_idx: list = field(repr=False)               # indices into WINDOW_FEATURES that the IF uses
    y_test: np.ndarray            # 0/1 attack label
    cat_test: np.ndarray          # dominant categorized_attack 0..7
    base_pred: np.ndarray         # Stage 0 naive baseline
    rule_pred: np.ndarray         # protocol OR pressure rule layer
    if_pred: np.ndarray           # Isolation Forest (thresholded)
    comb_pred: np.ndarray         # protocol OR pressure OR IF (EXP-0017)
    if_scores: np.ndarray         # raw IF anomaly score (higher = more anomalous)
    rule_hits: list               # list[RuleHit], aligned to TEST windows
    test_windows: list = field(repr=False, default_factory=list)
    protocol_pred: np.ndarray = field(default_factory=lambda: np.array([], dtype=int))
    pressure_pred: np.ndarray = field(default_factory=lambda: np.array([], dtype=int))
    pressure_bounds: tuple = ()
    split_id: str = ""
    split_sha256: str = ""
    rate_pred: np.ndarray = field(default_factory=lambda: np.array([], dtype=int))  # EXP-0025, Type 2 DoS
    rate_threshold: float = 0.0                                                     # TRAIN-normal packets_per_sec max

    def metrics(self, pred: np.ndarray) -> dict:
        return binmetrics(self.y_test, pred)

    def percat(self, pred: np.ndarray) -> dict:
        return percat(self.cat_test, pred)

    def category_flag_rate(self, name: str, pred: np.ndarray | None = None) -> float:
        pred = self.comb_pred if pred is None else pred
        m = self.cat_test == CATEGORY_NAMES.index(name)
        return float(pred[m].mean()) if m.any() else float("nan")


def run_detector(windows=None, target_fpr: float = TARGET_FPR,
                 seed: int = SEED, *, confirmation: str = "") -> DetectorResult:
    """Score EXP-0017 once, permanently including the pressure rule.

    Real-capture evaluation requires explicit confirmation and consumes an attempt
    ledger before reading data. Tests/dashboard must use exp0017_operational.load_result.
    Pressure is ARFF-row-aligned, NOT decoded from live packet bytes.
    Caller-supplied windows and altered model settings are not benchmark inputs.
    """
    from exp0017_operational import begin_evaluation, manifest_indices, save_result
    from exp0016_pressure_bounds_rule import align_egress_pressure, window_pressure_min_max
    if windows is not None or target_fpr != TARGET_FPR or seed != SEED:
        raise ValueError("EXP-0017 requires the verified dataset and frozen configuration")
    begin_evaluation(confirmation)
    # Alignment verifies both raw hashes before window construction.
    by_bucket = align_egress_pressure()
    pressure_windows = window_pressure_min_max(by_bucket)
    wins = build_windows()
    wins.sort(key=lambda w: w.w_index)
    n = len(wins)
    Xraw = np.array([[w.features[f] for f in WINDOW_FEATURES] for w in wins], dtype=float)
    y = np.array([w.is_attack for w in wins])
    cat = np.array([w.dominant_attack_category for w in wins])

    split, tr, va, te = manifest_indices(wins)
    tr_normal_mask = tr[y[tr] == 0]
    mu, sd = zfit(Xraw[tr_normal_mask])
    Xz = (Xraw - mu) / sd

    if_idx = [WINDOW_FEATURES.index(f) for f in IF_FEATURES]
    train_normal_windows = [wins[i] for i in tr_normal_mask]

    # ---- deterministic rule layer ----
    rule = DeterministicRuleLayer().fit(train_normal_windows)
    pressure = PressureBoundsRule().fit(
        v for w in train_normal_windows for v in by_bucket.get(w.w_index, ())
    )
    rate = RateFloodRule().fit(w.features["packets_per_sec"] for w in train_normal_windows)
    protocol_hits = [rule.evaluate(wins[i]) for i in te]
    pressure_hits = [
        pressure.evaluate(*pressure_windows.get(wins[i].w_index, (None, None, 0))[:2])
        for i in te
    ]
    rate_hits = [rate.evaluate(wins[i].features["packets_per_sec"]) for i in te]
    rule_hits_te = [
        RuleHit(bool(a.fired or b.fired or c.fired), a.reasons + b.reasons + c.reasons)
        for a, b, c in zip(protocol_hits, pressure_hits, rate_hits)
    ]
    rule_pred_te = np.array([h.fired for h in rule_hits_te], dtype=int)

    # ---- Stage 1 Isolation Forest (headline: IF_FEATURES, entropy included) ----
    clf = IsolationForest(n_estimators=300, max_samples="auto",
                          contamination="auto", random_state=seed, n_jobs=-1)
    clf.fit(Xz[np.ix_(tr_normal_mask, if_idx)])
    s_va = -clf.score_samples(Xz[np.ix_(va, if_idx)])
    thr = float(np.quantile(s_va[y[va] == 0], 1 - target_fpr))
    s_te = -clf.score_samples(Xz[np.ix_(te, if_idx)])
    if_pred_te = (s_te >= thr).astype(int)

    # ---- Stage 0 naive baseline (rate rules only; unchanged from EXP-0001) ----
    fi = {f: i for i, f in enumerate(WINDOW_FEATURES)}
    ref = Xraw[tr_normal_mask].mean(axis=0)
    base = np.zeros(len(te), dtype=bool)
    for f in ("iat_mean", "packets_per_sec", "bytes_per_sec"):
        col, r = Xraw[te, fi[f]], ref[fi[f]]
        base |= (col > 2 * r) | (col < 0.5 * r)
    base |= Xraw[te, fi["frac_func_valid"]] < 0.99
    base_pred_te = base.astype(int)

    # ---- combined operational detector: rule OR IF ----
    comb_pred_te = (rule_pred_te | if_pred_te).astype(int)

    result = DetectorResult(
        n_windows=n, n_train=len(tr), n_val=len(va), n_test=len(te),
        n_train_normal=len(tr_normal_mask), threshold=thr,
        valid_func_codes=rule.valid_func_codes, valid_addresses=rule.valid_addresses,
        mu=mu, sd=sd, if_idx=if_idx,
        y_test=y[te], cat_test=cat[te],
        base_pred=base_pred_te, rule_pred=rule_pred_te, if_pred=if_pred_te,
        comb_pred=comb_pred_te, if_scores=s_te, rule_hits=rule_hits_te,
        test_windows=[wins[i] for i in te],
        protocol_pred=np.array([h.fired for h in protocol_hits], dtype=int),
        pressure_pred=np.array([h.fired for h in pressure_hits], dtype=int),
        pressure_bounds=(pressure.bounds.low, pressure.bounds.high),
        split_id=split.split_id, split_sha256=split.membership_sha256,
        rate_pred=np.array([h.fired for h in rate_hits], dtype=int),
        rate_threshold=rate.bound.max_packets_per_sec,
    )
    # Persist every scored outcome, including a failed identity gate, without rerun.
    save_result(result)
    return result


def main() -> None:
    from exp0017_operational import main as operational_main
    operational_main()


if __name__ == "__main__":
    main()
