#!/usr/bin/env python3
"""
Egress anomaly detector — EXP-0002 (headline).

Layers, OR-ed together for the operational verdict:
  * Deterministic rule layer (ml/rules.py): out-of-profile Modbus function code /
    novel slave address -> immediate flag. NOT an Isolation Forest input.
  * Stage 1 Isolation Forest: unsupervised, trained on TRAIN-normal windows only,
    over IF_FEATURES (= all window features MINUS the rule-layer fields, INCLUDING the
    two payload-entropy features — pre-registration §2 amended 2026-09-04, see
    DECISION_LOG.md / EXPERIMENT_LOG.md EXP-0002).
  * Stage 0 naive baseline kept for comparison only.

Discipline unchanged from EXP-0001: contiguous time-block split, threshold picked on
VALIDATION-normal scores only, standardiser frozen from TRAIN-normal, TEST scored once,
labels never used as features, per-category breakdown reported, every flag explained.

Run:  .venv/bin/python ml/iforest_detector.py
"""
from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (average_precision_score, confusion_matrix,
                             precision_recall_fscore_support)

from features_windowed import (CATEGORY_NAMES, IF_FEATURES, RULE_LAYER_FEATURES,
                               WINDOW_FEATURES, build_windows)
from rules import DeterministicRuleLayer

REPORT_PATH = Path(__file__).resolve().parent.parent / "data" / "experiments" / "iforest_detector_report.md"

TRAIN_FRAC, VAL_FRAC = 0.60, 0.20
GUARD_WINDOWS = 1
TARGET_FPR = 0.01
SEED = 0

# No historical comparison constants: EXP-0001/0002 were run on a retracted
# fabricated input. EXP-0004 is a clean rebaseline on the verified dataset.


def contiguous_blocks(n: int):
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
    rule_pred: np.ndarray         # deterministic rule layer
    if_pred: np.ndarray           # Isolation Forest (thresholded)
    comb_pred: np.ndarray         # rule OR IF  (EXP-0002 headline)
    if_scores: np.ndarray         # raw IF anomaly score (higher = more anomalous)
    rule_hits: list               # list[RuleHit], aligned to TEST windows
    test_windows: list = field(repr=False, default_factory=list)

    def metrics(self, pred: np.ndarray) -> dict:
        return binmetrics(self.y_test, pred)

    def percat(self, pred: np.ndarray) -> dict:
        return percat(self.cat_test, pred)

    def category_flag_rate(self, name: str, pred: np.ndarray | None = None) -> float:
        pred = self.comb_pred if pred is None else pred
        m = self.cat_test == CATEGORY_NAMES.index(name)
        return float(pred[m].mean()) if m.any() else float("nan")


def run_detector(windows=None, target_fpr: float = TARGET_FPR,
                 seed: int = SEED) -> DetectorResult:
    """Run the full EXP-0002 detector once and return its results.

    `windows` lets a caller (e.g. a test) pass a pre-built list of
    `features_windowed.Window`; default builds from the raw TXT egress stream.
    Deterministic given the same windows + seed.
    """
    wins = build_windows() if windows is None else list(windows)
    wins.sort(key=lambda w: w.w_index)
    n = len(wins)
    Xraw = np.array([[w.features[f] for f in WINDOW_FEATURES] for w in wins], dtype=float)
    y = np.array([w.is_attack for w in wins])
    cat = np.array([w.dominant_attack_category for w in wins])

    tr, va, te = contiguous_blocks(n)
    tr_normal_mask = tr[y[tr] == 0]
    mu, sd = zfit(Xraw[tr_normal_mask])
    Xz = (Xraw - mu) / sd

    if_idx = [WINDOW_FEATURES.index(f) for f in IF_FEATURES]
    train_normal_windows = [wins[i] for i in tr_normal_mask]

    # ---- deterministic rule layer ----
    rule = DeterministicRuleLayer().fit(train_normal_windows)
    rule_hits_te = [rule.evaluate(wins[i]) for i in te]
    rule_pred_te = np.array([h.fired for h in rule_hits_te], dtype=int)

    # ---- Stage 1 Isolation Forest (headline: IF_FEATURES, entropy included) ----
    clf = IsolationForest(n_estimators=300, max_samples="auto",
                          contamination="auto", random_state=seed, n_jobs=-1)
    clf.fit(Xz[np.ix_(tr_normal_mask, if_idx)])
    s_va = -clf.score_samples(Xz[np.ix_(va, if_idx)])
    s_te = -clf.score_samples(Xz[np.ix_(te, if_idx)])
    thr = float(np.quantile(s_va[y[va] == 0], 1 - target_fpr))
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

    return DetectorResult(
        n_windows=n, n_train=len(tr), n_val=len(va), n_test=len(te),
        n_train_normal=len(tr_normal_mask), threshold=thr,
        valid_func_codes=rule.valid_func_codes, valid_addresses=rule.valid_addresses,
        mu=mu, sd=sd, if_idx=if_idx,
        y_test=y[te], cat_test=cat[te],
        base_pred=base_pred_te, rule_pred=rule_pred_te, if_pred=if_pred_te,
        comb_pred=comb_pred_te, if_scores=s_te, rule_hits=rule_hits_te,
        test_windows=[wins[i] for i in te],
    )


def main() -> None:
    R = run_detector()
    n = R.n_windows

    # feature matrix for the TEST windows only (for the explainability section)
    Xte = np.array([[w.features[f] for f in WINDOW_FEATURES] for w in R.test_windows], dtype=float)
    mu, sd, if_idx = R.mu, R.sd, R.if_idx
    y_te, cat_te = R.y_test, R.cat_test
    rule_pred_te, if_pred_te = R.rule_pred, R.if_pred
    comb_pred_te, base_pred_te, s_te = R.comb_pred, R.base_pred, R.if_scores
    thr = R.threshold

    buf = io.StringIO()
    p = lambda *a: print(*a, file=buf)

    p("# Egress anomaly detector — EXP-0004 rebaseline\n")
    p("Run on the verified row-aligned TXT dataset (sha256 `ce2d69e3…93e3`).\n")
    p("Payload entropy is a candidate IF input pending the paired EXP-0004 comparison. "
      "`function_code_valid` / `rare_func_rate` remain outside the IF and are handled "
      "by the standalone deterministic rule layer (`ml/rules.py`).\n")

    p("## Setup\n")
    p(f"- Egress stream: `destination == 1`, 5 s tumbling windows. {n:,} windows.")
    p(f"- Contiguous split: train {R.n_train:,} / val {R.n_val:,} / test {R.n_test:,} "
      f"({GUARD_WINDOWS}-window guard gap).")
    p(f"- Train-normal windows (fit IF + standardiser + rule profile): {R.n_train_normal:,}.")
    p(f"- Test block: {int((y_te == 0).sum()):,} normal / {int((y_te == 1).sum()):,} attack.")
    p(f"- **IF feature set ({len(if_idx)})**, entropy included: {', '.join(IF_FEATURES)}")
    p(f"- **Rule-layer fields (not IF inputs):** {', '.join(RULE_LAYER_FEATURES)}, plus "
      f"slave `address`.")
    p(f"- Rule profile learned from train-normal: valid function codes "
      f"{sorted(hex(c) for c in R.valid_func_codes)}, "
      f"valid addresses {sorted(R.valid_addresses)}.")
    p(f"- Threshold = val-normal {1 - TARGET_FPR:.0%} quantile = {thr:.4f}. TEST scored once.\n")

    # ---- results table ----
    rows = [
        ("Stage 0 naive baseline", base_pred_te, None),
        ("Deterministic rule layer only", rule_pred_te, None),
        ("Stage 1 IF only (candidate features, entropy in)", if_pred_te, s_te),
        ("Combined: rule OR IF", comb_pred_te, None),
    ]
    p("## Results — TEST block\n")
    p("| detector | precision | recall | F1 | FPR | PR-AUC |")
    p("|---|---|---|---|---|---|")
    for name, pred, score in rows:
        m = binmetrics(y_te, pred)
        ap = f"{average_precision_score(y_te, score):.3f}" if score is not None else "—"
        p(f"| {name} | {m['p']:.3f} | {m['r']:.3f} | {m['f1']:.3f} "
          f"| {m['fpr']:.3f} | {ap} |")
    cm = binmetrics(y_te, comb_pred_te)
    p(f"\nCombined confusion (test): TN {cm['tn']} · FP {cm['fp']} · FN {cm['fn']} · TP {cm['tp']}\n")
    p("No comparison with EXP-0001/0002 is shown because those experiments were "
      "run on a retracted fabricated input.\n")

    # ---- per-category ----
    p("## Per-category flag rate — TEST (Normal row = false-positive rate)\n")
    p("| category | n | rule only | IF only | **combined** |")
    p("|---|---|---|---|---|")
    pc_rule, pc_if, pc_comb = percat(cat_te, rule_pred_te), percat(cat_te, if_pred_te), percat(cat_te, comb_pred_te)
    for c in range(8):
        name = CATEGORY_NAMES[c]
        if name not in pc_comb:
            continue
        nn, cr = pc_comb[name]
        p(f"| {name} | {nn} | {pc_rule[name][1]:.1%} | {pc_if[name][1]:.1%} | "
          f"**{cr:.1%}** |")

    # ---- MFCI / Recon check ----
    p("\n### MFCI / Recon check\n")
    for name in ("MFCI", "Recon"):
        c = CATEGORY_NAMES.index(name)
        m = cat_te == c
        p(f"- **{name}**: n={int(m.sum())} · rule-layer catches {rule_pred_te[m].mean():.1%} "
          f"· IF alone {if_pred_te[m].mean():.1%} · combined {comb_pred_te[m].mean():.1%}.")
    # normal-window FP contribution of the rule
    nm = cat_te == 0
    p(f"- Rule layer on Normal test windows: fires on {rule_pred_te[nm].mean():.2%} "
      f"({int(rule_pred_te[nm].sum())} / {int(nm.sum())}). "
      f"IF-only Normal FP {if_pred_te[nm].mean():.2%}. "
      f"Combined Normal FP {comb_pred_te[nm].mean():.2%}.")

    # ---- explainability ----
    p("\n## Explainability — sample flagged TEST windows\n")
    p("```")
    if_idx_arr = np.array(if_idx)
    flagged = np.where(comb_pred_te == 1)[0]
    order = flagged[np.argsort(-np.where(np.isin(flagged, np.where(if_pred_te == 1)[0]),
                                         s_te[flagged], 1e9))]
    shown, seen = [], set()
    for j in order:
        obs = Xte[j, if_idx_arr]
        base_sd = sd[if_idx_arr]
        z = np.where(base_sd > 1e-9, (obs - mu[if_idx_arr]) / np.where(base_sd > 1e-9, base_sd, 1), 0.0)
        rh = R.rule_hits[j]
        top = np.argsort(-np.abs(z))[:3]
        key = (cat_te[j], rh.fired, tuple(np.round(obs[top], 1)))
        if key in seen:
            continue
        seen.add(key)
        shown.append(j)
        truth = CATEGORY_NAMES[cat_te[j]] if y_te[j] else "Normal (FALSE POSITIVE)"
        src = "RULE" + ("+IF" if if_pred_te[j] else "") if rh.fired else "IF"
        p(f"window @t={R.test_windows[j].t_start:.0f}s  truth={truth}  fired_by={src}"
          + (f"  score={s_te[j]:.3f}/thr {thr:.3f}" if if_pred_te[j] else ""))
        if rh.fired:
            p(f"    RULE: {'; '.join(rh.reasons)}")
        for oi in top:
            p(f"    {IF_FEATURES[oi]:<22} observed {obs[oi]:8.3f}  baseline {mu[if_idx[oi]]:8.3f}  z={z[oi]:+.1f}")
        p("")
        if len(shown) >= 7:
            break
    p("```")

    # ---- audit ----
    p("## Artifact-audit notes\n")
    p("- **Boundary sanity:** disjoint 5 s buckets, split on window index + 1-window "
      "guard gap → 0 windows span a block. PASS.")
    p("- **Rule layer vs IF (leakage check):** the rule fires only on function codes / "
      "addresses *absent from the entire train-normal block*. It is a frozen membership "
      "test, not fitted to attack data. On Normal test windows it fires "
      f"{rule_pred_te[nm].mean():.2%} of the time (novel benign codes), the same "
      "false-positive channel Stage 0 already had.")
    p("- **Entropy contribution:** entropy is legitimately evaluable because the verified "
      "TXT is row-aligned to the ARFF. Its measured contribution is reported separately "
      "in EXP-0004; no conclusion is inherited from retracted experiments.")
    p("- **Attack-family limitations:** interpret only from the verified EXP-0004 metrics "
      "and same-day DoS re-measurement.")

    REPORT_PATH.write_text(buf.getvalue(), encoding="utf-8")
    print(buf.getvalue())
    print(f"\n[report -> {REPORT_PATH}]")


if __name__ == "__main__":
    main()
