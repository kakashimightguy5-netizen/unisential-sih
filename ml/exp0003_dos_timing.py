#!/usr/bin/env python3
"""
EXP-0003 (investigation only) — does egress inter-arrival timing separate
DoS (Bad-CRC) windows from Normal windows in the TEST split?

MEASUREMENT ONLY. No detector code changes, no new features. TEST split only.
Result and verdict: docs/EXPERIMENT_LOG.md EXP-0003.

Pre-registered decision rule (fixed before interpreting the numbers):
  SEPARATION      : at least one IAT statistic where |Cohen's d| > 0.5 AND a simple
                    one-sided threshold on it would flag >=30% of DoS windows at
                    <=5 percentage-points of extra Normal FPR.
  NO SEPARATION   : |d| < 0.2 on all four IAT stats and the raw inter-frame-gap
                    distributions overlap (Mann-Whitney p may still be "significant"
                    on large n -- effect size, not p, decides).
  AMBIGUOUS       : anything in between -> no verdict change without a fuller experiment.

Run:  .venv/bin/python ml/exp0003_dos_timing.py
"""
import math
import statistics as st
from collections import defaultdict

import numpy as np
from scipy import stats

from features_txt import iter_records
from features_windowed import EGRESS_DESTINATION, WINDOW_SECONDS
from iforest_detector import run_detector

DOS_CAT = 6
IAT_STATS = ["iat_mean", "iat_std", "iat_min", "iat_max"]


def cohens_d(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    na, nb = len(a), len(b)
    sp = math.sqrt(((na - 1) * a.var(ddof=1) + (nb - 1) * b.var(ddof=1)) / (na + nb - 2))
    return (a.mean() - b.mean()) / sp if sp > 0 else 0.0


def main():
    R = run_detector()

    # --- identify TEST windows: pure-Normal vs contains-a-DoS-frame ---
    dos_widx, normal_widx = set(), set()
    for w in R.test_windows:
        cats = set(w.categories)
        if cats == {0}:
            normal_widx.add(w.w_index)
        elif DOS_CAT in cats:
            dos_widx.add(w.w_index)  # window contains >=1 DoS frame (any other cats too)

    print(f"TEST split: {len(R.test_windows)} windows total")
    print(f"  pure-Normal windows      : {len(normal_widx)}")
    print(f"  windows with >=1 DoS frame: {len(dos_widx)}")

    win_by_idx = {w.w_index: w for w in R.test_windows}

    # --- (1) per-window IAT aggregates already in the feature set ---
    print("\n=== (1) per-window IAT statistics (existing features) ===")
    print(f"{'stat':<12} {'Normal mean±std':>22} {'DoS mean±std':>22} {'Cohen d':>9} {'MWU p':>10}")
    agg = {}
    for s in IAT_STATS:
        nv = [win_by_idx[i].features[s] for i in normal_widx]
        dv = [win_by_idx[i].features[s] for i in dos_widx]
        d = cohens_d(dv, nv)
        p = stats.mannwhitneyu(dv, nv, alternative="two-sided").pvalue
        agg[s] = (nv, dv, d, p)
        print(f"{s:<12} {f'{st.mean(nv):.4f} ± {st.pstdev(nv):.4f}':>22} "
              f"{f'{st.mean(dv):.4f} ± {st.pstdev(dv):.4f}':>22} {d:>+9.3f} {p:>10.2e}")

    # --- what would a one-sided threshold on each stat buy? ---
    print("\n=== (2) best single-threshold sweep per IAT stat (DoS recall @ added Normal FPR) ===")
    for s in IAT_STATS:
        nv, dv, _, _ = agg[s]
        nv, dv = np.array(nv), np.array(dv)
        best = None
        cand = np.unique(np.concatenate([nv, dv]))
        for t in cand:
            for side in ("ge", "le"):
                if side == "ge":
                    dos_rec = (dv >= t).mean(); norm_fpr = (nv >= t).mean()
                else:
                    dos_rec = (dv <= t).mean(); norm_fpr = (nv <= t).mean()
                if norm_fpr <= 0.05 and (best is None or dos_rec > best[0]):
                    best = (dos_rec, norm_fpr, t, side)
        if best:
            print(f"  {s:<12} DoS recall {best[0]:.1%} at +{best[1]:.1%} Normal FPR "
                  f"(rule: {s} {'>=' if best[3] == 'ge' else '<='} {best[2]:.4f})")
        else:
            print(f"  {s:<12} no threshold reaches <=5% Normal FPR with any DoS recall")

    # --- (3) raw inter-frame gap distribution, DoS-windows vs Normal-windows ---
    frames = [r for r in iter_records() if r.destination == EGRESS_DESTINATION]
    buckets = defaultdict(list)
    for r in frames:
        buckets[math.floor(r.timestamp / WINDOW_SECONDS)].append(r)

    def gaps_for(widx_set):
        g = []
        for wi in widx_set:
            fr = sorted(buckets.get(wi, []), key=lambda r: r.timestamp)
            g += [fr[k].timestamp - fr[k - 1].timestamp for k in range(1, len(fr))]
        return np.array(g)

    ng, dg = gaps_for(normal_widx), gaps_for(dos_widx)
    print("\n=== (3) raw consecutive inter-frame gaps within those windows ===")
    for name, g in (("Normal-window gaps", ng), ("DoS-window gaps", dg)):
        q = np.quantile(g, [0, .05, .25, .5, .75, .95, 1]) if len(g) else []
        print(f"  {name:<20} n={len(g):>5}  mean={g.mean():.4f} std={g.std():.4f}  "
              f"min/p25/med/p75/max = {q[0]:.3f}/{q[2]:.3f}/{q[3]:.3f}/{q[4]:.3f}/{q[6]:.3f}")
    if len(ng) and len(dg):
        print(f"  Cohen's d (DoS vs Normal gaps): {cohens_d(dg, ng):+.3f}")
        print(f"  Mann-Whitney U p: {stats.mannwhitneyu(dg, ng, alternative='two-sided').pvalue:.2e}")
        print(f"  Kolmogorov-Smirnov p: {stats.ks_2samp(dg, ng).pvalue:.2e}")

    # --- (4) are the DoS egress frames themselves distinctive? ---
    print("\n=== (4) DoS egress frames vs Normal egress frames (frame content) ===")

    def frame_profile(widx_set, label):
        fr = [r for wi in widx_set for r in buckets.get(wi, [])]
        fc = defaultdict(int)
        for r in fr:
            fc[r.function_code] += 1
        fids = {r.frame_id for r in fr}
        lens = [r.frame_len_bytes for r in fr]
        print(f"  {label:<16} frames={len(fr):>5}  distinct frame_ids={len(fids):>3}  "
              f"func_codes={dict(sorted(fc.items()))}  len(min/med/max)="
              f"{min(lens)}/{int(st.median(lens))}/{max(lens)}")

    frame_profile(dos_widx, "DoS windows")
    frame_profile(normal_widx, "Normal windows")

    dos_frames = [r for wi in dos_widx for r in buckets.get(wi, []) if r.specific_attack == 18]
    if dos_frames:
        fids = {r.frame_id for r in dos_frames}
        print(f"  DoS frames only (spec==18): n={len(dos_frames)}  distinct frame_ids={len(fids)}  "
              f"func_codes={sorted({r.function_code for r in dos_frames})}  "
              f"lens={sorted({r.frame_len_bytes for r in dos_frames})}")


if __name__ == "__main__":
    main()
