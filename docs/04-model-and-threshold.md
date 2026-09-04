<!-- Consistent with and expanded by 06_AI_MODEL_EVALUATION_PLAN.md (adds the naive
     baseline stage, the full metric list, and per-attack-type honesty). Model choice
     rationale here (Isolation Forest) is unchanged and authoritative. -->

# Model Choice and Thresholding

## Model: Isolation Forest

**Chosen for P1.** Rationale:

- **Unsupervised, trained on normal-only data.** We do not need — and per the threat
  model should not rely on — a reliable set of labeled anomalies at train time. This
  fits an egress-anomaly-detection setting where attack examples are rare or absent
  in the training distribution.
- **Handles mixed continuous features without heavy preprocessing.** Isolation
  Forest partitions on raw feature values and does not require normalization to
  function correctly (though scaling is still applied for the z-score explainability
  layer, see below), which reduces preprocessing risk in a short build window.
- **Fast to train, fast to score.** Tree-based, no gradient optimization loop. Fits
  the 14-day timeline where iteration speed on feature choices matters more than
  squeezing out marginal detection performance.
- **Interpretable via path length.** The anomaly score is derived from average path
  length to isolate a point across trees — shorter paths mean more anomalous. This
  gives a natural per-sample anomaly score with no extra modeling step, which the
  per-feature z-score layer supplements with a feature-level explanation.

### Alternatives considered

- **One-Class SVM** — rejected for P1: sensitive to kernel/hyperparameter choice,
  more expensive to tune within the timeline, less naturally interpretable than
  isolation-forest path length.
- **Local Outlier Factor (LOF)** — rejected for P1: density-based, does not scale
  well to new/unseen points without recomputation against the reference set (no
  natural `.predict()` on new data without care), adds complexity not justified
  given the timeline.
- **Autoencoder** — explicitly out of scope per existing agent instructions (adds a
  training/tuning surface not justified for the 14-day window).

## Hyperparameters

The following are sweep candidates, not fixed values — none should be hardcoded
without a stated rationale once real data is available:

- `n_estimators` — `[TBD - pending experiment]`
- `contamination` — `[TBD - pending experiment; note this parameter affects the
  internal default threshold and interacts with the explicit thresholding step
  below — do not double-count]`
- `max_samples` — `[TBD - pending experiment]`

Sweep results, once run, must be recorded with the actual validation-split metric
used to pick them — never asserted from memory or intuition.

## Thresholding

- The anomaly-score-to-alert threshold is selected **only on a validation split**,
  held separate from both the normal-only training set and the final evaluation/test
  set.
- The threshold is never selected by looking at test-set performance. Any threshold
  value in code or docs must cite which split it was chosen against.
- Threshold selection method (e.g. percentile of validation anomaly scores, or a
  validation-set precision/recall tradeoff point) is `[TBD - pending experiment;
  depends on whether validation-set labels are available per 03-data-split-protocol.md]`.
