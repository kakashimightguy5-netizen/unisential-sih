# 10 — Demo & Success Criteria (Internal Hackathon, 2026-09-15)

Demo scope = **Tier 1 (MVP) only**. Nothing in the demo depends on a Tier 2/3
feature. If a metric is not yet produced by a recorded experiment, the demo shows the
*mechanism* and states clearly that quantitative evaluation is pending the dataset
blockers (`04_DATASET_PLAN.md`).

**Presentation surface (two possible forms — decided at the 2026-09-11 go/no-go,
`DECISION_LOG.md`):**
- **Form A (target):** a **Streamlit / Gradio single-page app** reading the backend
  API / SQLite store. Used if the core pipeline has a validated `EXPERIMENT_LOG.md`
  entry by 2026-09-11.
- **Form B (pre-agreed fallback):** **CLI output + matplotlib static plots**, demo
  driven from the terminal with pre-rendered figures. Used if the core pipeline is
  not validated by 2026-09-11.

The success criteria below (S-1 … S-8) are written to be satisfiable in **either**
form — "dashboard green/red" in Form B means the CLI severity line + the plotted
anomaly-score trace crossing the threshold marker. The baseline-vs-ML comparison
(S-6) in Form B is a printed table + a side-by-side plot.

---

## Demo Narrative

```
1. Normal traffic replay
        ↓
   Dashboard GREEN — low anomaly score, 0 alerts, stable stats
        ↓
2. Switch to abnormal / attack-labelled traffic replay
        ↓
   Feature deviation occurs (rate / function-mix / timing / entropy)
        ↓
   Isolation Forest anomaly score rises past the calibrated threshold
        ↓
   Alert turns RED — severity shown
        ↓
   Dashboard explains WHY: top feature deviations, observed value vs baseline value
        ↓
3. Baseline-vs-ML comparison moment
        ↓
   Show a window where the naive threshold rule MISSES (or FALSE-ALARMS)
   and the Isolation Forest is correct — with the explanation panel proving why
```

## What the Judge Can See on Screen

| Element | Where | Tier |
|---|---|---|
| Incoming (replayed) traffic, packet-by-packet or per-window | dashboard live panel | T1 |
| Packet / traffic statistics (pps, bytes/s, window count, inbound discarded = all) | stats panel | T1 |
| Current AI anomaly score (normalized 0–1) | score gauge | T1 |
| Severity (INFO→CRITICAL, green/red) | severity indicator | T1 |
| Explanation for each alert (feature, observed value, baseline value, deviation) | alert detail panel | T1 |
| Alert timeline | timeline strip | T1 |
| Normal vs anomalous behaviour, side by side | comparison view | T1 |
| Naive baseline verdict vs ML verdict per window | comparison view | T1 |

## Demo Assets (prepared in advance, provenance recorded)

- **Normal clip** — egress-filtered windows from the normal time range, held out of
  training.
- **Attack clip(s)** — egress-filtered windows from attack-labelled time ranges.
  On the gas-pipeline dataset the reliably-detected categories are **MFCI** and
  **Recon** (~100 %, rule layer); the demo attack clip **must** be drawn from those,
  since S-3 requires an alert (`06_AI_MODEL_EVALUATION_PLAN.md`, "Recall is
  structurally bimodal …"). MSCI/MPCI/CMRI/NMRI/DoS clips may be shown *alongside* as
  the honest "not detectable from one direction" demonstration for S-7, not for S-3.
  An entropy-on-payload fixture covers TS-5. Labelled: *simulated unidirectional view
  of a bidirectional dataset — not real diode data.*
- **Comparison window** — one pre-identified window where baseline ≠ correct and IF =
  correct (from `EXPERIMENT_LOG.md` T-18).
- A one-slide statement of the **novelty claim** and the **honest limitations**
  (no real diode dataset; entropy is one signal; per-attack-type honesty; blockers).

## Objective Success Criteria (MVP / Tier 1 scope)

The demo is a **success** if **all** of the following hold:

1. **S-1** The full Tier 1 pipeline runs end-to-end, offline, on the prepared clips,
   with no crash and no network access.
2. **S-2** On the normal clip: **0 alerts**, dashboard green, score stays below the
   calibrated threshold for every window.
3. **S-3** On the attack clip: **≥ 1 window alerts**, dashboard goes red, severity is
   shown.
4. **S-4** Every alert shown carries a feature-level explanation with **observed
   value and baseline value** (no bare-score alerts).
5. **S-5** The threshold in use displays its provenance (VALIDATION block + experiment
   ID).
6. **S-6** The baseline-vs-ML comparison view shows at least one window where the
   naive threshold rule is wrong and the Isolation Forest is right, with the
   explanation panel supporting it.
7. **S-7** The team can state, on request: the novelty claim, that the diode
   constraint is simulated, that entropy is one signal among several, and which
   attack types the MVP is *not* expected to catch.
8. **S-8** If the model artifact is removed mid-demo, the system degrades visibly
   (baseline-only, degraded banner) rather than crashing (`T-11`).

### Stretch (only if Tier 2 was built and validated)

- **S-9** A Tier 2 feature (e.g. IAT histogram distance) catches a window that the
  Tier 1 features alone miss, shown in the comparison view — explicitly framed as a
  stretch result.

## Explicitly NOT Required for Demo Success

- Any specific accuracy / precision / recall number (report only what
  `EXPERIMENT_LOG.md` contains by demo day; "evaluation pending the first recorded
  experiment / artifact audit" is an acceptable honest state — BLOCKER 1 no longer
  gates it).
- Any Tier 2 or Tier 3 capability.
- A hardened / multi-user / authenticated deployment.
- Live capture.

## Failure Conditions (demo is NOT a success)

- Any component makes a network call.
- An alert is shown with no explanation.
- The normal clip produces alerts (baseline not calibrated / leakage).
- A threshold or metric is shown without provenance.
- Any claim is made that the data is real diode traffic, or that a Tier 2/3 feature
  is implemented when it is not.
