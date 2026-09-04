# CODEX AI/DATA REVIEW

Reviewer role: `AI_DATA_REVIEWER`

Repository state inspected:

- `git status --short` shows uncommitted work in `README.md`, `.gitignore`, `.claude/`, `AGENTS.md`, and `docs/`
- current repository contents reviewed: `README.md`, `docs/01-threat-model.md`, `docs/04-model-and-threshold.md`, `docs/06-alert-schema.md`, `docs/07-scope-and-cuts.md`
- no dataset manifests, no feature schema, no split protocol, no ML code, and no `data/`, `packet_engine/`, or `ml/` implementation files were present in the current tree

## Review Status

**BLOCKED**

The repository does not yet contain the dataset provenance, feature schema, split protocol, or implementation artifacts required to verify the requested data and ML methodology. The existing specification is directionally sound, but it remains too incomplete to validate the actual observability of one-way traffic features or to assess leakage controls from evidence.

## Findings

### Finding ID: AID-001
Severity: HIGH
Affected file: `README.md`, `docs/01-threat-model.md`, `docs/07-scope-and-cuts.md`
Issue: The spec acknowledges the need for real dataset inspection, but the repository currently lacks the dataset provenance and feature schema needed to prove that the proposed detection targets are actually observable.
Evidence:
- `README.md` says pending items require real dataset inspection first: dataset provenance, feature schema, data split protocol, evaluation plan, architecture.
- `docs/01-threat-model.md` marks protocol/function-code violations, payload entropy anomalies, and volume/frequency anomalies as TBD pending real dataset confirmation.
- `docs/07-scope-and-cuts.md` states feature extraction must be bounded by what the real dataset supports and forbids inventing or simulating fields.
- No `data/` manifests, schema docs, or sample-record documentation were present in the repository contents I inspected.
Why it matters: The project’s detection claims cannot be evidence-backed until the team proves which fields exist, which traffic direction is observable, and whether the proposed features can be computed from the actual data source.
Recommended correction: Add dataset provenance documentation, a concrete feature schema, and sample-record evidence before finalizing any detection-target claims or feature engineering decisions.

### Finding ID: AID-002
Severity: HIGH
Affected file: `docs/01-threat-model.md`, `docs/06-alert-schema.md`
Issue: The current spec allows several threat classes and alert fields, but the repository does not yet show how those claims are constrained to one-way observations.
Evidence:
- `docs/01-threat-model.md` includes payload entropy and timing/volume anomalies, which may be valid only if raw bytes, timestamps, and windowing semantics are actually present.
- `docs/06-alert-schema.md` exposes `threat_class_guess` and `feature_contributions`, but the file does not yet tie those outputs to confirmed one-way-only features.
Why it matters: If the final implementation later relies on hidden bidirectional context, ACK-derived behavior, or session reconstruction, the detector would overstate what is actually being observed on a unidirectional link.
Recommended correction: Document the exact observable fields for one-way traffic and explicitly state which threat targets can and cannot be derived without reverse packets.

### Finding ID: AID-003
Severity: MEDIUM
Affected file: `docs/04-model-and-threshold.md`, `docs/07-scope-and-cuts.md`
Issue: The model plan selects Isolation Forest and normal-only training, but thresholding and validation methodology remain undecided and unevidenced.
Evidence:
- `docs/04-model-and-threshold.md` says threshold selection is only on a validation split, but the method is still TBD and depends on a missing `03-data-split-protocol.md`.
- `docs/07-scope-and-cuts.md` says no performance numbers or dataset facts may be stated until the ingestion/inspection step has been run and recorded.
Why it matters: Without a documented split protocol, the project is exposed to temporal leakage, duplicate-window leakage, and hidden threshold tuning on test data.
Recommended correction: Define and publish the split strategy before implementation, including how normal-only training, validation, and final evaluation are separated in time and by source.

### Finding ID: AID-004
Severity: MEDIUM
Affected file: `docs/04-model-and-threshold.md`, `docs/06-alert-schema.md`
Issue: The explanation plan is plausible, but the current documents do not yet prove that the feature contribution layer is derived only from non-leaky, one-way features.
Evidence:
- `docs/04-model-and-threshold.md` describes per-feature z-score explainability.
- `docs/06-alert-schema.md` defines `feature_contributions` and sorts them by `abs(z_score)`.
- Neither document currently shows the final feature list or how each feature is computed without leaking labels, future information, or reverse-direction state.
Why it matters: An explanation layer can become misleading if it includes features that were fit on test data, encode attack labels indirectly, or require unavailable reverse traffic.
Recommended correction: For every feature, document source field, computation window, fitting policy, and leakage risk before using it in alerts or evaluation.

### Finding ID: AID-005
Severity: LOW
Affected file: `docs/07-scope-and-cuts.md`
Issue: The scope document appropriately cuts backend and dashboard work, but it does not yet define evaluation criteria for the data/ML MVP.
Evidence:
- The approved P1 pipeline ends at CLI alert output and static plots.
- The document does not yet specify which metrics are required for the prototype demo beyond the general prohibition on fabricated performance numbers.
Why it matters: Without a minimum evaluation contract, the team could end up with a working pipeline that has no defensible way to report false positives, false negatives, or latency.
Recommended correction: Add a concise evaluation checklist that requires precision, recall, F1, false-positive rate, false-negative rate, and latency only after the real dataset and split protocol are available.

## Unavailable or Not Yet Reviewable

The following documents or implementation artifacts were not available in the repository state I inspected and are required for a complete AI/data review:

- `docs/00-dataset-provenance.md`
- `docs/02-feature-schema.md`
- `docs/03-data-split-protocol.md`
- `data/` manifests or sample inventory
- `packet_engine/` implementation
- `ml/` implementation

## Conclusion

The current repository state is not sufficient for AI/data sign-off. The high-level plan is acceptable for a unidirectional anomaly detector, but the evidence needed to verify dataset observability, leakage controls, and feature validity is still missing.
