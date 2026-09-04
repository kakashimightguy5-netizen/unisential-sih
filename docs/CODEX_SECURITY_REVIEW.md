# CODEX SECURITY REVIEW

Reviewer role: `SECURITY_ARCHITECT`

Repository state inspected:

- `git status --short` shows uncommitted work in `README.md`, `.gitignore`, `.claude/`, and `docs/`
- current spec documents reviewed: `docs/01-threat-model.md`, `docs/04-model-and-threshold.md`, `docs/06-alert-schema.md`, `docs/07-scope-and-cuts.md`
- `AGENTS.md` reviewed first as requested

## Review Status

**BLOCKED**

The security review cannot be completed to a validated conclusion because the repository still lacks the documents that the current spec explicitly depends on for architecture-critical decisions:

- `docs/00-dataset-provenance.md`
- `docs/02-feature-schema.md`
- `docs/03-data-split-protocol.md`

Those documents are referenced by the current spec, but they are not present in the repository state I inspected. Without them, I cannot verify the exact observable fields, feature boundary, or leakage controls for the one-way traffic pipeline.

## Findings

### Finding ID: SCR-001
Severity: HIGH
Affected file: `docs/01-threat-model.md`, `docs/04-model-and-threshold.md`, `docs/06-alert-schema.md`
Issue: The current specification still describes threat classes and alert fields that depend on unconfirmed dataset capabilities, while the required dataset provenance and feature-schema documents are unavailable.
Evidence:
- `docs/01-threat-model.md` states that protocol/function-code violations require a function-code field and payload entropy anomalies require raw payload bytes, but both remain TBD.
- `docs/04-model-and-threshold.md` defers hyperparameter and threshold decisions until real data is available.
- `docs/06-alert-schema.md` defines `timestamp`, `source_id`, `threat_class_guess`, and `feature_contributions` as dataset-dependent placeholders.
- `docs/01-threat-model.md` explicitly references `docs/00-dataset-provenance.md` and `docs/02-feature-schema.md`, but those files are not present.
Why it matters: A unidirectional-traffic detector can only make defensible claims about what is observable in the actual data stream. Without the provenance and feature schema, there is a risk of over-claiming detection of fields that may not exist, which would weaken the architecture review and could lead to false cybersecurity claims.
Recommended correction: Add and review the missing dataset provenance and feature schema documents before finalizing any detection claims, alert fields, or model assumptions. Explicitly map each proposed detection target to confirmed observable fields only.

### Finding ID: SCR-002
Severity: MEDIUM
Affected file: `docs/01-threat-model.md`
Issue: The threat model correctly centers egress behavior, but it does not yet define the protected network, monitoring network, or sensor placement boundary with enough precision to validate the trust model.
Evidence:
- The document says the system sits behind a unidirectional network diode and observes outbound behavior.
- The document does not yet specify where packet capture occurs, which side is authoritative for labels/ground truth, or how the monitoring component is isolated from the protected side.
Why it matters: In a data-diode deployment, trust boundaries are part of the security claim. If sensor placement and authority are underspecified, later implementation could accidentally depend on information that is not actually available on the monitoring side or could blur the separation between protected and observing networks.
Recommended correction: Add a dedicated architecture section that names the protected network, the monitoring network, the diode boundary, capture point, and the trust assumptions for each component.

### Finding ID: SCR-003
Severity: MEDIUM
Affected file: `docs/06-alert-schema.md`
Issue: The alert contract includes `threat_class_guess` and `feature_contributions`, but the current documentation does not yet state how these explanations remain valid when only one direction of traffic is available.
Evidence:
- `docs/06-alert-schema.md` defines `threat_class_guess` as a heuristic label and `feature_contributions` as z-score-based explanation output.
- The spec does not yet document the exact one-way feature set or how those explanations exclude bidirectional or response-dependent features.
Why it matters: Explainability is mandatory, but an explanation layer is only defensible if it is derived strictly from observable one-way features. If the implementation later uses session context, ACK behavior, or reverse-direction timing, the alert explanation would misrepresent what the detector can actually see.
Recommended correction: Constrain the explanation schema to fields provably derived from one-way observations only, and document which explanation features are unavailable when reverse traffic is absent.

### Finding ID: SCR-004
Severity: LOW
Affected file: `docs/07-scope-and-cuts.md`
Issue: The scope document correctly restricts expansion, but it does not yet enumerate the security boundary for offline PCAPs, synthetic traffic, and isolated lab testing in a way that can be audited.
Evidence:
- The document says feature extraction must be bounded by what the real dataset supports.
- The document says feature invention and simulation are out of scope unless explicitly described.
- The document does not yet define acceptance rules for synthetic traffic versus recorded PCAPs, or how each source is labeled in reviews and demos.
Why it matters: Clear source labeling is needed to prevent accidental confusion between simulated one-way views and real deployment behavior. That is especially important in security reviews, where synthetic demonstrations can otherwise be mistaken for validated operational evidence.
Recommended correction: Add a short provenance and labeling policy that distinguishes authorized public datasets, offline PCAPs, synthetic/generated traffic, and any simulated unidirectional view.

## Unavailable or Not Yet Reviewable Documents

The following documents are currently unavailable in the repository state I inspected and are required before a full security architecture review can be completed:

- `docs/00-dataset-provenance.md`
- `docs/02-feature-schema.md`
- `docs/03-data-split-protocol.md`

## Conclusion

The current repository state is not yet sufficient for a full SECURITY_ARCHITECT sign-off. The threat model direction is reasonable for a unidirectional diode setting, but architecture-critical provenance and feature-boundary documents are missing, so the review remains blocked.
