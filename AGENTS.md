# AGENTS.md

## Repository Context

- Project: Smart India Hackathon 2026
- Problem Statement: SIH26145
- Organization: NTRO
- Title: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
- Internal hackathon deadline: 2026-09-15

This repository is in **engineering specification only** phase. Do not start application development unless explicitly instructed.

## Core Interpretation

The system detects cyber threats in **unidirectional IP traffic** only.

The detector may observe only one direction of communication, so do not depend on:

- request-response correlation
- full bidirectional TCP session behavior
- reverse traffic
- acknowledgements from the opposite direction

Target context: critical infrastructure / OT / ICS environments using a data-diode-style unidirectional gateway.

## Current Detection Targets

Initial targets are:

1. protocol violations
2. unusual ports/services
3. unusual ICS function codes where available
4. packet-volume/frequency anomalies
5. inter-arrival/timing anomalies
6. payload entropy anomalies
7. unusual traffic behavior potentially associated with unauthorized data transfer

## Approved Approach

Use the following staged approach only:

- Stage 0: rule/statistical baseline
- Stage 1: Isolation Forest
- Stage 2: Autoencoder comparison, only if justified and time permits

Explainability is mandatory. Any alert must state why traffic was considered anomalous.

## Data Rules

Do not fabricate:

- datasets
- attack labels
- accuracy
- benchmark results
- model capability
- citations
- experimental results

Always distinguish between:

- PLANNED
- IMPLEMENTED
- TESTED
- VALIDATED

Dataset provenance must be documented. If a simulation of a unidirectional or data-diode view is used, it must be explicitly described as a simulation.

Prevent:

- train/test leakage
- temporal leakage
- attack leakage into normal-only training data
- feature leakage

## Security Boundary

Development and testing are restricted to:

- authorized public datasets
- offline PCAP files
- synthetic/generated traffic
- isolated local lab environments

Do not scan, probe, attack, or exploit third-party systems.

## Repository Responsibilities

- `docs/`: engineering specifications and reviews
- `data/`: dataset manifests and local data; large raw datasets must not be committed to Git
- `packet_engine/`: packet parsing, direction filtering, windowing, and feature extraction
- `ml/`: training, inference, thresholds, explainability, and evaluation
- `backend/`: API and application services
- `frontend/`: SOC-style monitoring dashboard
- `tests/`: unit, integration, regression, and demo tests

## Codex Review Roles

When reviewing the repository, use these lenses:

### SECURITY_ARCHITECT

Review:

- threat model
- data-diode assumptions
- OT/ICS interpretation
- observable vs non-observable information
- trust boundaries
- realistic detection claims

### AI_DATA_REVIEWER

Review:

- dataset provenance
- dataset format
- one-way filtering method
- feature engineering
- leakage
- model selection
- threshold methodology
- evaluation
- explainability

### QA_REVIEWER

Review:

- contradictions between documents
- unsupported claims
- missing requirements
- missing tests
- unrealistic scope
- demo reliability

When reporting findings, use:

- Finding ID:
- Severity: BLOCKER / HIGH / MEDIUM / LOW
- Affected file:
- Issue:
- Evidence:
- Why it matters:
- Recommended correction:

## Git Safety

Before modifying shared files:

- inspect `git status`
- inspect relevant files
- avoid destroying another agent’s uncommitted work

Never commit:

- API keys
- passwords
- secrets
- virtual environments
- model weights
- large raw datasets
- sensitive packet captures

## Scope Discipline

The MVP should eventually demonstrate:

PCAP replay -> unidirectional filtering -> feature extraction -> anomaly detection -> explainable alert -> clear demo output

Do not expand scope without explicit approval.

For now, keep work limited to documentation and specification changes unless the user explicitly requests implementation.
