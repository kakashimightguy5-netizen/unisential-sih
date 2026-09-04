<!-- Superseded for scope/scenarios by 03_THREAT_MODEL.md (which carries the tier tags,
     the full element list, and the trust-boundary diagram). This file's core framing
     — inbound physically impossible, egress exfiltration is the real threat — is
     unchanged and still correct. The three [TBD] markers below are answered by
     02-feature-schema.md / 04_DATASET_PLAN.md: class 1 SUPPORTED, class 2 PARTIALLY
     SUPPORTED, class 3 SUPPORTED. -->

# Threat Model

## Context

The system under protection sits behind a **unidirectional network diode**: hardware
enforces that no traffic can flow inbound to the protected (secure) side. This makes
classic inbound-facing threats (external scanning, inbound exploitation, C2 inbound
callbacks) structurally impossible and out of scope.

## The actual threat

Because inbound is physically blocked, the only realistic threat vector is **egress
exfiltration or signaling from an already-compromised device on the protected side**,
riding on traffic that is permitted to leave across the diode. The attacker is assumed
to already have a foothold internally (via removable media, insider action, supply
chain, etc. — the compromise vector itself is out of scope for this system). This
system's job is to detect anomalous *outbound* behavior on the diode-crossing link,
not to prevent the initial compromise.

## P1 threat classes

1. **Protocol / function-code violations** — traffic that violates expected protocol
   structure for the environment, e.g. unexpected or malformed Modbus function codes,
   out-of-spec field values. Requires a field identifying protocol function code.
   `[TBD - confirm against real dataset: does the dataset expose a function-code or
   equivalent protocol-op field?]`
2. **Payload entropy anomalies** — outbound payloads with entropy inconsistent with
   expected traffic (e.g. compressed/encrypted exfiltration data riding on a protocol
   that normally carries structured low-entropy telemetry). Requires raw payload bytes.
   `[TBD - confirm against real dataset: are raw payload bytes present, or only
   pre-extracted numeric fields?]`
3. **Volume / frequency anomalies** — deviations in packet rate, byte volume, or timing
   over a window, consistent with staged or bulk exfiltration. Requires timestamps
   (or ordered sequence) and size/count fields.
   `[TBD - confirm against real dataset: are per-record timestamps present at
   sufficient resolution to construct windows?]`

**Note:** it is expected that not all three classes will be fully supported by the
final dataset. Per the approved P1 scope (`07-scope-and-cuts.md`), the pipeline
proceeds with whichever threat classes the dataset's actual fields support, and this
document will be updated once `00-dataset-provenance.md` and `02-feature-schema.md`
are written from real inspection output. No threat class should be assumed
detectable until its required fields are confirmed present.

## Explicitly out of scope for this system

- Preventing or detecting the initial compromise of the internal device.
- Inbound-direction threats (structurally blocked by the diode).
- Attribution of the attacker beyond flagging anomalous egress behavior.
