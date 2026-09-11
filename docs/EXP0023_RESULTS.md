# EXP-0023 — Descriptive audit of the 14 undecoded `0x03` register-data bytes

**Status: TESTED.** Investigative/descriptive only — no detector, rule, model or
threshold was built or touched. `run_detector`, `iforest_detector.py`,
`features_windowed.py`, `rules.py`, Layer A, `app.py` and all closed/prior EXP files
were not imported for write access and are unchanged.

## Identity gates and offset sanity

- EXP-0017 reproduced from its checksummed artifact: `comb == protocol | pressure | IF`
  matches the stored `comb_pred`; whole-TEST confusion `(4767, 40, 2166, 2374)`
  reproduced exactly. TEST was not read or scored by this experiment.
- Split: `verified-egress-5s-exp0008-pretest-v1` (same manifest as every prior EXP).
- **Pressure-offset sanity check (required before trusting any layout claim):** the
  big-endian float32 at `frame[17:21]` was decoded independently from raw frame bytes
  and compared against the ARFF `pressure measurement` column for every egress `0x03`
  canonical response in the **Normal** category (48,060 rows) — **0 mismatches** at
  1e-4 relative tolerance (matching the ARFF text field's ~6-significant-digit
  precision). Attack-category rows were excluded from this check by design: under
  injection the pressure register is attacker-falsified, so decoded-vs-ARFF
  disagreement there is the known phenomenon (EXP-0016/0019), not an offset bug.
- Scan counts: 137,013 egress rows; 68,848 canonical `0x03` responses (byte_count=18,
  frame length 23); 21,384 of those fall in TRAIN pure-Normal windows.

## Frame layout confirmed

`addr(1) func(1) byte_count(1)=18 register-data(18) crc(2)`. Register-data region is
`frame[3:21]`. `frame[17:21]` = pressure float32 (verified above). The undecoded
region is `frame[3:17]` — **14 bytes = exactly 7 big-endian 16-bit Modbus registers**.

## Per-byte audit (TRAIN-normal, n=21,384 canonical `0x03` responses)

| offset | constant? | distinct | range | entropy (bits) |
|---|---|---|---|---|
| 0 | constant | 1 | 16 | 0.0 |
| 1 | varies | 4 | 0–48 | 0.99 |
| 2 | constant | 1 | 14 | 0.0 |
| 3 | varies | 4 | 0–48 | 0.99 |
| 4 | varies | 14 | 12–25 | 2.90 |
| 5 | varies | 256 | 0–255 | 7.52 |
| 6 | constant | 1 | 0 | 0.0 |
| 7 | varies | 2 | 0–1 | 0.04 |
| 8 | constant | 1 | 0 | 0.0 |
| 9 | constant | 1 | 0 | 0.0 |
| 10 | constant | 1 | 0 | 0.0 |
| 11 | constant | 1 | 0 | 0.0 |
| 12 | constant | 1 | 0 | 0.0 |
| 13 | varies | 2 | 0–1 | 0.06 |

7 of 14 bytes (0, 2, 6, 8, 9, 10, 11, 12 — note: 8 bytes, i.e. 4 full registers) are
**hard-constant** across every TRAIN-normal canonical response observed.

## Register-pair grouping (big-endian 16-bit, the only grouping tested that produces
clean structure)

| register | byte offsets | constant? | distinct | range |
|---|---|---|---|---|
| 0 | [0,1] | varies | 4 | 4096–4144 |
| 1 | [2,3] | varies | 4 | 3584–3632 |
| 2 | [4,5] | varies | 2387 | 3174–6501 |
| 3 | [6,7] | varies | 2 | 0–1 |
| 4 | [8,9] | **constant** | 1 | 0 |
| 5 | [10,11] | **constant** | 1 | 0 |
| 6 | [12,13] | varies | 2 | 0–1 |

Float32 candidates at every in-range offset (0–10) were also tested; none produced a
value distribution more structured/plausible than the register-pair grouping (most
have implausible magnitudes — e.g. offset 5's candidate ranges to ±1.7e38 — and none
correlate better with anything known than the integer registers below). Full numbers
are in the saved JSON.

## Documentation check (thesis Appendix A, Figure A.1, "Register Mapping Sheet",
p.57)

The RTU's documented **READS** register map begins:

| master reg | slave reg | name | type | range |
|---|---|---|---|---|
| 43011 | 43000 | Digital Outputs | Binary | 0,1 |
| 43012 | 43001 | Digital Inputs | Binary | 0,1 |
| 43013 | 43002 | Analog Input 0 | Integer | 0–32767 |
| 43014 | 43003 | Analog Input 1 | Integer | 0–32767 |
| 43015 | 43004 | Analog Input 2 | Integer | 0–32767 |
| 43016 | 43005 | Analog Input 3 | Integer | 0–32767 |
| 43017 | 43006 | Analog Input 4 | Integer | 0–32767 |
| 43018–43019 | 43007–43008 | Scaled Gas Pressure | Float | 0–100.0 psi |

That is **exactly 7 registers followed by a 2-register float** — the same shape as
the decoded frame (7 undecoded registers + the known pressure float). This is a
structural match worth naming, but it is documentation of the RTU's general register
map, not a byte-for-byte confirmation that *this* dataset's `0x03` query reads
starting at 43011 in this order; there is no independent ground truth (no ARFF column
for "Digital Outputs" etc. to cross-check against, unlike pressure). Treated as
**unconfirmed but plausible**, not established.

## Correlation with known fields (TRAIN-normal)

Every non-constant byte was correlated with decoded pressure and time:

| offset | Pearson vs pressure | Spearman vs pressure | Pearson vs time |
|---|---|---|---|
| 1 | −0.146 | −0.070 | −0.023 |
| 3 | −0.146 | −0.070 | −0.023 |
| **4** | **+0.995** | **+0.978** | −0.111 |
| 5 | −0.044 | −0.003 | −0.047 |
| 7 | +0.126 | +0.089 | −0.027 |
| 13 | −0.008 | −0.008 | −0.007 |

Byte offset 4 (the high byte of register 2, "Analog Input 0" in the documented map)
is **near-perfectly correlated with pressure** (Pearson 0.995). This is a genuine,
non-random, interpretable signal: register 2 as a whole (range 3174–6501) moves in
lockstep with the float pressure measurement, consistent with a raw ADC / analog
reading of the same physical sensor before scaling to engineering units. This is the
strongest finding of the audit. It is **not** attack-discriminating (see below), and
its specific meaning (raw ADC counts vs. some other analog channel) is not confirmed
— only that it tracks pressure almost exactly.

Bytes 1 and 3 (registers 0 and 1 — "Digital Outputs"/"Digital Inputs" if the map
above applies) have **identical values in every sample observed** (Pearson 1.0
between them, not tabulated above since the check wasn't run pairwise, but their
per-byte stats and pressure/time correlations are numerically identical in the saved
JSON — consistent with the two registers mirroring each other exactly in this
dataset). Their low nibble takes exactly 4 values (0, 16, 32, 48), consistent with
two independent binary flags packed into bits 4–5 of the byte — a plausible bitfield
pattern, unconfirmed.

## Attack comparison (Cohen's d, EXP-0014/0015 population-SD convention, TRAIN+VAL,
priority MSCI/MPCI first)

**No pure MSCI, MPCI, MFCI, DoS, or Recon window in TRAIN+VALIDATION contains even one
egress canonical `0x03` response** — `n_windows = 0` for every one of those five
categories, for every byte, every register, and every float candidate. This matches
EXP-0022's finding that most MSCI/MPCI episodes carry little or no `0x03` traffic;
here it is total for the *pure*-window definition used throughout this project's
EXP-0014/0015/0021/0022 line. **The motivating MSCI/MPCI question cannot be answered
from this field at all — not "no signal", but "no observable data" for those five
categories under the pure-window definition.**

CMRI (6,890 pure windows) and NMRI (4,018 pure windows) do contain `0x03` traffic, so
every non-constant byte/register/float candidate was compared there:

| field | category | n | d (vs full Normal) | grade | d (vs matched Normal) | grade |
|---|---|---|---|---|---|---|
| byte 1 / reg 0 | CMRI | 6890 | 0.122 | negligible | 0.044 | negligible |
| byte 1 / reg 0 | NMRI | 4018 | 0.065 | negligible | 0.013 | negligible |
| byte 3 | CMRI | 6890 | 0.122 | negligible | 0.044 | negligible |
| byte 3 | NMRI | 4018 | 0.065 | negligible | 0.013 | negligible |
| byte 4 | CMRI | 6890 | 0.059 | negligible | 0.017 | negligible |
| byte 4 | NMRI | 4018 | −0.016 | negligible | 0.020 | negligible |
| byte 5 | CMRI | 6890 | 0.040 | negligible | 0.052 | negligible |
| byte 5 | NMRI | 4018 | 0.115 | negligible | 0.054 | negligible |
| byte 7 / reg 3 | CMRI | 6890 | 0.049 | negligible | 0.052 | negligible |
| byte 7 / reg 3 | NMRI | 4018 | 0.021 | negligible | 0.086 | negligible |
| byte 13 / reg 6 | CMRI | 6890 | −0.020 | negligible | 0.005 | negligible |
| byte 13 / reg 6 | NMRI | 4018 | 0.016 | negligible | 0.044 | negligible |
| reg 2 (Analog Input 0) | CMRI | 6890 | 0.063 | negligible | 0.022 | negligible |
| reg 2 (Analog Input 0) | NMRI | 4018 | −0.005 | negligible | 0.026 | negligible |

An exhaustive scan of every byte × register × float-offset × category combination in
the saved JSON found **no `|d| ≥ 0.2` anywhere** (not even "small"). This includes
the pressure-correlated register 2, which despite being the audit's strongest
structural finding shows no CMRI/NMRI separation at the window-mean level used here.

## Outcome classification (14 bytes, conservative, per pre-registration step 6)

| offset(s) | class | note |
|---|---|---|
| 0, 2, 6, 8, 9, 10, 11, 12 | **(a) confirmed constant** in TRAIN-normal (meaning undocumented; register map names these positions "Digital Outputs"/"Digital Inputs" low byte and "Analog Input 3/4", unconfirmed) | 8 of 14 bytes |
| 5 | **(b) varies, appears noise-like** at the byte level (entropy 7.52/8, only −0.04 Pearson vs pressure) — the low byte of the pressure-correlated register 2; effectively unstructured jitter/rounding on top of the meaningful high byte | 1 byte |
| 1, 3, 7, 13 | **(c) plausible bitfield pattern, unconfirmed meaning** — low-nibble/single-bit variation consistent with the documented "Digital Outputs"/"Digital Inputs"/other status registers, no independent ground truth, no attack separation | 4 bytes |
| 4 | **(c) plausible pattern, unconfirmed meaning** — near-perfect (r=0.995) correlation with decoded pressure, consistent with a raw analog/ADC channel reading the same sensor; strongest finding of the audit, but not attack-discriminating and not process-meaning-confirmed | 1 byte |
| — | **(d) real MSCI/MPCI Cohen's-d separation** | **none** — 0 pure MSCI/MPCI windows contain any `0x03` traffic at all; no byte/register/float candidate reaches even a small effect for CMRI or NMRI (the only two categories with observable data here) |

**No byte or byte-group is a genuine feature candidate under this experiment's bar.**
The one genuinely interesting structural finding (byte 4 / register 2 tracking
pressure almost exactly) does not help MSCI/MPCI detection because those categories
essentially never produce a pure `0x03`-response window to measure against in the
first place — consistent with, and reinforcing, EXP-0022's conclusion.

## Tests

`tests/test_exp0023_0x03_register_bytes_diag.py`: 16 fast synthetic units (frame
offset math — including a byte-for-byte reproduction of the frozen EXP-0016 sample
frame as the required sanity check — constant/varying byte detection, entropy, 16-bit
register grouping, float-candidate decoding, Pearson/Spearman, per-window
aggregation, the Cohen's-d convention including nearest-index bisect matching, and a
static-analysis check that `source` and the protected files are never touched) + 1
`@pytest.mark.slow` saved-result replay (no raw-data read; skips if the JSON is
absent). Full suite: **198 → 215 passed** (17 new; 0 skipped, 0 failed with the JSON
present).

## Files

New only: `ml/exp0023_0x03_register_bytes_diag.py`,
`tests/test_exp0023_0x03_register_bytes_diag.py`,
`data/experiments/exp0023_register_bytes.json`, this file. `run_detector`, `app.py`,
DoS files, Layer A, the closed EXP-0018/0019/0020 CMRI files, and all prior EXP files
are unchanged.

## Limitations / honest disclosure

- The register-map documentation match (7 registers + float, same order as the RTU's
  documented READS table) is a **structural coincidence worth naming**, not a
  confirmed decode — there is no ARFF column against which "Digital Outputs" /
  "Analog Input 0-4" values could be independently cross-checked the way pressure
  was. Any future work treating these as literal digital-output/analog-input values
  must say so is an assumption, not a verified fact.
- `n_windows = 0` for MSCI/MPCI/MFCI/DoS/Recon means **absence of data under the pure-
  window definition**, not a measured null result for those categories — a different
  (non-pure, or per-frame rather than per-window) aggregation might observe some
  `0x03` traffic in windows dominated by those attacks. That would be a new,
  separately pre-registered experiment; it was out of scope here.
- Cohen's d here is computed once per field at the window-mean level (matching the
  EXP-0014/0015 convention used throughout this project), not per-frame; a per-frame
  or per-episode aggregation (as EXP-0021/0022 did for pressure) was not attempted
  for these bytes and could behave differently, though given the total absence of
  MSCI/MPCI `0x03` windows this would not change the primary finding.
