<!-- PLANNING DOCUMENT — no code, docs, or data files have been changed by this plan.
     Produced 2026-09-08. Review before any step is executed. -->

# EXP-0004 Recovery Plan — retract the fabricated raw TXT, adopt the verified row-aligned file

**Status:** DRAFT FOR REVIEW. Nothing below has been executed. This document is the
only file created. No `data/` directory, no moves, no doc edits, no code changes have
been made.

## 0. Summary of the situation (as verified 2026-09-08)

| | Old file | New file |
|---|---|---|
| repo name | `data/raw/gas_pipeline_raw.txt` (referenced in docs; **not present locally**) | `gaspipeline2-raw.txt` (loose in project root) |
| sha256 | `45de4266d75553c8e658113ec4d43967c1de3ddaf38bb7022ad0a135b635fbbd` (from provenance doc) | `ce2d69e3ada867b498a1db4560d609c35d23667f4f5cf2dea57ddd63fe7d93e3` (measured today) |
| bytes | 14,234,301 (from provenance doc) | 18,627,186 (measured today) |
| data rows | 209,668 | **274,628** |
| schema | `hexframe,categorized,specific,source,destination,timestamp` (6 fields) | **identical** 6-field schema |
| provenance | pasted into an earlier AI chat that was told to "proceed"; hash recorded as if verified. Confirmed **AI-generated / fabricated**. | independently verified row-aligned to `IanArffDataset.arff` — see §3 |

**Verification I ran today (read-only, `scratchpad/analyze.py` + `scratchpad/align.py`):**

- New file: 274,628 lines, **0** lines with a field count ≠ 6, timestamps strictly
  non-decreasing (0 out-of-order), attack rate 60,048 / 274,628 = **21.87%**.
- New file `categorized` histogram: `{0:214580, 1:7753, 2:13035, 3:7900, 4:20412,
  5:4898, 6:2176, 7:3874}` — **exactly** the local ARFF `categorized result` domain
  recorded in `00-dataset-provenance.md`.
- Row-for-row vs `IanArffDataset.arff` (274,628 rows each, file order):
  - `timestamp` mismatches: **0**
  - `categorized` mismatches: **0**
  - `specific` mismatches: **0**
  - new-file `destination` ↔ ARFF `command response`: perfect bijection —
    `destination==1` ⇔ `command response==0` (137,013 rows, the response/egress
    direction); `destination==3` ⇔ `command response==1` (137,615 rows). This
    **also independently re-confirms BLOCKER 2** (egress = response direction) and
    the existing `EGRESS_DESTINATION = 1` constant in `ml/features_windowed.py`.
- `IanArffDataset.arff` in the project root: sha256
  `970a7bcd3949d09ac7baff11603538b142f214ee47ed70baf9efb3344f4af459`, 18,340,346
  bytes — **matches** `00-dataset-provenance.md` exactly. It is the authoritative
  file, just in the wrong location.
- There is no `data/` directory yet (gitignored — expected).

Conclusion: the new file is genuine, row-aligned companion data to the authoritative
ARFF, carrying the payload bytes the ARFF lacks. It supersedes the fabricated file and
**dissolves BLOCKER 3**.

---

## 1. FILE ORGANISATION

### 1.1 Confirm the new file's real name / extension — DONE

`dir` of the project root shows the file is **`gaspipeline2-raw.txt`** (note the
`.txt` extension is real; the task brief's `"gaspipeline2-raw"` was missing it). It
is plain ASCII text, one `\n`-terminated record per line, LF line endings, no BOM,
no header row. Size 18,627,186 bytes. Confirmed decodable: every line's field 1 is
valid hex, `bytes.fromhex()` succeeds on all 274,628.

### 1.2 Target filenames (code-expected)

`ml/features_txt.py` line 33:

```python
RAW_TXT = Path(__file__).resolve().parent.parent / "data" / "raw" / "gas_pipeline_raw.txt"
```

`docs/00-dataset-provenance.md` and `scripts/inspect_dataset.py` (line 31) also
expect `data/raw/gas_pipeline_raw.txt` and `data/raw/IanArffDataset.arff`.

**Decision: the NEW file takes the canonical name `data/raw/gas_pipeline_raw.txt`.**
The old (fabricated) file vacates that name and becomes
`data/raw/RETRACTED_gas_pipeline_raw.txt`. This keeps `RAW_TXT` unchanged — zero code
edits for path — and the retraction is unambiguous in the filename.

> Alternative considered and rejected: name the new file `gas_pipeline_raw_v2.txt`
> and update `RAW_TXT`. Rejected because it spreads a rename across code + tests +
> 3 docs for no benefit; the `RETRACTED_` prefix already disambiguates.

### 1.3 Exact commands (PowerShell, run from the project root)

```powershell
# 1. create the raw data dir (gitignored; local only)
New-Item -ItemType Directory -Force -Path .\data\raw | Out-Null

# 2. verify the two loose files BEFORE moving (fail loudly on mismatch)
if ((Get-FileHash .\IanArffDataset.arff -Algorithm SHA256).Hash -ne `
    '970A7BCD3949D09AC7BAFF11603538B142F214EE47ED70BAF9EFB3344F4AF459') { throw 'ARFF hash mismatch' }
(Get-FileHash .\gaspipeline2-raw.txt -Algorithm SHA256).Hash.ToLower()   # expect ce2d69e3ada867b498a1db4560d609c35d23667f4f5cf2dea57ddd63fe7d93e3
(Get-Item .\gaspipeline2-raw.txt).Length                                 # expect 18627186

# 3. move ARFF into place
Move-Item .\IanArffDataset.arff .\data\raw\IanArffDataset.arff

# 4. move the NEW verified TXT into the canonical code-expected name
Move-Item .\gaspipeline2-raw.txt .\data\raw\gas_pipeline_raw.txt

# 5. mark read-only (matches "everything under data/raw/ is read-only")
Set-ItemProperty .\data\raw\IanArffDataset.arff    -Name IsReadOnly -Value $true
Set-ItemProperty .\data\raw\gas_pipeline_raw.txt   -Name IsReadOnly -Value $true
```

### 1.4 The old fabricated file

The old `gas_pipeline_raw.txt` (sha256 `45de4266…fbbd`) is **not in the working tree**
(no `data/` dir exists, and it is gitignored so it is not in history either). Two cases:

- **If a copy is recoverable** (earlier chat attachment, a backup, `data/reconnaissance/`
  on another machine): place it at `data\raw\RETRACTED_gas_pipeline_raw.txt` — never at
  the canonical name — after confirming its hash is `45de4266…fbbd`. Mark it read-only.
- **If no copy is recoverable:** record that fact in the provenance doc and decision
  log (the retraction stands on documentation alone; the hash is the identifier).
  Do **not** synthesise a placeholder.

```powershell
# only if a verified copy of the old file is in hand as .\OLD_gas_pipeline_raw.txt
if ((Get-FileHash .\OLD_gas_pipeline_raw.txt -Algorithm SHA256).Hash.ToLower() -ne `
    '45de4266d75553c8e658113ec4d43967c1de3ddaf38bb7022ad0a135b635fbbd') { throw 'not the retracted file' }
Move-Item .\OLD_gas_pipeline_raw.txt .\data\raw\RETRACTED_gas_pipeline_raw.txt
Set-ItemProperty .\data\raw\RETRACTED_gas_pipeline_raw.txt -Name IsReadOnly -Value $true
```

---

## 2. RETRACTION TEXT

### 2.1 Append to `docs/DECISION_LOG.md` (top of the entries, above the 2026-09-04 DoS entry)

```markdown
### 2026-09-08 · RETRACTION — `gas_pipeline_raw.txt` (sha256 45de4266…fbbd) was AI-generated, not a capture; EXP-0001/0002/0003 retracted

- **Decision:** the raw hex-frame file used by EXP-0001, EXP-0002 and EXP-0003
  (`data/raw/gas_pipeline_raw.txt`, sha256
  `45de4266d75553c8e658113ec4d43967c1de3ddaf38bb7022ad0a135b635fbbd`, 14,234,301
  bytes, 209,668 rows) is **confirmed AI-generated / fabricated content**, not a
  genuine testbed capture. It was pasted into an earlier AI chat session that was
  asked to "proceed" with it, and its hash was then recorded in
  `00-dataset-provenance.md` as if it had been provenance-verified. It never was.
  The file is **retracted**. It is renamed to
  `data/raw/RETRACTED_gas_pipeline_raw.txt` (not deleted — kept for the audit
  trail) and must never again be an input to any pipeline stage.
- **What was re-checked (2026-09-08):** 0% of the file's frames' trailing two bytes
  validate as a Modbus CRC-16 in either byte order. **This CRC check is not
  conclusive on its own** — the new genuine file (§below) shows the *same* 0% CRC
  signature, so a failed CRC does not by itself prove fabrication. The deciding
  evidence is the **confirmed origin** (pasted AI output, no capture provenance),
  not the CRC result.
- **Consequence:** EXP-0001, EXP-0002 and EXP-0003 in `EXPERIMENT_LOG.md` are
  marked **RETRACTED** (banner prepended, entries kept for audit). Every
  performance number they produced — the EXP-0002 "headline" IF recall 0.136 /
  combined 0.141, the EXP-0003 DoS effect sizes, DIAG-0001's XGBoost ceiling — is
  withdrawn and must not appear on any slide, README, or spec as a result. The
  exact-reproduction constants in `tests/test_detector.py` are now baselined
  against a retracted file and are invalid until EXP-0004 rebaselines them.
- **What is NOT affected:** `IanArffDataset.arff` (sha256 `970a7bcd…f459`) was
  always the authoritative file and is untouched. BLOCKER 1 (label codebook) and
  BLOCKER 2 (direction semantics) were resolved from the Turnipseed 2015 thesis and
  the ARFF, not from the retracted TXT — they still stand.
- **Options considered:** (a) silently replace the file and keep the experiment
  numbers; (b) delete the file and the experiment entries; (c) retract openly,
  keep the entries with a banner, re-run as EXP-0004. **Chosen (c)** — silent
  replacement would repeat the exact integrity failure being corrected, and
  deleting the entries destroys the audit trail of how the error entered.
- **Impact:** `00-dataset-provenance.md` (file inventory + CORRECTION section +
  BLOCKER 3), `EXPERIMENT_LOG.md` (retraction banners on EXP-0001/0002/0003 +
  DIAG-0001 + new EXP-0004), `tests/test_detector.py` (constants invalid pending
  EXP-0004), `README.md` / any doc quoting EXP-0002 numbers.
```

### 2.2 Append to `docs/EXPERIMENT_LOG.md`

**(a) New section immediately under the title `# Experiment Log`:**

```markdown
> ## ⚠️ RETRACTION NOTICE — 2026-09-08
>
> **EXP-0001, EXP-0002, EXP-0003 and DIAG-0001 are RETRACTED.** They were all run on
> `data/raw/gas_pipeline_raw.txt` (sha256 `45de4266…fbbd`), which has since been
> confirmed to be **AI-generated / fabricated content**, not a genuine capture (see
> `DECISION_LOG.md` 2026-09-08). Every metric, effect size, threshold and
> per-category number in those entries is **withdrawn**. The entries are kept below,
> unedited except for a per-entry banner, purely as an audit trail of the error.
>
> Replacement work: **EXP-0004** (below), run on the verified row-aligned file
> `data/raw/gas_pipeline_raw.txt` (sha256 `ce2d69e3…93e3`, 274,628 rows), which is
> confirmed row-for-row aligned to `IanArffDataset.arff`.
```

**(b) Banner to prepend to EACH of EXP-0001, EXP-0002, EXP-0003, and DIAG-0001**
(immediately after the `### EXP-000x …` / `### DIAG-0001 …` heading line):

```markdown
> **🚫 RETRACTED 2026-09-08.** Run on the fabricated file `gas_pipeline_raw.txt`
> (sha256 `45de4266…fbbd`). All numbers in this entry are withdrawn. Retained for
> audit only. See the RETRACTION NOTICE at the top of this file and `DECISION_LOG.md`
> 2026-09-08. Do not cite any figure below.
```

**(c) Pre-registration §2 note** — add one line under the existing "AMENDED /
WITHDRAWN" text:

```markdown
   *2026-09-08:* the EXP-0001 measurement cited as the basis for admitting entropy
   to the headline was run on the retracted file. Whether entropy earns a headline
   slot is **re-opened** and must be decided by EXP-0004 on the verified file (§EXP-0004
   pre-registration below), not inherited.
```

---

## 3. NEW FILE ADOPTION — `docs/00-dataset-provenance.md` changes

### 3.1 File inventory table — replace the `gas_pipeline_raw.txt` row

```markdown
| `data/raw/IanArffDataset.arff` | 18340346 | `970a7bcd3949d09ac7baff11603538b142f214ee47ed70baf9efb3344f4af459` | **AUTHORITATIVE** |
| `data/raw/gas_pipeline_raw.txt` | 18627186 | `ce2d69e3ada867b498a1db4560d609c35d23667f4f5cf2dea57ddd63fe7d93e3` | **AUTHORITATIVE — row-aligned companion to the ARFF (payload bytes)** |
| `data/raw/RETRACTED_gas_pipeline_raw.txt` | 14234301 | `45de4266d75553c8e658113ec4d43967c1de3ddaf38bb7022ad0a135b635fbbd` | **RETRACTED — AI-generated, see DECISION_LOG 2026-09-08. Not an input to anything.** |
| `data/processed/gas_pipeline_ml_ready.csv` | 11349508 | `53d501c63362c25af3b3de702b1a99220af251d00d3afe93e5698ffdf2fc924d` | **DISCARD** |
```

### 3.2 New subsection — insert after "The ARFF-vs-TXT discrepancy"

```markdown
## NEW AUTHORITATIVE RAW FILE (2026-09-08) — row-aligned to the ARFF

`data/raw/gas_pipeline_raw.txt` was replaced on 2026-09-08. The previous file at this
path (sha256 `45de4266…fbbd`) was fabricated and is retracted (DECISION_LOG 2026-09-08).
The current file is a genuine, independently-verified companion to the authoritative
ARFF.

**Measured facts (this file):**
- sha256 `ce2d69e3ada867b498a1db4560d609c35d23667f4f5cf2dea57ddd63fe7d93e3`
- 18,627,186 bytes
- 274,628 data rows; 0 rows with a field count ≠ 6
- 6 fields: `hexframe , categorized_attack{0-7} , specific_attack{0-35} , source , destination , timestamp`
- timestamps strictly non-decreasing in file order (0 out-of-order); range
  1418682163.170388 .. 1418957854.165377 — **the full ARFF span**, not the truncated
  range of the retracted file
- attack rate 60,048 / 274,628 = 21.87%
- `source` domain `{1,2,3}` counts `{1:117664, 2:40739, 3:116225}`
- `destination` domain `{1,3}` counts `{1:137013, 3:137615}`
- function-code histogram (byte 1) matches the ARFF audit profile: `0x03:137696`,
  `0x10:128200`, `0x08:3123`, `0x88:2521`, `0xAB:1024`, `0x2B:1024`, plus the
  "exactly-40" tail; slave-address histogram dominated by address 4 (274,026) with
  the same 32-count tail the ARFF shows.

**Verification evidence — this is an independent alignment check, not "trust me":**
row-for-row comparison against `data/raw/IanArffDataset.arff` (both 274,628 rows, in
file order), performed 2026-09-08:

| check | result |
|---|---|
| row count | 274,628 == 274,628 |
| `timestamp` (TXT field 6) vs ARFF `time` | **0** mismatches across all 274,628 rows |
| `categorized_attack` (TXT field 2) vs ARFF `categorized result` | **0** mismatches |
| `specific_attack` (TXT field 3) vs ARFF `specific result` | **0** mismatches |
| TXT `destination` vs ARFF `command response` | perfect bijection: `destination==1` ⇔ `command response==0` (137,013); `destination==3` ⇔ `command response==1` (137,615) |

Because timestamp, both label fields, and the direction field agree on every one of
274,628 rows in order, the TXT is the ARFF's row-aligned source record with the
Modbus payload bytes the ARFF omits. The join key is **row index** (file order), with
`timestamp` as a redundant cross-check.

**This RESOLVES BLOCKER 3.** For the first time, payload-derived features (entropy,
frame structure) can be joined to the authoritative 274,628-row label set with a
verified 1:1 key. Payload entropy is now evaluable against ground-truth labels
directly — no fuzzy join, no omission.
```

### 3.3 BLOCKER 3 section — change the status line

```markdown
### BLOCKER 3 — TXT-to-ARFF linkage. RESOLVED 2026-09-08 — VERIFIED ROW ALIGNMENT.

Superseded: the 2026-09-02 "resolved by decision (no join attempted)" position and the
2026-09-04 "TXT is a different, smaller capture" caveat both applied to the **retracted**
file. The current `data/raw/gas_pipeline_raw.txt` (sha256 `ce2d69e3…93e3`) is row-for-row
aligned to the ARFF on timestamp + both label fields + direction across all 274,628 rows
(see "NEW AUTHORITATIVE RAW FILE" above). The join key is row index. Payload entropy and
frame-structure features CAN now be evaluated against the authoritative labels.
```

### 3.4 Also update

- The "CORRECTION (2026-09-04): the TXT **is** labelled" block: add a dated note that
  the row counts / timestamp-range / "smaller different capture" statements described
  the retracted file; the current file is full-span and row-aligned.
- The "All facts in this document come from `scripts/inspect_dataset.py` run on
  2026-09-01" header line: add "…and the 2026-09-08 re-verification recorded in this
  file's 'NEW AUTHORITATIVE RAW FILE' section."
- `scripts/inspect_dataset.py` should be re-run once the files are in place so
  `data/reconnaissance/dataset_inspection.json` reflects the new hashes (code change
  in §4 if the script hard-codes the old 209,668 expectation — it does not appear to).

---

## 4. EXP-0004 DESIGN

### 4.1 Is the existing code compatible with the new file as-is?

**Schema:** identical. Field order `hexframe, categorized, specific, source,
destination, timestamp` is exactly what `ml/features_txt.py::iter_records()` parses
(`len(parts) != 6` skip; `bytes.fromhex`; `float(ts)`; int fields). **No parser change
needed.**

| module | compatible as-is? | notes |
|---|---|---|
| `ml/features_txt.py` | **Yes, no change.** | `RAW_TXT` path constant already points at `data/raw/gas_pipeline_raw.txt` — which is now the new file. 6-field parse unchanged. `_crc16_modbus` still runs; `crc_ok` is computed but is **not** in `FEATURE_COLUMNS` and not used downstream, so the ~0% CRC rate is a non-issue (same as before). Function codes 0x03/0x10 dominate; `_parse_frame_fields` handles the rest via the `rare_function_code` path. |
| `ml/features_windowed.py` | **Yes, no change.** | `EGRESS_DESTINATION = 1` is confirmed correct against the ARFF (`destination==1` ⇔ `command response==0` ⇔ response/egress). Egress frame count rises from 104,627 → **137,013**. `NORMAL_FUNC_CODES = {0x03, 0x10}` still correct. |
| `ml/rules.py` | **Yes, no change.** | Membership test on function codes / addresses, profile frozen from train-normal. Behaviour is data-driven, not hard-coded. |
| `ml/iforest_detector.py` | **Yes, code-wise.** | `build_windows()` reads the new file transparently. **But** the hard-coded `EXP0001` / `EXP0001_PERCAT_COMBINED` comparison dicts (lines 43–52) are retracted numbers — they must be replaced with an `EXP0003`-or-blank comparison, or the "vs EXP-0001" columns removed, before the report is trustworthy. This is a reporting-cosmetics change, not a pipeline change. |
| `ml/exp0003_dos_timing.py`, `ml/xgb_txt_diagnostic.py` | Run transparently; all recorded outputs are retracted and must be regenerated if still wanted. |
| `tests/test_detector.py` | **Will fail.** All constants (`THRESHOLD`, `COMBINED`, `CONFUSION`, `PER_CATEGORY_COMBINED`, `n_windows == 35_935`, split sizes) are exact matches to the retracted run. They must be **rebaselined from the EXP-0004 run** and the module docstring updated. `tests/test_rules.py` is fixture-based (mechanism only) and should still pass — verify. |
| `tests/conftest.py` | Docstring mentions "209k frames → 35,935 windows"; update the prose. |

**Net:** the feature/detector/rule code needs **zero functional changes** to run on
the new file. The required edits are (1) retraction banners in docs, (2) replacing
retracted comparison constants in `iforest_detector.py`, (3) rebaselining
`tests/test_detector.py` from the EXP-0004 result, (4) provenance updates from §3.

### 4.2 EXP-0004 pre-registration block (to add to `EXPERIMENT_LOG.md` BEFORE running)

```markdown
## PRE-REGISTRATION — EXP-0004 (recorded 2026-09-08, before any EXP-0004 run)

Supersedes the EXP-0001-era pre-registration for the TXT path (that work is retracted).
Fixed before the detector is run on the new file.

1. **Dataset.** `data/raw/gas_pipeline_raw.txt`, sha256 `ce2d69e3…93e3`, 274,628 rows,
   verified row-aligned to `IanArffDataset.arff` (provenance §"NEW AUTHORITATIVE RAW
   FILE"). Any deviation from this hash invalidates the run.

2. **Direction filter.** Egress = `destination == 1` (⇔ ARFF `command response == 0`,
   response/telemetry, thesis-confirmed + now ARFF-cross-verified). 137,013 egress
   frames. The `destination == 3` direction is a labelled sensitivity run only.

3. **Split.** Contiguous time-block, decided now, before any metric:
   - 60 / 20 / 20 by **egress-window index** (same rule as the retracted EXP-0001/2,
     which is a defensible default and keeps the design comparable).
   - 1-window (5 s) guard gap discarded at each of the two boundaries.
   - Boundaries recorded as absolute epoch `time` + ISO-8601 in the EXP-0004 entry
     and the report, per `03-data-split-protocol.md`.
   - TRAIN normal-only subset = windows with no attack-labelled frame
     (`categorized == 0` for every frame in the window).
   - TEST scored exactly once.

4. **Feature set — starting point = EXP-0002 headline, entropy status RE-OPENED.**
   - IF inputs (candidate, 14): `packet_count, packets_per_sec, bytes_per_sec,
     mean_frame_len, iat_{mean,std,min,max}, frac_func_{read,write},
     distinct_frame_ratio, repeat_frame_rate, payload_entropy_{mean,std}`.
   - Deterministic rule layer (not IF inputs): out-of-profile function code /
     novel slave address, profile frozen from TRAIN-normal.
   - `frac_func_valid`, `rare_func_rate` stay out of the IF (zero variance on normal).
   - **Entropy decision:** because BLOCKER 3 is now genuinely resolved (verified
     alignment, not "the TXT is self-labelled"), entropy IS legitimately evaluable
     against authoritative labels. It stays a **candidate headline input**, but its
     contribution must be reported as a paired with/without-entropy comparison in the
     EXP-0004 entry (recall, precision, PR-AUC each way), and the headline slot is
     only confirmed if entropy adds measured signal on the verified file — not
     inherited from the retracted EXP-0001.

5. **Model.** `sklearn.IsolationForest`, `n_estimators=300`, `max_samples="auto"`,
   `contamination="auto"` (not used for thresholding), `random_state=0`. Standardiser
   (mean/std) frozen from TRAIN-normal.

6. **Threshold.** 99th percentile of VALIDATION-normal anomaly scores (target FPR 1%).
   Chosen on validation only.

7. **Artifact / leakage audit** (`03-data-split-protocol.md` checklist, run on TRAIN
   only): boundary sanity; function-code tail per-class; the "exactly-40" scripted
   pattern; `source == 2` leak confirmation (see §5); field-presence not applicable
   (TXT has no sparse columns). Recorded PASS/FAIL/NEEDS-DOC in the entry before any
   metric is quoted.

8. **Metrics reported:** precision, recall, F1, FPR, FNR, PR-AUC, ROC-AUC, per-category
   (Normal/NMRI/CMRI/MSCI/MPCI/MFCI/DoS/Recon) flag rate, inference latency, throughput.
   Naive baseline (Stage 0) reported alongside. Headline recall computed over the
   pre-registered CAN / PARTIAL-CAN categories only (that table is re-inherited from
   the top of this log — it derives from the thesis, not the retracted file, but the
   DoS "MEASURED (EXP-0003)" citation reverts to "reasoning; EXP-0003 retracted" until
   EXP-0004 re-measures it).

9. **DoS re-measurement.** Fold the EXP-0003 question (egress IAT separation for DoS)
   back in as a section of EXP-0004 or a same-day EXP-0005, on the verified file, with
   the same pre-registered NO-SEPARATION / SEPARATION / AMBIGUOUS decision rule.
```

### 4.3 Realistic runtime

The retracted EXP-0002 processed 209,668 rows → ~7 s (per `pyproject.toml` marker).
New file is 274,628 rows (**×1.31**) and egress frames 104,627 → 137,013 (×1.31),
so windows ≈ 35,935 → **~47,000**.

| step | retracted | EXP-0004 estimate |
|---|---|---|
| `features_txt` parse (274k lines, hex decode, entropy) | — | ~5–8 s |
| `build_windows` (egress filter + 5 s buckets) | — | ~2–3 s |
| IsolationForest fit (300 trees, ~15k train-normal windows) + score | — | ~4–6 s |
| **full `ml/iforest_detector.py` run** | ~7 s | **~15–25 s** |
| `pytest -m slow` (fixture builds detector once) | ~7 s | **~20–30 s** |
| `ml/xgb_txt_diagnostic.py` (DIAG rerun, if wanted) | ~1–2 min | **~2–3 min** |
| `scripts/inspect_dataset.py` (full re-recon, both files) | — | ~1–2 min |

Nothing here needs a background job. Total wall-clock for the full EXP-0004 cycle
(move files → run detector → rebaseline tests → write entry) is well under an hour of
compute; the write-up is the long pole.

---

## 5. RISK CHECKLIST — verify before trusting EXP-0004 results

Each item is "assumed from the retracted file's provenance doc — must be re-checked
against the new file specifically."

| # | Assumption (from old provenance) | Status on new file | Action before EXP-0004 metrics |
|---|---|---|---|
| R1 | `source == 2` is the MITM injection rig, 100% attack, label-leaking, not wire-observable | **Re-checked today: holds.** `source==2` → 40,739 rows, **all attack** (0 normal). `source==1` → all normal. `source==3` → mixed (96,916 normal / 19,309 attack). | Confirm `source` is **never** a feature (it is not in `FEATURE_COLUMNS` / `IF_FEATURES` — verified). Add the crosstab to the EXP-0004 artifact audit. |
| R2 | NMRI + CMRI frames carry `source == 2` exclusively | **Not yet re-verified per-category on the new file.** | Run `categorized × source` crosstab on the new file; record it. Only matters as a leak-audit note, not for features. |
| R3 | `destination == 1` is the egress/response direction | **Re-checked today: verified against ARFF** (`destination==1` ⇔ `command response==0`, exact bijection, 137,013 rows). Stronger evidence than the old file ever had. | None — this is now cross-validated. Note it in the entry. |
| R4 | Trailing 2 bytes do not validate as Modbus CRC-16 → no "bad CRC" feature; DoS (specific 18) has no frame-level signature | **Expected to hold** (task states the new genuine file shows the same 0% CRC signature) but **not yet independently run** on the new file. | Run the CRC check (both byte orders) on the new file's normal frames; confirm ~0%. If it were suddenly non-zero, `crc_ok` becomes a real candidate feature and DoS detectability must be re-assessed. |
| R5 | Valid slave-address set on normal traffic = `{4}`; other addresses are the scripted tail | New file: address 4 dominates (274,026); tail of exactly-32 and decreasing counts present, same shape as ARFF. Per-frame vs per-window, and whether tail addresses land in normal or attack windows, **not yet checked**. | Let `rules.py` derive `valid_addresses` from TRAIN-normal as designed; record what set it learns and whether the rule fires on any Normal TEST window (the retracted EXP-0002 claimed 0 — must be re-measured). |
| R6 | Function-code set on normal traffic = `{0x03, 0x10}`; everything else is attack/rare | New file function-code histogram consistent with this (0x03 + 0x10 = 265,896 of 274,628; rest is the tail incl. exception codes 0x88 etc.). Per-class split of the tail **not yet checked**. | Artifact-audit check 3 (function-code tail per-class) on TRAIN only. |
| R7 | The "exactly-40 / exactly-32" counts are scripted injection episodes, contiguous in time | Present in the new file (multiple function codes at exactly 40; addresses at exactly 32). Temporal contiguity **not checked**. | Artifact-audit check 5: confirm these episodes are distributed across TRAIN/VAL/TEST by the contiguous split, not accidentally concentrated in one block. |
| R8 | Windowed features don't straddle the split boundary | Code enforces this (bucket by `floor(ts/5)`, split on window index + guard). | Boundary-sanity check (audit check 6) — re-run, expect PASS. |
| R9 | Rows are in strict timestamp order so a contiguous split is valid | **Re-checked today: 0 out-of-order** across 274,628 rows. | None. |
| R10 | 274,628 vs thesis 274,627 (+1 row) discrepancy | Same +1 as the ARFF — the new file matches the local ARFF, not the thesis count. Already documented for the ARFF. | Note that the TXT inherits the same +1; no new discrepancy. |
| R11 | `gas_pipeline_ml_ready.csv` relationship (it was row-aligned to the *old* TXT by line number) | That CSV is DISCARD anyway; its `record_index` now aligns to nothing real. | Confirm nothing in the pipeline reads it (it does not). Leave the DISCARD disposition; add a line that its row-alignment claim referred to the retracted file. |
| R12 | Determinism of the detector (seed 0 → bit-identical) | Was true on the old file. | `test_detector_is_deterministic` must still pass on the new file before the rebaselined constants are trusted. |
| R13 | Entropy actually carries signal (retracted EXP-0001 claimed recall 0.027→0.132 from adding it) | **Unknown — that measurement is retracted.** | EXP-0004 §4 pre-reg item 4: report paired with/without-entropy numbers; do not assume the lift. |

**Hard gate:** no EXP-0004 metric is quoted anywhere until R1–R13's "action" column is
discharged and the artifact audit is recorded in the EXP-0004 entry, per the standing
pre-registration discipline.

---

## 6. EXECUTION ORDER (once this plan is approved — NOT yet done)

1. §1.3 commands — create `data/raw/`, verify hashes, move both files, set read-only.
2. §1.4 — place `RETRACTED_gas_pipeline_raw.txt` if a copy exists, else document its absence.
3. §3 — provenance doc edits (inventory, new subsection, BLOCKER 3, CORRECTION note).
4. §2 — retraction entries in `DECISION_LOG.md` and `EXPERIMENT_LOG.md` + banners on EXP-0001/0002/0003 + DIAG-0001.
5. §4.2 — write the EXP-0004 pre-registration block into `EXPERIMENT_LOG.md`.
6. §5 — run R2/R4/R5/R6/R7 checks (read-only scripts), record outputs.
7. Fix `ml/iforest_detector.py` retracted comparison constants (§4.1).
8. Run `ml/iforest_detector.py` on the new file; capture the report.
9. Run the DoS re-measurement (§4.2 item 9).
10. Rebaseline `tests/test_detector.py` constants + docstrings from step 8; run full `pytest`.
11. Write the EXP-0004 (and EXP-0005 if split out) entry with all metrics + audit results.
12. Sweep `README.md` and numbered specs for quoted EXP-0002 numbers; replace with EXP-0004 or `[pending]`.
13. Re-run `scripts/inspect_dataset.py`; refresh `data/reconnaissance/` artifacts.

**STOP HERE. Awaiting review of this plan.**
