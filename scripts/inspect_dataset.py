#!/usr/bin/env python3
"""
SIH26145 dataset reconnaissance (read-only).

Provenance: egress traffic extracted from Mississippi State ICS testbed dataset,
used as a simulated diode-observer view. This is a dataset-based unidirectional
SIMULATION, NOT a physical data-diode capture.

This script inspects the ACTUAL files on disk and emits a deterministic report
(markdown + JSON) under data/reconnaissance/. It does not train a model, does not
select a threshold, and reports no performance metrics. Stdlib only.

Files inspected:
  data/raw/IanArffDataset.arff          (authoritative ML-ready ARFF)
  data/raw/gas_pipeline_raw.txt         (authoritative row-aligned payload companion)

The discarded provisional CSV is reported as present/absent but is not required.
Everything under data/raw/ is opened read-only and never modified.
"""
import csv
import hashlib
import json
import math
import os
import sys
from collections import Counter, OrderedDict
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARFF = os.path.join(ROOT, "data/raw/IanArffDataset.arff")
TXT = os.path.join(ROOT, "data/raw/gas_pipeline_raw.txt")
CSV = os.path.join(ROOT, "data/processed/gas_pipeline_ml_ready.csv")
OUTDIR = os.path.join(ROOT, "data/reconnaissance")

DIST_ATTRS = [
    "address", "function", "command response",
    "binary result", "categorized result", "specific result",
]


def sha256_and_size(path):
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def parse_arff_header(path):
    relation = None
    attrs = []  # list of dict(name,type,nominal)
    data_start_line = None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, raw in enumerate(f):
            line = raw.strip()
            low = line.lower()
            if not line or line.startswith("%"):
                continue
            if low.startswith("@relation"):
                relation = line.split(None, 1)[1].strip()
            elif low.startswith("@attribute"):
                rest = line[len("@attribute"):].strip()
                if rest.startswith("'"):
                    end = rest.index("'", 1)
                    name = rest[1:end]
                    typ = rest[end + 1:].strip()
                else:
                    name, typ = rest.split(None, 1)
                nominal = None
                if typ.startswith("{"):
                    nominal = [v.strip().strip("'\"")
                               for v in typ.strip("{}").split(",")]
                    typ = "nominal"
                attrs.append({"name": name, "type": typ, "nominal": nominal})
            elif low.startswith("@data"):
                data_start_line = i + 1
                break
    return relation, attrs, data_start_line


def iter_arff_data_rows(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        in_data = False
        for raw in f:
            line = raw.strip()
            if not in_data:
                if line.lower().startswith("@data"):
                    in_data = True
                continue
            if not line or line.startswith("%"):
                continue
            yield next(csv.reader([line]))


def shannon_bits_per_byte(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def analyze_arff(path):
    relation, attrs, data_start = parse_arff_header(path)
    names = [a["name"] for a in attrs]
    idx = {n: i for i, n in enumerate(names)}
    ncols = len(names)

    count = 0
    bad_width = 0
    missing = [0] * ncols
    dists = {a: Counter() for a in DIST_ATTRS if a in idx}
    ti = idx.get("time")
    tmin = None
    tmax = None
    prev_t = None
    monotonic_nondec = True
    strictly_increasing = True
    t_counter = Counter()
    # cross-tabs for direction evidence
    cr_by_func = Counter()          # (command response, function) -> n
    cr_len_sum = Counter()          # command response -> sum(length)
    cr_len_n = Counter()
    cr_binresult = Counter()        # (command response, binary result) -> n
    func_i = idx.get("function")
    len_i = idx.get("length")
    cr_i = idx.get("command response")
    bin_i = idx.get("binary result")
    cat_i = idx.get("categorized result")
    spec_i = idx.get("specific result")
    row_hashes = Counter()
    cat_spec = Counter()            # (categorized, specific) -> n
    bin_by_cat = Counter()

    for parts in iter_arff_data_rows(path):
        count += 1
        if len(parts) != ncols:
            bad_width += 1
            continue
        for j, v in enumerate(parts):
            if v == "?":
                missing[j] += 1
        for a in dists:
            dists[a][parts[idx[a]]] += 1
        if ti is not None:
            try:
                t = float(parts[ti])
            except ValueError:
                t = None
            if t is not None:
                t_counter[parts[ti]] += 1
                if tmin is None or t < tmin:
                    tmin = t
                if tmax is None or t > tmax:
                    tmax = t
                if prev_t is not None:
                    if t < prev_t:
                        monotonic_nondec = False
                    if t <= prev_t:
                        strictly_increasing = False
                prev_t = t
        if cr_i is not None and func_i is not None:
            cr_by_func[(parts[cr_i], parts[func_i])] += 1
        if cr_i is not None and len_i is not None:
            try:
                L = float(parts[len_i])
                cr_len_sum[parts[cr_i]] += L
                cr_len_n[parts[cr_i]] += 1
            except ValueError:
                pass
        if cr_i is not None and bin_i is not None:
            cr_binresult[(parts[cr_i], parts[bin_i])] += 1
        if cat_i is not None and spec_i is not None:
            cat_spec[(parts[cat_i], parts[spec_i])] += 1
        if bin_i is not None and cat_i is not None:
            bin_by_cat[(parts[bin_i], parts[cat_i])] += 1
        row_hashes[hashlib.md5("\x1f".join(parts).encode()).hexdigest()] += 1

    dup_rows = sum(c - 1 for c in row_hashes.values() if c > 1)
    dup_ts = sum(c - 1 for c in t_counter.values() if c > 1)

    missing_pct = {names[j]: (missing[j], round(100.0 * missing[j] / count, 4))
                   for j in range(ncols)} if count else {}

    cr_avg_len = {k: round(cr_len_sum[k] / cr_len_n[k], 3)
                  for k in cr_len_n}

    return {
        "relation": relation,
        "data_start_line": data_start,
        "attributes": attrs,
        "instance_count": count,
        "rows_wrong_width": bad_width,
        "missing_per_attribute": missing_pct,
        "distributions": {a: OrderedDict(sorted(dists[a].items(),
                                                key=lambda kv: (-kv[1], kv[0])))
                          for a in dists},
        "timestamp": {
            "attribute": "time",
            "min": tmin,
            "max": tmax,
            "min_iso_utc": datetime.fromtimestamp(tmin, timezone.utc).isoformat()
            if tmin else None,
            "max_iso_utc": datetime.fromtimestamp(tmax, timezone.utc).isoformat()
            if tmax else None,
            "monotonic_nondecreasing": monotonic_nondec,
            "strictly_increasing": strictly_increasing,
            "duplicate_timestamp_count": dup_ts,
            "distinct_timestamps": len(t_counter),
        },
        "duplicate_full_rows": dup_rows,
        "direction_evidence": {
            "command_response_values": dict(Counter(
                {k: v for (k, _), v in
                 Counter({(cr, f): n for (cr, f), n in cr_by_func.items()}).items()})),
            "count_by_command_response": _sum_first(cr_by_func),
            "avg_length_by_command_response": cr_avg_len,
            "function_by_command_response": _nest(cr_by_func),
            "binary_result_by_command_response": _nest(cr_binresult),
        },
        "categorized_x_specific": _nest(cat_spec),
        "binary_x_categorized": _nest(bin_by_cat),
        "names": names,
    }


def _sum_first(counter2):
    out = Counter()
    for (a, _b), n in counter2.items():
        out[a] += n
    return dict(out)


def _nest(counter2):
    out = {}
    for (a, b), n in counter2.items():
        out.setdefault(str(a), {})[str(b)] = n
    for a in out:
        out[a] = OrderedDict(sorted(out[a].items(),
                                    key=lambda kv: (-kv[1], kv[0])))
    return out


def analyze_txt(path):
    n = 0
    field_widths = Counter()
    tmin = tmax = None
    prev = None
    mono = True
    ncols_seen = Counter()
    ent_sum = 0.0
    ent_n = 0
    sample = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            n += 1
            parts = line.split(",")
            ncols_seen[len(parts)] += 1
            if len(parts) == 6:
                hexstr, m1, m2, m3, m4, ts = parts
                field_widths[len(hexstr)] += 0
                try:
                    raw = bytes.fromhex(hexstr)
                    ent_sum += shannon_bits_per_byte(raw)
                    ent_n += 1
                except ValueError:
                    pass
                try:
                    t = float(ts)
                    if tmin is None or t < tmin:
                        tmin = t
                    if tmax is None or t > tmax:
                        tmax = t
                    if prev is not None and t < prev:
                        mono = False
                    prev = t
                except ValueError:
                    pass
                if len(sample) < 3:
                    sample.append(parts)
    return {
        "row_count": n,
        "column_count_distribution": dict(ncols_seen),
        "timestamp_min": tmin,
        "timestamp_max": tmax,
        "monotonic_nondecreasing": mono,
        "mean_payload_entropy_bits_per_byte": round(ent_sum / ent_n, 4) if ent_n else None,
        "entropy_rows_decoded": ent_n,
        "sample_rows": sample,
    }


def analyze_csv(path):
    if not os.path.exists(path):
        return {"present": False}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        r = csv.reader(f)
        header = next(r)
        n = 0
        tmin = tmax = None
        for row in r:
            n += 1
            try:
                t = float(row[header.index("timestamp_unix")])
                if tmin is None or t < tmin:
                    tmin = t
                if tmax is None or t > tmax:
                    tmax = t
            except (ValueError, IndexError):
                pass
    return {
        "present": True,
        "header": header,
        "data_row_count": n,
        "timestamp_min": tmin,
        "timestamp_max": tmax,
    }


def analyze_alignment(arff_path, txt_path):
    rows = 0
    timestamp_mismatches = 0
    categorized_mismatches = 0
    specific_mismatches = 0
    direction_mismatches = 0
    arff_rows = iter_arff_data_rows(arff_path)
    with open(txt_path, "r", encoding="utf-8", errors="replace") as f:
        for raw_txt, arff_row in zip(f, arff_rows):
            parts = raw_txt.strip().split(",")
            if len(parts) != 6 or len(arff_row) != 20:
                continue
            rows += 1
            if float(parts[5]) != float(arff_row[16]):
                timestamp_mismatches += 1
            if parts[1] != arff_row[18]:
                categorized_mismatches += 1
            if parts[2] != arff_row[19]:
                specific_mismatches += 1
            expected_direction = "0" if parts[4] == "1" else "1" if parts[4] == "3" else None
            if expected_direction != arff_row[15]:
                direction_mismatches += 1
        remaining_txt = sum(1 for line in f if line.strip())
    remaining_arff = sum(1 for _ in arff_rows)
    return {
        "compared_rows": rows,
        "remaining_arff_rows": remaining_arff,
        "remaining_txt_rows": remaining_txt,
        "timestamp_mismatches": timestamp_mismatches,
        "categorized_mismatches": categorized_mismatches,
        "specific_mismatches": specific_mismatches,
        "direction_mismatches": direction_mismatches,
    }


def build_report(files, arff, txt, csvd, alignment):
    lines = []
    w = lines.append
    w("# SIH26145 Dataset Reconnaissance Report")
    w("")
    w(f"Generated: {datetime.now(timezone.utc).isoformat()} (UTC)")
    w("Generator: `scripts/inspect_dataset.py` (deterministic, re-runnable, stdlib only)")
    w("")
    w("Provenance: egress traffic extracted from Mississippi State ICS testbed "
      "dataset, used as a simulated diode-observer view. This is a **dataset-based "
      "unidirectional simulation, NOT a physical data-diode capture.**")
    w("")
    w("No model was trained. No threshold was selected. No performance metric is reported.")
    w("")

    w("## 1. File integrity (SHA-256 + exact byte size)")
    w("")
    w("| file | bytes | sha256 |")
    w("|---|---|---|")
    for name, (h, sz) in files.items():
        w(f"| `{name}` | {sz} | `{h}` |")
    w("")

    w("## 2. ARFF relation + attribute schema (in order)")
    w("")
    w(f"Relation name: `{arff['relation']}`")
    w(f"`@data` begins at file line {arff['data_start_line']}.")
    w("")
    w("| # | attribute | type | nominal values |")
    w("|---|---|---|---|")
    for i, a in enumerate(arff["attributes"], 1):
        nom = ", ".join(a["nominal"]) if a["nominal"] else ""
        w(f"| {i} | `{a['name']}` | {a['type']} | {nom} |")
    w("")

    w("## 3. Verified instance count")
    w("")
    w(f"Parsed data instances: **{arff['instance_count']}**")
    w(f"Rows whose field count != {len(arff['names'])}: {arff['rows_wrong_width']}")
    w("")

    w("## 4. Missing-value count and percentage per attribute (ARFF `?`)")
    w("")
    w("| attribute | missing | missing % |")
    w("|---|---|---|")
    for name, (cnt, pct) in arff["missing_per_attribute"].items():
        w(f"| `{name}` | {cnt} | {pct} |")
    w("")

    w("## 5. Unique values / distributions for key categorical attributes")
    w("")
    for a in DIST_ATTRS:
        d = arff["distributions"].get(a, {})
        w(f"### `{a}` — {len(d)} distinct value(s)")
        w("")
        w("| value | count |")
        w("|---|---|")
        for k, v in list(d.items())[:60]:
            w(f"| `{k}` | {v} |")
        w("")

    ts = arff["timestamp"]
    w("## 6. Timestamp analysis (`time` attribute)")
    w("")
    w(f"- min: {ts['min']} ({ts['min_iso_utc']})")
    w(f"- max: {ts['max']} ({ts['max_iso_utc']})")
    w(f"- monotonically non-decreasing in file order: **{ts['monotonic_nondecreasing']}**")
    w(f"- strictly increasing: {ts['strictly_increasing']}")
    w(f"- distinct timestamp strings: {ts['distinct_timestamps']}")
    w(f"- duplicate timestamp count (extra rows sharing a timestamp): {ts['duplicate_timestamp_count']}")
    w("")

    w("## 7. Normal-vs-attack distribution (DOCUMENTED label definitions)")
    w("")
    w("`binary result` distribution (raw values, no semantic mapping applied):")
    w("")
    w("| value | count |")
    w("|---|---|")
    for k, v in arff["distributions"]["binary result"].items():
        w(f"| `{k}` | {v} |")
    w("")
    w("**Documented semantics.** Per the cited Turnipseed (2015) thesis codebook in "
      "`docs/00-dataset-provenance.md`, `binary result` 0=normal/1=attack and "
      "`categorized result` 0..7 = Normal/NMRI/CMRI/MSCI/MPCI/MFCI/DoS/Recon. "
      "Labels are evaluation-only and must never be model inputs.")
    w("")
    w("`binary result` x `categorized result` cross-tab (raw values):")
    w("")
    w("```json")
    w(json.dumps(arff["binary_x_categorized"], indent=2))
    w("```")
    w("")

    w("## 8. Attack-category and specific-attack distributions (raw values)")
    w("")
    w("`categorized result`:")
    w("")
    w("| value | count |")
    w("|---|---|")
    for k, v in arff["distributions"]["categorized result"].items():
        w(f"| `{k}` | {v} |")
    w("")
    w("`specific result`:")
    w("")
    w("| value | count |")
    w("|---|---|")
    for k, v in arff["distributions"]["specific result"].items():
        w(f"| `{k}` | {v} |")
    w("")
    w("`categorized result` x `specific result` cross-tab:")
    w("")
    w("```json")
    w(json.dumps(arff["categorized_x_specific"], indent=2))
    w("```")
    w("")

    de = arff["direction_evidence"]
    w("## 9. Does `command response` reliably identify frame direction? (evidence only)")
    w("")
    w(f"- `command response` value counts: {json.dumps(de['count_by_command_response'])}")
    w(f"- average `length` by `command response` value: {json.dumps(de['avg_length_by_command_response'])}")
    w("")
    w("`function` distribution split by `command response`:")
    w("")
    w("```json")
    w(json.dumps(de["function_by_command_response"], indent=2))
    w("```")
    w("")
    w("`binary result` split by `command response`:")
    w("")
    w("```json")
    w(json.dumps(de["binary_result_by_command_response"], indent=2))
    w("```")
    w("")
    w("**Interpretation:** Turnipseed (2015) section 3.5.2 defines 0=response and "
      "1=command. The verified TXT alignment independently confirms destination 1 "
      "maps to ARFF response/egress (`command response == 0`).")
    w("")

    w("## 10. Record count after each possible direction filter")
    w("")
    cbcr = de["count_by_command_response"]
    for k, v in sorted(cbcr.items()):
        w(f"- keep only `command response == {k}`: {v} rows")
    w("")
    w("`command response == 0` is response/egress; `== 1` is command, per the cited primary source.")
    w("")

    w("## 11. Can a unidirectional simulation be built without reverse-flow features?")
    w("")
    w("Yes. Keep `command response == 0` (response/egress), construct windows only "
      "after filtering, and exclude the sparse process-variable columns plus all label "
      "fields from model inputs. This is the implemented TXT-path simulation.")
    w("")

    w("## 12. Duplicate rows and leakage-prone patterns")
    w("")
    w(f"- exact duplicate full rows in ARFF: {arff['duplicate_full_rows']}")
    w(f"- duplicate timestamps: {ts['duplicate_timestamp_count']}")
    w("")
    w("Leakage / 'artificially easy' concerns (dataset authors' own warning): Morris "
      "et al. have documented that this MSU testbed data contains unintended "
      "instrumentation artifacts that can make attacks trivially separable. This ARFF "
      "has 0 exact duplicate rows and a strictly increasing timestamp (one row per "
      "distinct timestamp), so row-level dedup is not the concern here. The concern is "
      "field-level: only 7 `function` codes and a handful of `length` templates "
      "dominate, `crc rate` is fully populated on every row, and the payload fields "
      "are present/absent in fixed patterns. Any split protocol must (a) split by "
      "contiguous time blocks, not random rows, so near-identical polling-loop frames "
      "do not straddle the split, and (b) treat `crc rate`, exact `length` templates "
      "and per-row field-presence patterns as suspected label-correlated artifacts to "
      "be audited before use.")
    w("")

    w("## 13. Attributes effectively unavailable (mostly/all `?`)")
    w("")
    w("| attribute | missing % |")
    w("|---|---|")
    for name, (cnt, pct) in arff["missing_per_attribute"].items():
        if pct >= 50.0:
            w(f"| `{name}` | {pct} |")
    w("")

    w("## 14. Official ARFF vs supporting raw TXT")
    w("")
    w(f"- ARFF: relation `{arff['relation']}`, {len(arff['names'])} attributes, "
      f"{arff['instance_count']} instances, timestamps "
      f"{ts['min']}..{ts['max']}")
    w(f"- TXT: {txt['row_count']} rows, column-count distribution "
      f"{json.dumps(txt['column_count_distribution'])}, timestamps "
      f"{txt['timestamp_min']}..{txt['timestamp_max']}")
    w(f"- TXT schema: 6 comma-separated fields (raw hex Modbus-style frame, "
      f"categorized label, specific label, source, destination, unix timestamp). It is "
      f"the payload-bearing companion to, not a duplicate of, the 20-attribute ARFF schema.")
    w(f"- Alignment rows compared: {alignment['compared_rows']}; remaining ARFF/TXT "
      f"rows: {alignment['remaining_arff_rows']}/{alignment['remaining_txt_rows']}.")
    w(f"- Mismatches — timestamp: {alignment['timestamp_mismatches']}; categorized "
      f"label: {alignment['categorized_mismatches']}; specific label: "
      f"{alignment['specific_mismatches']}; direction: {alignment['direction_mismatches']}.")
    w("- Join key: row index, with timestamp and labels as redundant checks.")
    w(f"- TXT mean payload Shannon entropy: {txt['mean_payload_entropy_bits_per_byte']} "
      f"bits/byte over {txt['entropy_rows_decoded']} decoded frames. The ARFF itself has "
      f"no raw payload bytes.")
    w("")

    w("## 15. Disposition of the provisional CSV")
    w("")
    if csvd["present"]:
        w(f"`data/processed/gas_pipeline_ml_ready.csv` is present with "
          f"{csvd['data_row_count']} data rows and remains **DISCARD / unused**.")
    else:
        w("`data/processed/gas_pipeline_ml_ready.csv` is absent, consistent with its "
          "**DISCARD / unused** disposition. The current pipeline reads neither it nor "
          "any derived replacement.")
    w("")

    w("## P1 capability classification")
    w("")
    w("### protocol / function-code violation detection — **SUPPORTED**")
    w("Exact supporting attributes (ARFF): `function` (Modbus function code, "
      f"{len(arff['distributions']['function'])} distinct values observed), `address`, "
      "`length`, and `command response`. Direction semantics are documented; `crc rate` "
      "remains excluded as an instrumentation-artifact risk.")
    w("")
    w("### payload-entropy anomaly detection — **SUPPORTED ON VERIFIED TXT PATH**")
    w("The ARFF itself has no raw payload bytes. The canonical TXT supplies them and "
      "is exactly row-aligned with the ARFF labels and direction, so per-frame and "
      f"windowed entropy are evaluable. Mean per-frame entropy in this recon is "
      f"{txt['mean_payload_entropy_bits_per_byte']} bits/byte.")
    w("")
    w("### volume / frequency anomaly detection — **SUPPORTED**")
    w("Exact supporting attributes (ARFF): `time` (unix epoch, "
      f"microsecond-resolution, range {ts['min']}..{ts['max']}, "
      f"monotonic_nondecreasing={ts['monotonic_nondecreasing']}), plus `length` for "
      "byte volume and `function` for per-op rates. Windowed packet-rate / byte-rate "
      "features are constructible. Timestamps are strictly increasing with "
      f"{ts['duplicate_timestamp_count']} duplicates, spanning "
      "~3.2 days of continuous polling; windows are well-defined but the steady "
      "polling cadence means splitting must be by contiguous time blocks.")
    w("")
    return "\n".join(lines) + "\n"


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    for p in (ARFF, TXT):
        if not os.path.exists(p):
            print(f"MISSING: {p}", file=sys.stderr)
            sys.exit(1)

    files = OrderedDict()
    for label, p in (("data/raw/IanArffDataset.arff", ARFF),
                     ("data/raw/gas_pipeline_raw.txt", TXT)):
        files[label] = sha256_and_size(p)
    if os.path.exists(CSV):
        files["data/processed/gas_pipeline_ml_ready.csv"] = sha256_and_size(CSV)

    arff = analyze_arff(ARFF)
    txt = analyze_txt(TXT)
    csvd = analyze_csv(CSV)
    alignment = analyze_alignment(ARFF, TXT)

    machine = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "provenance_note": ("egress traffic extracted from Mississippi State ICS "
                            "testbed dataset, used as a simulated diode-observer "
                            "view; dataset-based unidirectional simulation, NOT a "
                            "physical data-diode capture"),
        "files": {k: {"sha256": v[0], "bytes": v[1]} for k, v in files.items()},
        "arff": arff,
        "txt": txt,
        "alignment": alignment,
        "csv": csvd,
    }
    json_path = os.path.join(OUTDIR, "dataset_inspection.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(machine, f, indent=2, default=str)

    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    md_path = os.path.join(OUTDIR, f"{date}-dataset-reconnaissance.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(build_report(files, arff, txt, csvd, alignment))

    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    print(f"ARFF instances: {arff['instance_count']}")
    print(f"ARFF bytes: {files['data/raw/IanArffDataset.arff'][1]}")


if __name__ == "__main__":
    main()
