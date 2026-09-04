#!/usr/bin/env python3
"""
Frame-level feature extraction from data/raw/gas_pipeline_raw.txt.

The file is a labelled Modbus-RTU hex-frame log, one frame per line:

    <hexframe>,<categorized_attack>,<specific_attack>,<source>,<destination>,<timestamp>

Frame layout: byte0 = slave address, byte1 = function code.
  func 0x03 (read holding registers)
    8-byte frame  -> request  : start_reg = bytes[2:4], qty = bytes[4:6]
    longer frame  -> response : byte_count = bytes[2]
  func 0x10 (write multiple registers)
    8-byte frame  -> echo response : start_reg = bytes[2:4], qty = bytes[4:6]
    9+ byte frame -> request        : start_reg/qty at same offsets, byte_count = bytes[6]
  any other function code -> rare / diagnostic, recorded as-is, no length check.

Lines whose comma-split field count != 6 are trailing / truncated records and skipped.

IMPORTANT: `source` and `destination` are NOT model features. `source == 2` is the
lab MITM injection rig and appears only on attack rows (verified crosstab); it leaks
the label and is not wire-observable through a diode. They are parsed here only so
downstream code can audit that leak, never to train on.
"""
from __future__ import annotations

import math
import zlib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator

RAW_TXT = Path(__file__).resolve().parent.parent / "data" / "raw" / "gas_pipeline_raw.txt"

FUNC_READ = 0x03
FUNC_WRITE_MULTI = 0x10

# Feature columns that are legitimately available to a passive one-directional
# observer of the egress byte stream. `source`/`destination`/`*_attack`/`timestamp`
# are deliberately excluded.
FEATURE_COLUMNS = [
    "address",
    "function_code",
    "frame_len_bytes",
    "is_request",
    "start_register",
    "quantity",
    "byte_count",
    "length_anomaly",
    "rare_function_code",
    "interarrival_seconds",
    "message_entropy_bits_per_byte",
]

MISSING = -1  # sentinel for fields that do not apply to a given frame type


def _crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def _byte_entropy(frame: bytes) -> float:
    if not frame:
        return 0.0
    counts: dict[int, int] = {}
    for b in frame:
        counts[b] = counts.get(b, 0) + 1
    n = len(frame)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class FrameRecord:
    record_index: int
    frame_id: int  # crc32 of the hex frame — for "distinct frames per window", not a model feature
    # --- features ---
    address: int
    function_code: int
    frame_len_bytes: int
    is_request: int
    start_register: int
    quantity: int
    byte_count: int
    length_anomaly: int
    rare_function_code: int
    crc_ok: int
    interarrival_seconds: float
    message_entropy_bits_per_byte: float
    # --- labels / audit-only, never features ---
    categorized_attack: int
    specific_attack: int
    source: int
    destination: int
    timestamp: float

    def features(self) -> dict:
        return {k: getattr(self, k) for k in FEATURE_COLUMNS}


def _parse_frame_fields(frame: bytes) -> dict:
    """Return the protocol-structural fields for one decoded frame."""
    out = {
        "address": frame[0] if len(frame) >= 1 else MISSING,
        "function_code": frame[1] if len(frame) >= 2 else MISSING,
        "frame_len_bytes": len(frame),
        "is_request": MISSING,
        "start_register": MISSING,
        "quantity": MISSING,
        "byte_count": MISSING,
        "length_anomaly": 0,
        "rare_function_code": 0,
        "crc_ok": MISSING,
    }
    if len(frame) < 4:
        out["rare_function_code"] = 1
        return out

    func = frame[1]
    n = len(frame)

    # CRC-16 (Modbus RTU): last two bytes, little-endian, over everything before.
    if n >= 4:
        expected = _crc16_modbus(frame[:-2])
        got = frame[-2] | (frame[-1] << 8)
        out["crc_ok"] = int(expected == got)

    def u16(lo_off: int) -> int:
        return (frame[lo_off] << 8) | frame[lo_off + 1]

    if func == FUNC_READ:
        if n == 8:
            out["is_request"] = 1
            out["start_register"] = u16(2)
            out["quantity"] = u16(4)
            out["length_anomaly"] = 0  # 8 bytes is exactly a well-formed request
        else:
            out["is_request"] = 0
            bc = frame[2]
            out["byte_count"] = bc
            # addr+func+bytecount + data + 2 CRC
            out["length_anomaly"] = int(n != bc + 5)
    elif func == FUNC_WRITE_MULTI:
        if n == 8:
            out["is_request"] = 0  # echo response
            out["start_register"] = u16(2)
            out["quantity"] = u16(4)
            out["length_anomaly"] = 0
        elif n >= 9:
            out["is_request"] = 1
            out["start_register"] = u16(2)
            out["quantity"] = u16(4)
            bc = frame[6]
            out["byte_count"] = bc
            # addr+func+start(2)+qty(2)+bytecount + data + 2 CRC
            out["length_anomaly"] = int(n != bc + 9)
        else:
            out["rare_function_code"] = 1
    else:
        # rare / diagnostic function code: record as-is, no length check
        out["rare_function_code"] = 1

    return out


def iter_records(path: Path = RAW_TXT) -> Iterator[FrameRecord]:
    prev_ts: float | None = None
    idx = 0
    with path.open("r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) != 6:
                continue  # trailing / truncated record
            hexframe, cat, spec, src, dst, ts_s = parts
            try:
                frame = bytes.fromhex(hexframe)
                ts = float(ts_s)
                cat_i, spec_i = int(cat), int(spec)
                src_i, dst_i = int(src), int(dst)
            except ValueError:
                continue
            idx += 1

            pf = _parse_frame_fields(frame)
            iat = 0.0 if prev_ts is None else max(0.0, ts - prev_ts)
            prev_ts = ts

            yield FrameRecord(
                record_index=idx,
                frame_id=zlib.crc32(hexframe.encode()),
                interarrival_seconds=iat,
                message_entropy_bits_per_byte=_byte_entropy(frame),
                categorized_attack=cat_i,
                specific_attack=spec_i,
                source=src_i,
                destination=dst_i,
                timestamp=ts,
                **pf,
            )


if __name__ == "__main__":
    import csv
    import sys

    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parent.parent / "data" / "experiments" / "txt_frame_features.csv"
    )
    rows = list(iter_records())
    fieldnames = ["record_index", "frame_id", *FEATURE_COLUMNS,
                  "categorized_attack", "specific_attack", "source", "destination", "timestamp"]
    with out_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            d = asdict(r)
            w.writerow({k: d[k] for k in fieldnames})
    print(f"wrote {len(rows)} rows -> {out_path}")
