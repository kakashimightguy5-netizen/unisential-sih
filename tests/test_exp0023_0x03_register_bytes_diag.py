"""EXP-0023: synthetic units for the 0x03 register-byte offset math, plus one slow
saved-result replay (no raw-data read). INVESTIGATIVE/DESCRIPTIVE ONLY — there is no
detector/rule/model under test here.
"""
import json
import math
import struct
from pathlib import Path

import numpy as np
import pytest

import exp0023_0x03_register_bytes_diag as exp

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0023_register_bytes.json"


# ------------------------------------------------------- offset math sanity

def _make_0x03_response(undecoded: bytes, pressure: float) -> bytes:
    """Build a syntactically valid 23-byte 0x03 response: addr,func,bytecount=18,
    14 undecoded bytes, 4-byte big-endian pressure float, 2-byte (unchecked) CRC."""
    assert len(undecoded) == 14
    body = bytes([0x04, 0x03, 18]) + undecoded + struct.pack(">f", pressure)
    return body + b"\x00\x00"  # CRC not checked by undecoded_bytes/pressure_bytes


def test_undecoded_bytes_is_frame_3_to_17():
    frame = _make_0x03_response(bytes(range(14)), 12.5)
    ub = exp.undecoded_bytes(frame)
    assert ub == bytes(range(14))
    assert len(ub) == exp.UNDECODED_LEN == 14


def test_pressure_bytes_is_frame_17_to_21_and_reproduces_frozen_sample():
    """Reproduces the real frozen frame from EXP-0016 (`04031210000e000c7600...`,
    ARFF pressure 0.689655) as an offset-math sanity check, independent of any
    live raw-data read."""
    frame = bytes.fromhex("04031210000e000c7600000000000000003f308d3e3044")
    assert len(frame) == 23
    (value,) = struct.unpack(">f", exp.pressure_bytes(frame))
    assert math.isclose(value, 0.689655, rel_tol=1e-3)
    assert exp.undecoded_bytes(frame).hex() == "10000e000c760000000000000000"


def test_undecoded_bytes_rejects_non_canonical_frames():
    assert exp.undecoded_bytes(bytes(8)) is None  # too short / a request, not a response
    non_response = bytes([0x04, 0x03, 0, 0, 0, 0, 0, 0])
    assert exp.undecoded_bytes(non_response) is None
    wrong_func = bytes([0x04, 0x10, 18]) + bytes(20)
    assert exp.undecoded_bytes(wrong_func) is None
    wrong_byte_count = bytes([0x04, 0x03, 10]) + bytes(20)
    assert exp.undecoded_bytes(wrong_byte_count) is None


# ------------------------------------------------------- per-byte / register / float audits

def _sample(undecoded_hex: str, cat=0, bucket=0, pressure=1.0) -> exp.Sample:
    ub = bytes.fromhex(undecoded_hex)
    assert len(ub) == 14
    return exp.Sample(bucket=bucket, cat=cat, spec=0, ts=0.0, undecoded=ub,
                       pressure=pressure, pressure_from_bytes=pressure)


def test_audit_byte_detects_constant_and_varying():
    samples = [_sample("00" * 14) for _ in range(5)] + [_sample("01" + "00" * 13)]
    const = exp.audit_byte(1, samples)
    assert const["is_constant"] is True
    assert const["n_distinct"] == 1
    varying = exp.audit_byte(0, samples)
    assert varying["is_constant"] is False
    assert varying["n_distinct"] == 2
    assert varying["min"] == 0 and varying["max"] == 1


def test_byte_entropy_bits_zero_for_constant_max_for_uniform_bimodal():
    assert exp.byte_entropy_bits([5, 5, 5, 5]) == 0.0
    assert math.isclose(exp.byte_entropy_bits([0, 1, 0, 1]), 1.0, rel_tol=1e-9)


def test_audit_register_pair_big_endian():
    # register 0 = bytes[0:2]; 0x01,0x02 -> 0x0102
    ub_hex = "0102" + "00" * 12
    samples = [_sample(ub_hex)]
    reg = exp.audit_register_pair(0, samples)
    assert reg["max"] == 0x0102
    assert reg["byte_offsets"] == [0, 1]


def test_audit_float_candidate_roundtrips_a_known_float():
    f = 3.5
    ub = struct.pack(">f", f) + b"\x00" * 10
    samples = [_sample(ub.hex())]
    cand = exp.audit_float_candidate(0, samples)
    assert cand["n_finite"] == 1
    assert math.isclose(cand["mean"], 3.5)


# ------------------------------------------------------- stats helpers

def test_pearson_and_spearman_perfect_linear():
    a = [1, 2, 3, 4, 5]
    b = [2, 4, 6, 8, 10]
    assert math.isclose(exp.pearson(a, b), 1.0, rel_tol=1e-9)
    assert math.isclose(exp.spearman(a, b), 1.0, rel_tol=1e-9)


def test_pearson_none_when_constant():
    assert exp.pearson([1, 1, 1], [1, 2, 3]) is None


def test_window_means_aggregates_per_bucket():
    samples = [_sample("00" * 14, bucket=1), _sample("02" + "00" * 13, bucket=1),
               _sample("04" + "00" * 13, bucket=2)]
    means = exp.window_means(samples, lambda s: s.undecoded[0])
    assert means[1] == 1.0  # mean of 0 and 2
    assert means[2] == 4.0


# ------------------------------------------------------- category Cohen's d convention

class _Blocks:
    def __init__(self, train, validation):
        self.train = set(train)
        self.validation = set(validation)


def test_build_bucket_cats_scopes_to_train_plus_validation():
    samples = [
        exp.Sample(bucket=0, cat=0, spec=0, ts=0.0, undecoded=bytes(14), pressure=1.0, pressure_from_bytes=1.0),
        exp.Sample(bucket=1, cat=3, spec=0, ts=0.0, undecoded=bytes(14), pressure=1.0, pressure_from_bytes=1.0),
        exp.Sample(bucket=99, cat=3, spec=0, ts=0.0, undecoded=bytes(14), pressure=1.0, pressure_from_bytes=1.0),
    ]
    blocks = _Blocks(train=[0, 1], validation=[])
    bucket_cats = exp.build_bucket_cats(blocks, samples)
    assert bucket_cats == {0: {0}, 1: {3}}  # bucket 99 outside TRAIN+VAL scope, excluded


def test_category_cohens_d_separates_shifted_category_from_normal():
    # pure-Normal windows (bucket -> cat 0) at 0.0, pure-MSCI windows at +5.0
    field_by_window = {}
    bucket_cats = {}
    for b in range(10):
        bucket_cats[b] = {0}
        field_by_window[b] = float(b % 2)  # small within-group variance, mean 0.5
    for b in range(10, 15):
        bucket_cats[b] = {3}
        field_by_window[b] = 5.0 + float(b % 2)  # mean ~5.4
    out = exp.category_cohens_d(field_by_window, bucket_cats)
    assert out["MSCI"]["n_windows"] == 5
    assert out["MSCI"]["cohens_d_vs_full_normal"] > 0
    assert out["MPCI"]["n_windows"] == 0


def test_category_cohens_d_zero_std_gives_zero_d():
    field_by_window = {0: 1.0, 1: 1.0, 2: 1.0}
    bucket_cats = {0: {0}, 1: {0}, 2: {3}}
    out = exp.category_cohens_d(field_by_window, bucket_cats)
    assert out["MSCI"]["cohens_d_vs_full_normal"] == 0.0


def test_category_cohens_d_matches_nearest_normal_bucket_by_index():
    # Normal windows at buckets 0 (val 0.0) and 100 (val 100.0); MSCI at bucket 40
    # should nearest-match bucket 0, at bucket 90 should nearest-match bucket 100.
    field_by_window = {0: 0.0, 1: 0.1, 100: 100.0, 101: 100.1, 40: 9.0, 90: 91.0}
    bucket_cats = {0: {0}, 1: {0}, 100: {0}, 101: {0}, 40: {3}, 90: {3}}
    out = exp.category_cohens_d(field_by_window, bucket_cats)
    assert out["MSCI"]["n_windows"] == 2
    # matched mean should be much closer to the attack mean than the full-normal mean is
    assert out["MSCI"]["cohens_d_vs_matched_normal"] < out["MSCI"]["cohens_d_vs_full_normal"]


# ------------------------------------------------------- scope / source discipline

def test_module_never_parses_or_uses_source_field():
    src = Path(exp.__file__).read_text(encoding="utf-8")
    # 'source' must not appear as an identifier used for filtering/features anywhere
    # (comments referencing the constraint are fine; code access is not).
    import ast
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "source":
            pytest.fail("exp0023 must never read record.source")
        if isinstance(node, ast.Name) and node.id == "source":
            pytest.fail("exp0023 must never bind/use a bare 'source' identifier")


def test_module_does_not_import_run_detector_or_protected_files():
    src = Path(exp.__file__).read_text(encoding="utf-8")
    for forbidden in ("iforest_detector", "rules", "app", "features_windowed"):
        assert f"import {forbidden}" not in src
        assert f"from {forbidden} " not in src


# ------------------------------------------------------- slow replay (no raw read)

@pytest.mark.slow
def test_saved_result_identity_gate_and_offset_sanity():
    if not RESULT_PATH.exists():
        pytest.skip("EXP-0023 result not generated in this tree")
    r = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert r["identity_gates"]["exp0017_reproduced"] is True
    assert tuple(r["identity_gates"]["exp0017_confusion"]) == exp.EXP0017_TEST_CONFUSION
    assert r["pressure_offset_sanity_check"]["all_match"] is True
    assert r["pressure_offset_sanity_check"]["n_checked_against_arff"] > 0
    assert len(r["per_byte_train_normal"]) == 14
    # only category (d)-style claims allow a promising verdict; script makes no
    # such verdict itself, so just check the shape is present for every priority cat
    for off in r["non_constant_byte_offsets"]:
        comparison = r["attack_comparison_per_byte"][str(off)]
        for cat in ("MSCI", "MPCI"):
            assert cat in comparison
