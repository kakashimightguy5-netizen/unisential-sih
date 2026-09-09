"""Unit + integration proofs for EXP-0010 synthetic egress-flood injection.

The fast tests use hand-built synthetic frames. The slow test runs the real
EXP-0004 detector and the full injection sweep.
"""
import math

import pytest

import exp0010_egress_flood as exp
from features_txt import FrameRecord
from features_windowed import WINDOW_SECONDS


def frame(index, ts, *, function=0x03, length=8, entropy=3.0, fid=None):
    return FrameRecord(
        record_index=index, frame_id=index if fid is None else fid,
        address=4, function_code=function, frame_len_bytes=length, is_request=0,
        start_register=-1, quantity=-1, byte_count=-1, length_anomaly=0,
        rare_function_code=0, crc_ok=1, interarrival_seconds=0.0,
        message_entropy_bits_per_byte=entropy, categorized_attack=0,
        specific_attack=0, source=3, destination=1, timestamp=ts,
    )


def normal_window_frames(w_index=100, n=4):
    base = w_index * WINDOW_SECONDS
    return [
        frame(i, base + i * (WINDOW_SECONDS / (n + 1)),
              function=(0x03 if i % 2 == 0 else 0x10), length=8 + i, fid=1000 + i)
        for i in range(n)
    ]


# --------------------------------------------------------------- feature helper

def test_window_features_matches_manual_computation():
    frames = normal_window_frames(n=4)
    feats = exp._window_features(frames)
    assert feats["packet_count"] == 4.0
    assert feats["packets_per_sec"] == 4 / WINDOW_SECONDS
    assert feats["distinct_frame_ratio"] == 1.0
    assert feats["repeat_frame_rate"] == 0.0
    assert feats["frac_func_read"] == 0.5 and feats["frac_func_write"] == 0.5
    assert feats["frac_func_valid"] == 1.0


# --------------------------------------------------------------- synthesis: K=1

def test_k1_is_a_no_op_for_both_profiles():
    frames = normal_window_frames()
    for profile in exp.PROFILES:
        out = exp.synthesize_flood(frames, 100, 1, profile)
        assert [f.frame_id for f in out] == [f.frame_id for f in frames]
        assert exp._window_features(out) == exp._window_features(frames)


# --------------------------------------------------------------- profile A

def test_profile_a_scales_rate_only_distinct_frames():
    frames = normal_window_frames(w_index=100, n=4)
    k = 5
    out = exp.synthesize_flood(frames, 100, k, "A_distinct")
    assert len(out) == k * 4
    assert len({f.frame_id for f in out}) == k * 4          # all distinct
    assert all(math.floor(f.timestamp / WINDOW_SECONDS) == 100 for f in out)
    ts = [f.timestamp for f in out]
    assert ts == sorted(ts)
    gaps = [round(ts[i] - ts[i - 1], 9) for i in range(1, len(ts))]
    assert len(set(gaps)) == 1                              # uniform re-spacing

    f0 = exp._window_features(frames)
    f1 = exp._window_features(out)
    assert f1["packets_per_sec"] == pytest.approx(k * f0["packets_per_sec"])
    assert f1["bytes_per_sec"] == pytest.approx(k * f0["bytes_per_sec"])
    assert f1["packet_count"] == k * f0["packet_count"]
    assert f1["distinct_frame_ratio"] == 1.0
    assert f1["repeat_frame_rate"] == 0.0
    assert f1["iat_std"] == 0.0
    assert f1["mean_frame_len"] == pytest.approx(f0["mean_frame_len"])
    assert f1["frac_func_read"] == pytest.approx(f0["frac_func_read"])
    assert f1["payload_entropy_mean"] == pytest.approx(f0["payload_entropy_mean"])


# --------------------------------------------------------------- profile B

def test_profile_b_keeps_frame_ids_and_collapses_distinct_ratio():
    frames = normal_window_frames(w_index=100, n=4)
    k = 5
    out = exp.synthesize_flood(frames, 100, k, "B_duplicate")
    assert len(out) == k * 4
    assert set(f.frame_id for f in out) == set(f.frame_id for f in frames)
    f1 = exp._window_features(out)
    assert f1["distinct_frame_ratio"] == pytest.approx(4 / (k * 4))
    assert f1["repeat_frame_rate"] > 0.5
    assert f1["packet_count"] == k * 4.0
    # frames grouped by id -> non-decreasing id order
    ids = [f.frame_id for f in out]
    assert ids == sorted(ids)


def test_flood_preserves_function_codes_so_rule_layer_stays_silent():
    frames = normal_window_frames(n=6)
    for profile in exp.PROFILES:
        out = exp.synthesize_flood(frames, 100, 10, profile)
        assert {f.function_code for f in out} <= {0x03, 0x10}
        assert {f.address for f in out} == {4}


def test_unknown_profile_rejected():
    with pytest.raises(ValueError, match="unknown profile"):
        exp.synthesize_flood(normal_window_frames(), 100, 2, "C_bogus")


def test_preregistered_constants():
    assert exp.SEVERITIES == (1, 2, 5, 10, 20)
    assert exp.PROFILES == ("A_distinct", "B_duplicate")
    assert exp.EXP0004_TEST_CONFUSION == (4771, 36, 3793, 747)


# --------------------------------------------------------------- integration

@pytest.mark.slow
def test_full_flood_test_runs_and_gates_hold():
    result = exp.run_flood_test()
    assert result["experiment"] == "EXP-0010"
    assert "SYNTHETIC INJECTION TEST" in result["warning"]
    assert result["detector"]["modified"] is False

    # boundary + identity gates passed (construction would have raised otherwise)
    assert result["manifest"]["split_id"] == "verified-egress-5s-exp0008-pretest-v1"
    assert len(result["detector"]["identity_gates_passed"]) == 3

    # untouched real Normal TEST FP == EXP-0004 reference, exactly
    ut = result["untouched_real_normal_test"]
    assert ut["n"] == 4807
    assert ut["combined_fpr"] == ut["exp0004_reference_combined_fpr"]

    rows = result["dose_response"]
    assert len(rows) == len(exp.PROFILES) * len(exp.SEVERITIES)
    n_pos = result["evaluation_cohort"]["total_windows_per_row"] // 2
    for row in rows:
        assert 0.0 <= row["combined_rate"] <= 1.0
        assert row["rule_rate"] == 0.0                      # rule layer is volume-blind
        c = row["confusion_vs_real_normal_test"]
        # negative class is constant and equals EXP-0004's real Normal TEST split
        assert (c["tn"], c["fp"]) == (4771, 36)
        assert c["tn"] + c["fp"] == ut["n"] == 4807
        assert c["tp"] + c["fn"] == n_pos == 4807
        assert c["tp"] == row["combined_flagged"]
        assert c["precision"] == pytest.approx(c["tp"] / (c["tp"] + c["fp"]))
        assert c["recall"] == pytest.approx(row["combined_rate"])
        assert c["fpr"] == pytest.approx(36 / 4807)
        if row["severity_x"] == 1:
            assert row["combined_rate"] == ut["combined_fpr"]
        else:
            assert row["combined_rate"] >= ut["combined_fpr"]
