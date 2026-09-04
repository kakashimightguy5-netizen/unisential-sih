"""Shared fixtures.

`detector_result` runs the real EXP-0002 detector once per test session over the
full TXT egress stream (~7s: 209k frames -> 35,935 windows -> IF fit/score). Every
integration test reads from that one result rather than re-running the pipeline.
"""
import pytest


@pytest.fixture(scope="session")
def detector_result():
    from iforest_detector import run_detector
    return run_detector()
