"""Smoke tests: engine + initial planted fixtures behave as expected."""
from eval_lib import discover_units, evaluate


def test_planted_fixtures_detect():
    units = discover_units("planted")
    assert units, "no planted fixtures found"
    result = evaluate(units)
    assert result.total.fn == 0, f"missed findings: {result.failures}"
    assert result.total.fp == 0, f"false positives: {result.failures}"
