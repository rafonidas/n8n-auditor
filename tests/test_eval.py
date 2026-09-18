"""Precision / recall evaluation over the fixture sets.

Targets (from SPEC): recall >= 0.95 on planted, precision >= 0.9 on adversarial,
and zero non-info false positives on the clean set.
"""
import pytest
from eval_lib import discover_units, evaluate, print_table

RECALL_TARGET = 0.95
PRECISION_TARGET = 0.90


@pytest.fixture(scope="module")
def results():
    res = {
        "clean": evaluate(discover_units("clean")),
        "planted": evaluate(discover_units("planted")),
        "adversarial": evaluate(discover_units("adversarial")),
    }
    print_table("static-layer evaluation (P=precision, R=recall)", res)
    return res


def test_fixture_counts():
    assert len(discover_units("clean")) >= 5
    assert len(discover_units("planted")) >= 25
    assert len(discover_units("adversarial")) >= 10


def test_clean_set_has_no_false_positives(results):
    res = results["clean"]
    assert res.total.fp == 0, "false positives on clean set:\n" + "\n".join(res.failures)


def test_planted_recall(results):
    res = results["planted"]
    assert res.total.recall >= RECALL_TARGET, (
        f"planted recall {res.total.recall:.2f} < {RECALL_TARGET}:\n" + "\n".join(res.failures)
    )
    assert res.total.fp == 0, "false positives on planted set:\n" + "\n".join(res.failures)


def test_adversarial_precision(results):
    res = results["adversarial"]
    assert res.total.precision >= PRECISION_TARGET, (
        f"adversarial precision {res.total.precision:.2f} < {PRECISION_TARGET}:\n"
        + "\n".join(res.failures)
    )
    assert res.total.fn == 0, "adversarial expected findings missed:\n" + "\n".join(res.failures)
