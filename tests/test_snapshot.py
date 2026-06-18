from sentinel.providers._snapshot import api_error, collection_quality, finalize_snapshot, merge_results


def test_collection_quality_states():
    assert collection_quality([], checks_attempted=1, checks_succeeded=1) == "complete"
    assert collection_quality([{}], checks_attempted=1, checks_succeeded=1) == "partial"
    assert collection_quality([{}], checks_attempted=1, checks_succeeded=0) == "failed"


def test_finalize_and_merge():
    a = finalize_snapshot({"x": 1}, [], checks_attempted=1, checks_succeeded=1)
    assert a["collection_quality"] == "complete"
    b = finalize_snapshot(
        {"y": 2},
        [api_error("E", "msg")],
        checks_attempted=1,
        checks_succeeded=0,
    )
    merged = merge_results(a, b)
    assert merged["collection_quality"] in {"partial", "failed"}
    assert len(merged["errors"]) >= 1