from main import threshold_blocked


def test_scanner_error_is_not_counted_as_successful_block():
    assert threshold_blocked(2, {"matches": [{"vulnerability": {"severity": "High"}}]})
    assert not threshold_blocked(2, {"matches": []})
    assert not threshold_blocked(1, {})
    assert not threshold_blocked(0, {"matches": [1]})
