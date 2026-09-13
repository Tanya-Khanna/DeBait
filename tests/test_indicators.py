from debait.hunter.indicators import extract_indicators


def test_indicators_preserve_attacker_supplied_source_and_spans():
    text = "Use https://Pay.Example.Test/checkout and contact @mule_demo. Account: TEST-4488."
    values = extract_indicators(text, "decoy-reply-1")

    domain = next(value for value in values if value.kind == "domain")
    handle = next(value for value in values if value.kind == "payment_handle")
    account = next(value for value in values if value.kind == "account_string")
    assert domain.value == "pay.example.test"
    assert handle.value == "@mule_demo"
    assert account.value == "TEST-4488"
    assert all(value.source_event_id == "decoy-reply-1" for value in values)
    assert all(value.claim_status == "attacker_supplied" for value in values)
    assert text[domain.source_start : domain.source_end].lower().startswith("https://")


def test_duplicate_indicators_are_normalized_without_claiming_illicit_ownership():
    values = extract_indicators("https://pay.example.test/a then https://PAY.EXAMPLE.TEST/b", "reply-2")
    domains = [value for value in values if value.kind == "domain"]
    assert len(domains) == 1
    assert domains[0].claim_status != "confirmed_illicit"
