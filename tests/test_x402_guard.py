"""Tests for x402 dry-run payment route contracts."""

import json

from guard0.x402_guard import (
    X402_FIXTURE_PAYMENT_HEADER,
    build_x402_wallet_preflight_dry_run,
)


def test_x402_wallet_preflight_requires_payment_without_settlement():
    payload = build_x402_wallet_preflight_dry_run()

    assert payload["schema"] == "0guard.x402_wallet_preflight_dry_run.v1"
    assert payload["status"] == "payment_required_dry_run"
    assert payload["httpStatus"] == 402
    assert payload["paymentRequirement"]["displayPrice"] == "0.01 USDC"
    assert payload["paymentReadback"]["facilitatorCalled"] is False
    assert payload["paymentReadback"]["settlementEnabled"] is False
    assert payload["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    assert payload["safety"]["x402SettlementEnabled"] is False
    assert payload["safety"]["moneyMovementEnabled"] is False


def test_x402_wallet_preflight_accepts_only_fixture_payment_header():
    payload = build_x402_wallet_preflight_dry_run(
        payment_header=X402_FIXTURE_PAYMENT_HEADER,
        body={"target": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab"},
    )

    assert payload["status"] == "payment_fixture_accepted_no_settlement"
    assert payload["httpStatus"] == 200
    assert payload["paymentReadback"]["paymentHeaderAccepted"] is True
    assert payload["paymentReadback"]["paymentHeaderReturned"] is False
    assert payload["productResponse"]["rawPayloadResaleAllowed"] is False
    assert payload["productResponse"]["targetHash"]
    assert payload["safety"]["facilitatorCalled"] is False


def test_x402_wallet_preflight_rejects_malformed_payment_without_echo():
    secretish_header = "not-a-real-payment-secret-token"
    payload = build_x402_wallet_preflight_dry_run(payment_header=secretish_header)

    assert payload["status"] == "malformed_payment_fixture"
    assert payload["httpStatus"] == 400
    assert payload["paymentReadback"]["paymentHeaderAccepted"] is False
    assert payload["paymentReadback"]["paymentHeaderHash"]
    encoded = json.dumps(payload)
    assert secretish_header not in encoded
    assert payload["safety"]["paymentSettlementEnabled"] is False
