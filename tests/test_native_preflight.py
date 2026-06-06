"""Tests for the unified native preflight surface."""

from guard0.native_preflight import build_native_preflight, hackathon_strategy


def test_native_preflight_reviews_ton_without_address_and_allows_read_only_evm():
    ton = build_native_preflight(
        {
            "surface": "ton",
            "operation": "preview_wallet",
            "chain": "ton:mainnet",
            "intentText": "Preview Telegram wallet risk before any wallet prompt.",
        }
    )
    evm = build_native_preflight(
        {
            "surface": "evm",
            "operation": "read_status",
            "chain": "eip155:8453",
            "intent": {"mode": "preview"},
        }
    )

    assert ton["decision"] == "review"
    assert any(component["id"] == "ton_risk_passport" for component in ton["components"])
    assert evm["decision"] == "allow"
    assert evm["safety"]["bridgingEnabled"] is False


def test_native_preflight_routes_arbitrum_and_metamask_to_external_guardrails():
    arbitrum = build_native_preflight(
        {
            "surface": "arbitrum_sepolia",
            "operation": "upgrade_proxy",
            "chain": "eip155:421614",
            "intentText": "Activate a Stylus upgrade through an admin wallet.",
        }
    )
    metamask = build_native_preflight(
        {
            "surface": "metamask_delegation",
            "operation": "requestExecutionPermissions",
            "chain": "eip155:1",
            "intentText": "Grant delegated agent spend permission without expiry.",
            "config": {"maxAmount": "10"},
        }
    )

    assert arbitrum["decision"] == "review"
    assert any(component["id"] == "external_guardrail" for component in arbitrum["components"])
    assert metamask["decision"] == "deny"
    assert any(component["id"] == "external_guardrail" for component in metamask["components"])


def test_hackathon_strategy_is_0g_first_and_source_cited():
    strategy = hackathon_strategy()

    assert strategy["schema"] == "0guard.hackathon_strategy.v1"
    assert strategy["opportunities"][0]["id"] == "0g_apac_final_review"
    assert strategy["thesis"]["0gFirst"].startswith("0G remains")
    assert all(opportunity["sources"] for opportunity in strategy["opportunities"])
    assert strategy["safety"]["moneyMovementEnabled"] is False
