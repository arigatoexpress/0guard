"""Tests for the critical strategy review contract."""

from guard0.strategy_review import build_strategy_review


def test_strategy_review_is_opinionated_safe_and_actionable():
    review = build_strategy_review()

    assert review["schema"] == "0guard.strategy_review.v1"
    assert review["mode"] == "critical_strategy_review_no_side_effects"
    assert "pre-wallet risk receipt network" in review["executiveTake"]
    assert review["safety"]["transactionSigningEnabled"] is False
    assert review["safety"]["telegramSendsEnabled"] is False
    assert review["safety"]["moneyMovementEnabled"] is False
    assert review["safety"]["rawPayloadsReturned"] is False

    critique_ids = {item["id"] for item in review["whatIWouldDoDifferently"]}
    assert {
        "narrow_the_claim",
        "one_paid_route_first",
        "data_moat_before_more_adapters",
        "model_as_narrator_not_judge",
    } <= critique_ids

    spine_layers = [item["layer"] for item in review["productSpine"]]
    assert spine_layers == ["decision", "evidence", "proof", "distribution", "operations"]
    assert review["nextBuildSequence"][0]["id"] == "production_contract_freeze"
    assert "live_mainnet_payment_before_testnet" in {
        item["id"] for item in review["killOrDefer"]
    }

