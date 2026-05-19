"""Tests for prepared social/newsletter content."""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_current_x_update_thread_is_review_ready_and_within_limits():
    path = REPO_ROOT / "content" / "0guard_current_update_x_thread.json"
    data = json.loads(path.read_text(encoding="utf-8"))

    tweets = data["tweets"]
    assert len(tweets) == 5
    assert all(1 <= len(tweet) <= 280 for tweet in tweets)
    combined = "\n".join(tweets).lower()
    assert "pre-wallet firewall" in combined
    assert "no signing" in combined
    assert "no fund movement" in combined
    assert "0guard" in combined


def test_postsubmit_x_update_thread_is_review_ready_and_within_limits():
    path = REPO_ROOT / "content" / "0guard_postsubmit_update_x_thread.json"
    data = json.loads(path.read_text(encoding="utf-8"))

    tweets = data["tweets"]
    assert len(tweets) == 4
    assert all(1 <= len(tweet) <= 280 for tweet in tweets)
    combined = "\n".join(tweets).lower()
    assert "34 rights-aware source lanes" in combined
    assert "20 no-network reputation connector" in combined
    assert "threatfox" in combined
    assert "chainalysis" in combined
    assert "trm" in combined
    assert "web risk" in combined
    assert "#0ghackathon" in combined
    assert "#buildon0g" in combined
    assert "still reading back as submitted" not in combined
    assert "still submitted" not in combined


def test_main_and_zeroguard_x_update_threads_are_review_ready():
    paths = [
        REPO_ROOT / "content" / "x_main_account_hackathon_update_2026-05-16.json",
        REPO_ROOT / "content" / "x_zeroguard_account_update_2026-05-16.json",
    ]

    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        tweets = data["tweets"]
        assert len(tweets) == 4
        assert all(1 <= len(tweet) <= 280 for tweet in tweets)
        combined = "\n".join(tweets).lower()
        assert "0g apac hackathon" in combined
        assert "project is submitted" not in combined or "is submitted" in combined
        assert "still submitted" not in combined
        assert "still reading back as submitted" not in combined
        assert "#0ghackathon" in combined
        assert "#buildon0g" in combined


def test_substack_draft_is_plain_english_and_safety_bounded():
    text = (REPO_ROOT / "content" / "substack_0guard_launch_draft.md").read_text(
        encoding="utf-8"
    )

    assert text.startswith("# 0guard:")
    assert "AI agents should not get to the wallet first" in text
    assert "does not sign transactions" in text
    assert "GoPlus" in text
    assert "0G" in text
