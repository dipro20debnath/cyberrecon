import pytest

from cyberrecon.policy import PolicyError, evaluate_gate, validate_fail_level


def test_policy_gate_fails_on_threshold_and_change():
    report = {
        "risk": {"severity": "high"},
        "comparison": {"summary": {"has_changes": True, "added": 2, "removed": 1}},
    }
    reasons = evaluate_gate(report, fail_on="medium", fail_on_change=True)
    assert len(reasons) == 2
    assert "risk severity high" in reasons[0]
    assert "baseline changed" in reasons[1]


def test_policy_gate_allows_lower_risk():
    assert evaluate_gate({"risk": {"severity": "low"}}, fail_on="high") == []


def test_policy_rejects_invalid_level():
    with pytest.raises(PolicyError, match="low, medium, high or critical"):
        validate_fail_level("urgent")
