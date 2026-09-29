import os

import pytest

from cyberrecon.history import HistoryError, collect_history


def _write_report(path, target, score, completed_at):
    path.write_text(
        '{"target": "%s", "completed_at": "%s", "risk": {"score": %s, "severity": "low"}, "duration_ms": 42}'
        % (target, completed_at, score),
        encoding="utf-8",
    )


def test_collect_history_filters_target_and_keeps_newest(tmp_path):
    older = tmp_path / "older.json"
    newer = tmp_path / "newer.json"
    other = tmp_path / "other.json"
    _write_report(older, "example.com", 10, "2026-09-28T10:00:00Z")
    _write_report(newer, "Example.COM.", 20, "2026-09-29T10:00:00Z")
    _write_report(other, "other.example", 90, "2026-09-29T11:00:00Z")
    os.utime(older, (100, 100))
    os.utime(newer, (200, 200))
    os.utime(other, (300, 300))

    records = collect_history(tmp_path, target="example.com", limit=10)
    assert [item["path"] for item in records] == [newer, older]
    assert records[0]["risk_score"] == 20
    assert records[0]["duration_ms"] == 42


def test_collect_history_rejects_invalid_limit(tmp_path):
    with pytest.raises(HistoryError, match="between 1 and 500"):
        collect_history(tmp_path, limit=0)
