import json

import pytest

from cyberrecon.reporting import write_report
from cyberrecon.utils.validators import TargetValidationError, normalize_target


def test_target_normalization():
    assert normalize_target("Example.COM.").value == "example.com"
    assert normalize_target("192.0.2.10").kind == "ip"
    with pytest.raises(TargetValidationError):
        normalize_target("../etc/passwd")


def test_all_report_formats(tmp_path):
    data = {"target": "example.com", "modules": {"dns": {"records": {"A": ["192.0.2.10"]}}}}
    for fmt in ("json", "csv", "html"):
        path = write_report(data, tmp_path, "example.com", fmt)
        assert path.exists()
        assert path.suffix == f".{fmt}"
    assert json.loads((tmp_path / "example.com_scan.json").read_text(encoding="utf-8"))["target"] == "example.com"
