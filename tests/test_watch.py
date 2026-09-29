from typer.testing import CliRunner

from cyberrecon.cli import app


def test_watch_rejects_invalid_iteration_count():
    result = CliRunner().invoke(app, ["watch", "example.com", "--iterations", "0"])
    assert result.exit_code == 2
    assert "between 1 and 1000" in result.stdout
