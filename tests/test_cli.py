"""CLI tests. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from baysoz_admissioncel.cli import main

_ROOT = Path(__file__).resolve().parents[1]
_EXAMPLES = _ROOT / "examples"


def test_version_and_help_are_attributed(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as version_exit:
        main(["--version"])
    assert version_exit.value.code == 0
    version = capsys.readouterr().out
    assert "Baysöz Labs <baysozlabs@proton.me>" in version

    with pytest.raises(SystemExit) as help_exit:
        main(["--help"])
    assert help_exit.value.code == 0
    help_text = capsys.readouterr().out
    assert "Baysöz Labs <baysozlabs@proton.me>" in help_text
    assert "check" in help_text


def test_check_text_and_json(capsys: pytest.CaptureFixture[str]) -> None:
    args = [
        "check",
        "--policy",
        str(_EXAMPLES / "policy.yaml"),
        "--binding",
        str(_EXAMPLES / "policy.yaml"),
        "--fixtures",
        str(_EXAMPLES / "fixtures.yaml"),
        "--params",
        str(_EXAMPLES / "params.yaml"),
        "--forge",
        "--max-fixtures",
        "12",
    ]
    assert main(args) == 0
    text = capsys.readouterr().out
    assert "Baysöz Labs <baysozlabs@proton.me>" in text
    assert "evaluations=" in text
    assert main([*args, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["attribution"] == "Baysöz Labs <baysozlabs@proton.me>"
    assert payload["summary"]["denied"] >= 1


def test_check_sarif_output(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "check",
            "--policy",
            str(_EXAMPLES / "policy.yaml"),
            "--binding",
            str(_EXAMPLES / "policy.yaml"),
            "--fixtures",
            str(_EXAMPLES / "fixtures.yaml"),
            "--params",
            str(_EXAMPLES / "params.yaml"),
            "--format",
            "sarif",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
    assert "Baysöz Labs" in payload["runs"][0]["tool"]["driver"][
        "fullDescription"
    ]["text"]


def test_forge_json_is_attributed(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "forge",
            "--policy",
            str(_EXAMPLES / "policy.yaml"),
            "--format",
            "json",
            "--max-fixtures",
            "4",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["attribution"] == "Baysöz Labs <baysozlabs@proton.me>"
    assert len(payload["fixtures"]) <= 4


def test_invalid_input_exits_two(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("kind: [broken\n", encoding="utf-8")
    code = main(["check", "--policy", str(path)])
    assert code == 2
    assert "Baysöz Labs" in capsys.readouterr().err
