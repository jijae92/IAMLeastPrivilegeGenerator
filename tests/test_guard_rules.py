import shutil
import subprocess
from pathlib import Path

import pytest


GUARD_BIN = shutil.which("cfn-guard")


@pytest.mark.skipif(GUARD_BIN is None, reason="cfn-guard not installed")
@pytest.mark.parametrize(
    "template",
    [
        Path("tests/negative/env_plain.json"),
        Path("tests/negative/iam_star.json"),
        Path("tests/negative/egress_any.json"),
    ],
)
def test_guard_negative_cases_fail(template: Path) -> None:
    result = subprocess.run(
        [
            GUARD_BIN,
            "validate",
            "--rules",
            "policy-as-code/guard/rules.guard",
            "--data",
            str(template),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


@pytest.mark.skipif(GUARD_BIN is None, reason="cfn-guard not installed")
def test_guard_project_template_passes() -> None:
    template = Path("infra/sam-app/template.yaml")
    result = subprocess.run(
        [
            GUARD_BIN,
            "validate",
            "--rules",
            "policy-as-code/guard/rules.guard",
            "--data",
            str(template),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
