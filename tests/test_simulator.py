"""Policy simulator tests."""

import json
from pathlib import Path

from cli.main import app as cli_app
from core.models import PolicyDoc, PolicyStatement
from core.policy.simulator import PolicySimulator, SimulationCase


def test_local_simulation_allows_matching_action():
    policy = PolicyDoc(
        statements=[PolicyStatement(actions=["s3:GetObject"], resources=["arn:aws:s3:::bucket/*"])],
    )
    simulator = PolicySimulator(client=None)
    result = simulator.compare(
        before=policy,
        after=policy,
        cases=[SimulationCase(action="s3:GetObject", resource="arn:aws:s3:::bucket/object.txt")],
    )
    assert result[0]["before"] == "Allow"
    assert result[0]["after"] == "Allow"


def test_local_simulation_denies_missing_match():
    policy = PolicyDoc(statements=[PolicyStatement(actions=["s3:PutObject"], resources=["*"])])
    simulator = PolicySimulator(client=None)
    result = simulator.compare(
        before=policy,
        after=policy,
        cases=[SimulationCase(action="s3:GetObject", resource="arn:aws:s3:::bucket/object.txt")],
    )
    assert result[0]["before"] == "Deny"


def test_cli_diff_threshold_failure(tmp_path):
    before = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Stmt", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]}
        ],
    }
    after = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Stmt", "Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["*"]}
        ],
    }
    cases = [
        {"action": "s3:GetObject", "resource": "arn:aws:s3:::bucket/object.txt"},
    ]

    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    cases_path = tmp_path / "cases.json"
    out_path = tmp_path / "diff.json"

    before_path.write_text(__import__("json").dumps(before), encoding="utf-8")
    after_path.write_text(__import__("json").dumps(after), encoding="utf-8")
    cases_path.write_text(__import__("json").dumps(cases), encoding="utf-8")

    exit_code = cli_app(
        [
            "diff",
            "--before",
            str(before_path),
            "--after",
            str(after_path),
            "--cases",
            str(cases_path),
            "--deny-threshold",
            "0.1",
            "--format",
            "json",
            "--output",
            str(out_path),
        ]
    )
    assert exit_code == 3
    diff_data = json.loads(out_path.read_text(encoding="utf-8"))
    summary = diff_data.get("summary", {})
    for key in ("allow_reduced_pct", "resource_concrete_pct", "deny_change", "high_risk_reduced"):
        assert key in summary
