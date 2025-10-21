"""Policy generator tests for action merging and resources."""

from __future__ import annotations

from core.models import ActionRecord
from core.policy.generator import PolicyGenerator


def _record(
    *,
    action: str,
    service: str,
    resources: list[str] | None = None,
    conditions: list[dict[str, object]] | None = None,
) -> ActionRecord:
    return ActionRecord(
        principal_arn="arn:aws:iam::123456789012:role/Test",
        service=service,
        action=action,
        count=1,
        resources=resources or [],
        conditions=conditions or [],
    )


def test_policy_generator_groups_actions_by_resource():
    records = [
        _record(action="s3:GetObject", service="s3", resources=["arn:aws:s3:::example/*"]),
        _record(action="s3:PutObject", service="s3", resources=["arn:aws:s3:::example/*"]),
    ]
    policy = PolicyGenerator().build(records)
    assert len(policy.statements) == 1
    statement = policy.statements[0]
    assert sorted(statement.actions) == ["s3:GetObject", "s3:PutObject"]
    assert statement.resources == ["arn:aws:s3:::example/*"]


def test_policy_generator_uses_wildcard_when_no_resources():
    records = [_record(action="dynamodb:ListTables", service="dynamodb")]
    policy = PolicyGenerator().build(records)
    statement = policy.statements[0]
    assert statement.resources == ["*"]


def test_policy_generator_adds_logs_baseline():
    records = [_record(action="lambda:InvokeFunction", service="lambda")]
    generator = PolicyGenerator(include_logs_baseline=True)
    policy = generator.build(records)
    assert any("logs:CreateLogGroup" in stmt.actions for stmt in policy.statements)


def test_policy_generator_splits_policies_when_limit():
    records = [
        _record(action=f"s3:GetObject", service="s3", resources=["arn:aws:s3:::a/*"]),
        _record(action=f"sqs:SendMessage", service="sqs", resources=["arn:aws:sqs:us-east-1:123456789012:queue"]),
    ]
    generator = PolicyGenerator(max_statements=1)
    first = generator.build(records)
    assert len(first.statements) == 1
    assert generator.additional_policies, "Expected overflow policy to be created"
    assert len(generator.additional_policies[0].statements) == 1


def test_policy_generator_actions_mode_uses_wildcard_when_no_resources():
    records = [_record(action="dynamodb:ListTables", service="dynamodb", resources=[])]
    policy = PolicyGenerator(mode="actions").build(records)
    assert policy.statements[0].resources == ["*"]


def test_policy_generator_resources_mode_preserves_resources():
    records = [_record(action="s3:GetObject", service="s3", resources=["arn:aws:s3:::bucket/*"])]
    policy = PolicyGenerator(mode="resources").build(records)
    assert policy.statements[0].resources == ["arn:aws:s3:::bucket/*"]


def test_policy_generator_sid_is_capped_length():
    long_service = "a" * 200
    record = _record(action=f"{long_service}:Get", service=long_service, resources=["*"])
    policy = PolicyGenerator().build([record])
    assert len(policy.statements[0].sid) <= 128
