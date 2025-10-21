"""Inference helpers tests."""

from datetime import datetime, timezone

import pytest

from core.inference.arn_rules import (
    ArnRuleRegistry,
    infer_dynamodb_arn,
    infer_ec2_arn,
    infer_kms_arn,
    infer_lambda_arn,
    infer_s3_arn,
    infer_secretsmanager_arn,
    infer_sns_arn,
    infer_sqs_arn,
    infer_ssmparam_arn,
)
from core.inference.resource_level import ResourceLevelIndex
from core.models import EventModel


def _event(service: str, request_parameters: dict) -> EventModel:
    return EventModel(
        event_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        principal_arn="arn:aws:iam::123456789012:user/Alice",
        principal_type="user",
        account_id="123456789012",
        region="us-east-1",
        event_source=f"{service}.amazonaws.com",
        action="GetObject",
        request_parameters=request_parameters,
        response_elements={},
        resource_arns=[],
        error_code=None,
        aws_service=service,
        is_read_only=False,
        is_denied_pre_policy=False,
    )


def test_arn_registry_falls_back_to_star():
    registry = ArnRuleRegistry()
    event = _event("unknownservice", {})
    assert registry.infer(event) == {"*"}


def test_infer_s3_arn():
    event = _event("s3", {"bucketName": "example", "key": "object.txt"})
    assert infer_s3_arn(event) == {
        "arn:aws:s3:::example",
        "arn:aws:s3:::example/object.txt",
    }


def test_infer_dynamodb_arn():
    event = _event("dynamodb", {"tableName": "Orders"})
    assert infer_dynamodb_arn(event) == {
        "arn:aws:dynamodb:us-east-1:123456789012:table/Orders"
    }


def test_infer_lambda_arn():
    event = _event("lambda", {"functionName": "Process"})
    assert infer_lambda_arn(event) == {
        "arn:aws:lambda:us-east-1:123456789012:function:Process"
    }


def test_infer_sqs_arn_from_url():
    event = _event("sqs", {"queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"})
    assert infer_sqs_arn(event) == {
        "arn:aws:sqs:us-east-1:123456789012:MyQueue"
    }


def test_infer_sns_arn_from_name():
    event = _event("sns", {"topicName": "alerts"})
    assert infer_sns_arn(event) == {
        "arn:aws:sns:us-east-1:123456789012:alerts"
    }


def test_infer_sns_from_arn():
    arn = "arn:aws:sns:us-east-1:123456789012:Alerts"
    event = _event("sns", {"topicArn": arn})
    assert infer_sns_arn(event) == {arn}


def test_infer_kms_arn_from_id():
    event = _event("kms", {"keyId": "1234abcd-12ab-34cd-56ef-1234567890ab"})
    assert infer_kms_arn(event) == {
        "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    }


def test_infer_kms_fallback_star():
    event = _event("kms", {})
    assert infer_kms_arn(event) == {"*"}


def test_infer_secretsmanager_arn_from_plain_name():
    event = _event("secretsmanager", {"secretId": "MySecret"})
    assert infer_secretsmanager_arn(event) == {
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:MySecret*"
    }


def test_infer_ssmparam_arn():
    event = _event("ssm", {"name": "/app/config"})
    assert infer_ssmparam_arn(event) == {
        "arn:aws:ssm:us-east-1:123456789012:parameter//app/config"
    }


def test_infer_lambda_fallback():
    event = _event("lambda", {})
    assert infer_lambda_arn(event) == {"*"}


def test_infer_ec2_arn_instance():
    event = _event("ec2", {"instanceId": "i-1234567890abcdef0"})
    assert infer_ec2_arn(event) == {
        "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
    }


def test_resource_level_index_defaults():
    index = ResourceLevelIndex()
    assert index.allows_scoping("s3:GetObject") is True
    assert index.allows_scoping("ec2:DescribeInstances") is False


def test_inference_registry_combines_rules():
    registry = ArnRuleRegistry()
    event = _event("s3", {"bucketName": "example"})
    result = registry.infer(event)
    assert "arn:aws:s3:::example" in result
    assert "*" not in result


def test_infer_returns_star_when_missing_fields():
    event = _event("dynamodb", {})
    assert infer_dynamodb_arn(event) == {"*"}
