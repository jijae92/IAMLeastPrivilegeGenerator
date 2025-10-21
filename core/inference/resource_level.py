"""Static mappings describing resource-level support for AWS actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


# Curated from AWS IAM documentation (selected services relevant to least-privilege policies)
_DEFAULT_SUPPORT: Dict[str, bool] = {
    # S3
    "s3:GetObject": True,
    "s3:PutObject": True,
    "s3:DeleteObject": True,
    "s3:ListBucket": True,
    "s3:ListAllMyBuckets": False,
    # DynamoDB
    "dynamodb:PutItem": True,
    "dynamodb:GetItem": True,
    "dynamodb:DeleteItem": True,
    "dynamodb:Query": True,
    "dynamodb:Scan": True,
    "dynamodb:ListTables": False,
    # Lambda
    "lambda:InvokeFunction": True,
    "lambda:ListFunctions": False,
    # SQS
    "sqs:SendMessage": True,
    "sqs:ReceiveMessage": True,
    "sqs:DeleteMessage": True,
    "sqs:ListQueues": False,
    # SNS
    "sns:Publish": True,
    "sns:ListTopics": False,
    # KMS
    "kms:Decrypt": True,
    "kms:Encrypt": True,
    "kms:ListKeys": False,
    # Secrets Manager
    "secretsmanager:GetSecretValue": True,
    "secretsmanager:ListSecrets": False,
    # SSM Parameter Store
    "ssm:GetParameter": True,
    "ssm:PutParameter": True,
    "ssm:DescribeParameters": False,
    # EC2 (sample subset)
    "ec2:StartInstances": True,
    "ec2:StopInstances": True,
    "ec2:DescribeInstances": False,
}


@dataclass(slots=True)
class ResourceLevelIndex:
    """Lookup table indicating whether actions allow resource-level scoping."""

    supports_resource_level: Dict[str, bool] = field(default_factory=lambda: dict(_DEFAULT_SUPPORT))

    def allows_scoping(self, action: str) -> bool:
        """Return True if the action supports resource-level permissions."""
        return self.supports_resource_level.get(action, False)

    def register(self, action: str, scoped: bool) -> None:
        """Override resource-level support information for custom actions."""
        self.supports_resource_level[action] = scoped


__all__ = ["ResourceLevelIndex"]
