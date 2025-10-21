"""Inference helpers for deriving resource ARNs from CloudTrail events."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Dict, Iterable, List, Set

from core.models import EventModel

ArnSet = Set[str]
Extractor = Callable[[EventModel], ArnSet]

if TYPE_CHECKING:  # pragma: no cover
    from core.models import ActionRecord


def _default_fallback(_event: EventModel) -> ArnSet:
    return {"*"}


@dataclass(slots=True)
class ArnRuleRegistry:
    """Registry of ARN inference functions keyed by AWS service."""

    service_rules: Dict[str, list[Extractor]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.service_rules:
            self._register_defaults()

    def infer(self, event: EventModel) -> ArnSet:
        extractors = self.service_rules.get(event.aws_service, [])
        if not extractors:
            return _default_fallback(event)

        candidates: ArnSet = set()
        for extractor in extractors:
            inferred = extractor(event)
            if not inferred:
                continue
            candidates.update(inferred)

        return candidates or {"*"}

    def register(self, service: str, extractor: Extractor) -> None:
        self.service_rules.setdefault(service, []).append(extractor)

    def infer_from_record(self, record: "ActionRecord") -> Set[str]:
        if record.resources:
            return set(record.resources)
        # Fallback to wildcard when no resource detail is known.
        return set()

    # ------------------------------------------------------------------
    def _register_defaults(self) -> None:
        self.register("s3", infer_s3_arn)
        self.register("dynamodb", infer_dynamodb_arn)
        self.register("lambda", infer_lambda_arn)
        self.register("sqs", infer_sqs_arn)
        self.register("sns", infer_sns_arn)
        self.register("kms", infer_kms_arn)
        self.register("secretsmanager", infer_secretsmanager_arn)
        self.register("ssm", infer_ssmparam_arn)
        self.register("ec2", infer_ec2_arn)


# ---------------------------------------------------------------------------
# Service-specific inference helpers


def infer_s3_arn(event: EventModel) -> ArnSet:
    bucket = event.request_parameters.get("bucketName") or event.request_parameters.get("Bucket")
    key = event.request_parameters.get("key") or event.request_parameters.get("Key")
    arns: ArnSet = set()
    if bucket:
        if key:
            arns.add(f"arn:aws:s3:::{bucket}/{key}")
        arns.add(f"arn:aws:s3:::{bucket}")
    arns |= set(event.resource_arns)
    return arns or {"*"}


def infer_dynamodb_arn(event: EventModel) -> ArnSet:
    table = event.request_parameters.get("tableName") or event.request_parameters.get("TableName")
    if table:
        return {
            f"arn:aws:dynamodb:{event.region}:{event.account_id}:table/{table}",
        }
    return set(event.resource_arns) or {"*"}


def infer_lambda_arn(event: EventModel) -> ArnSet:
    function = (
        event.request_parameters.get("functionName")
        or event.request_parameters.get("FunctionName")
        or event.request_parameters.get("Function")
    )
    if function:
        return {
            f"arn:aws:lambda:{event.region}:{event.account_id}:function:{function}",
        }
    return set(event.resource_arns) or {"*"}


def infer_sqs_arn(event: EventModel) -> ArnSet:
    queue_url = event.request_parameters.get("queueUrl") or event.request_parameters.get("QueueUrl")
    queue_name = event.request_parameters.get("queueName") or event.request_parameters.get("QueueName")
    arns: ArnSet = set(event.resource_arns)
    if queue_url and not queue_name:
        queue_name = queue_url.rstrip("/").split("/")[-1]
    if queue_name:
        arns.add(f"arn:aws:sqs:{event.region}:{event.account_id}:{queue_name}")
    return arns or {"*"}


def infer_sns_arn(event: EventModel) -> ArnSet:
    topic_arn = (
        event.request_parameters.get("topicArn")
        or event.request_parameters.get("TopicArn")
        or event.request_parameters.get("TopicARN")
    )
    topic_name = event.request_parameters.get("topicName") or event.request_parameters.get("TopicName")
    arns: ArnSet = set(event.resource_arns)
    if topic_arn:
        arns.add(str(topic_arn))
    elif topic_name:
        arns.add(f"arn:aws:sns:{event.region}:{event.account_id}:{topic_name}")
    return arns or {"*"}


def infer_kms_arn(event: EventModel) -> ArnSet:
    key_arn = event.request_parameters.get("keyArn") or event.request_parameters.get("KeyId")
    key_id = event.request_parameters.get("keyId")
    arns: ArnSet = set(event.resource_arns)
    if key_arn:
        arns.add(str(key_arn))
    elif key_id:
        arns.add(f"arn:aws:kms:{event.region}:{event.account_id}:key/{key_id}")
    return arns or {"*"}


def infer_secretsmanager_arn(event: EventModel) -> ArnSet:
    secret_id = event.request_parameters.get("secretId") or event.request_parameters.get("SecretId")
    arns: ArnSet = set(event.resource_arns)
    if secret_id:
        if secret_id.startswith("arn:aws:secretsmanager"):
            arns.add(secret_id)
        else:
            arns.add(f"arn:aws:secretsmanager:{event.region}:{event.account_id}:secret:{secret_id}*")
    return arns or {"*"}


def infer_ssmparam_arn(event: EventModel) -> ArnSet:
    name = event.request_parameters.get("name") or event.request_parameters.get("Name")
    arns: ArnSet = set(event.resource_arns)
    if name:
        arns.add(f"arn:aws:ssm:{event.region}:{event.account_id}:parameter/{name}")
    return arns or {"*"}


def infer_ec2_arn(event: EventModel) -> ArnSet:
    resource_id = (
        event.request_parameters.get("instanceId")
        or event.request_parameters.get("InstanceId")
        or event.request_parameters.get("resourceId")
        or event.request_parameters.get("ResourceId")
    )
    arns: ArnSet = set(event.resource_arns)
    if resource_id:
        res_type = "instance"
        if resource_id.startswith("vol-"):
            res_type = "volume"
        elif resource_id.startswith("snap-"):
            res_type = "snapshot"
        arns.add(f"arn:aws:ec2:{event.region}:{event.account_id}:{res_type}/{resource_id}")
    return arns or {"*"}


__all__ = [
    "ArnRuleRegistry",
    "infer_s3_arn",
    "infer_dynamodb_arn",
    "infer_lambda_arn",
    "infer_sqs_arn",
    "infer_sns_arn",
    "infer_kms_arn",
    "infer_secretsmanager_arn",
    "infer_ssmparam_arn",
    "infer_ec2_arn",
]
