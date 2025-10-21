# Demo Walkthrough

This guide shows how to exercise IAM Least-Privilege Generator end-to-end using a test AWS account. Replace placeholder values (account IDs, bucket names, regions) with your environment.

## 1. Generate CloudTrail Activity

Use the snippet below from CloudShell or an IAM role with the necessary permissions. It triggers `s3:ListBucket`, `GetObject`, `PutObject`, `dynamodb:PutItem`, and `kms:Encrypt` so CloudTrail captures both read and write patterns.

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=us-east-1
BUCKET=iamlp-demo-logs-$ACCOUNT_ID
TABLE=IamLpDemoOrders
date_suffix=$(date +%s)

aws s3api create-bucket --bucket $BUCKET --region $REGION --create-bucket-configuration LocationConstraint=$REGION || true
aws dynamodb create-table \
  --table-name $TABLE \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST || true

aws s3api put-object --bucket $BUCKET --key demo/object.txt --body /etc/hosts
aws s3 ls s3://$BUCKET/demo/
aws s3 cp /etc/hosts s3://$BUCKET/demo/upload-$date_suffix.txt
aws dynamodb put-item --table-name $TABLE --item '{"pk":{"S":"order-$date_suffix"}}'

KEY_ID=$(aws kms create-key --description "IAMLP Demo" --query KeyMetadata.KeyId --output text)
aws kms encrypt --key-id $KEY_ID --plaintext fileb:///etc/hosts --query CiphertextBlob --output text >/dev/null
```

Ensure CloudTrail is configured to deliver management events to an S3 bucket, e.g. `arn:aws:s3:::my-trail-logs`.

## 2. Normalize and Aggregate CloudTrail

```bash
TRAIL_BUCKET=my-trail-logs
PREFIX=AWSLogs/$ACCOUNT_ID/CloudTrail/$REGION/
START=2024-01-01T00:00:00Z
END=2024-01-01T23:59:59Z

python -m iamlp.cli parse \
  --s3-bucket $TRAIL_BUCKET \
  --prefix "$PREFIX" \
  --start $START \
  --end $END \
  --format json \
  --output artifacts/parsed.jsonl

python -m iamlp.cli aggregate \
  --events artifacts/parsed.jsonl \
  --min-count 1 \
  --format json \
  --output artifacts/aggregate.json

python -m iamlp.cli infer \
  --events artifacts/parsed.jsonl \
  --format json \
  --output artifacts/inferred.json

python -m iamlp.cli generate \
  --from-agg artifacts/aggregate.json \
  --mode actions \
  --format json \
  --output artifacts/policy_v1.json
```

## 3. Compare Policies via Simulation

Assume `original.json` is the pre-existing broad policy. Run the simulator to quantify scope reductions.

```bash
python -m iamlp.cli simulate \
  --before original.json \
  --after artifacts/policy_v1.json \
  --cases artifacts/parsed.jsonl \
  --format md \
  --output artifacts/diff.md
```

Review `diff.md` for changes in allowed actions, resource scope, and AccessDenied outcomes. Exit code `3` indicates Deny increases beyond thresholds.

## 4. Re-Test Workflows

Attach `policy_v1.json` to the target principal and rerun the command bundle from step 1. Confirm read-only and put operations succeed while any intentionally excluded actions fail with `AccessDenied`, validating least-privilege.

## 5. Refine with Resource Mode

Generate a more granular policy based on inferred resources.

```bash
python -m iamlp.cli generate \
  --from-agg artifacts/aggregate.json \
  --mode resources \
  --format json \
  --output artifacts/policy_v2.json
```

Run `simulate` again comparing `policy_v1.json` versus `policy_v2.json` to ensure the reduced resource scope still satisfies the workload and does not introduce new denials.

## Definition of Done Checklist

- CI executes `pytest` with ≥ 90% pass rate and overall coverage ≥ 80% before stakeholders sign off.
- ARN inference unit tests for S3, DynamoDB, Lambda, KMS, Secrets Manager, and SSM pass when running `generate --mode resources`.
- `diff.md` reports include allowed-action delta, resource concreteness ratio, AccessDenied change, and high-risk permission reduction metrics.
- GitHub Actions workflow finishes green and release tag `v0.1.0` is pushed.

## Deployment Recap

- Package & deploy via SAM: `sam build && sam deploy --guided --stack-name iamlp`
- Remove the stack when finished: `sam delete --stack-name iamlp`
