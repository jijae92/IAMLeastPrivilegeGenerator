# AWS CDK Skeleton

This optional CDK stack mirrors the SAM template for teams preferring infrastructure-as-code in Python.

## Usage

1. Create a virtual environment and install CDK: `pip install aws-cdk-lib constructs`.
2. Bootstrap your environment: `cdk bootstrap`.
3. Synthesize the stack: `cdk synth`.
4. Deploy: `cdk deploy`.

Translate resources from `infra/sam-app/template.yaml` into constructs inside `app.py` as the project matures.
