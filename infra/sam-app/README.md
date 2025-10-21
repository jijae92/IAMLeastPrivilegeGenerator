# AWS SAM Stack

1. Install dependencies: `pip install aws-sam-cli`.
2. Build the project: `sam build --use-container`.
3. Deploy to your AWS account: `sam deploy --guided`.
4. After deployment, upload CloudTrail logs to the generated S3 bucket to trigger the analyzer.

Use the outputs to configure the API endpoint consumed by the Web UI and CLI.
