"""AWS CDK app stub replicating the SAM stack."""

from __future__ import annotations

from aws_cdk import App, Environment, Stack


class IamLeastPrivilegeStack(Stack):
    def __init__(self, scope: App, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # TODO: Add resources mirroring infra/sam-app/template.yaml


def build_app() -> App:
    app = App()
    IamLeastPrivilegeStack(app, "IamLeastPrivilegeStack", env=Environment(account="123456789012", region="us-east-1"))
    return app


def main() -> None:
    app = build_app()
    app.synth()


if __name__ == "__main__":
    main()
