#!/usr/bin/env python3
"""
setup_infra.py — AI SDK Proxy infrastructure bootstrap

Creates:
  - Cognito User Pool + App Client (for human users / CLI login)
  - Cognito User Pool + Resource Server (for machine-to-machine tokens)
  - SNS topic for audit events
  - SNS topic policy allowing the Cognito-authenticated IAM role to publish

Usage:
    python3 scripts/setup_infra.py --env dev --region us-east-1
    python3 scripts/setup_infra.py --env prod --region us-east-1 --profile my-aws-profile

Outputs a .env file and prints next steps.
"""

import argparse
import io
import json
import sys
import time
import zipfile
import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Cognito
# ---------------------------------------------------------------------------

def create_user_pool(cognito, env: str) -> dict:
    """Create a Cognito User Pool with sensible defaults."""
    pool_name = f"ai-sdk-proxy-{env}"
    print(f"Creating Cognito User Pool: {pool_name} ...")

    response = cognito.create_user_pool(
        PoolName=pool_name,
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 12,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        AutoVerifiedAttributes=["email"],
        UsernameAttributes=["email"],
        Schema=[
            {
                "Name": "email",
                "AttributeDataType": "String",
                "Required": True,
                "Mutable": True,
            }
        ],
        AdminCreateUserConfig={
            "AllowAdminCreateUserOnly": True,   # Admins add users; no self-signup
            "InviteMessageTemplate": {
                "EmailMessage": "Hello {username}, your AI SDK Proxy temporary password is {####}",
                "EmailSubject": "AI SDK Proxy - Your Temporary Password",
            },
        },
        UserPoolTags={t["Key"]: t["Value"] for t in _tags_with_env(env)},
    )
    pool = response["UserPool"]
    print(f"  User Pool ID : {pool['Id']}")
    return pool


def create_user_pool_group(cognito, pool_id: str) -> None:
    """Create a default 'ai-sdk-users' group. Admins add users to this later."""
    group_name = "ai-sdk-users"
    try:
        cognito.create_group(
            GroupName=group_name,
            UserPoolId=pool_id,
            Description="Users authorized to call AI SDK Proxy",
        )
        print(f"  Group created : {group_name}")
    except cognito.exceptions.GroupExistsException:
        print(f"  Group already exists : {group_name} (skipped)")


def create_app_client(cognito, pool_id: str, env: str) -> dict:
    """
    Create an App Client for human (interactive) login.
    Uses USER_PASSWORD_AUTH + REFRESH_TOKEN_AUTH.
    No client secret — suitable for CLI / desktop apps.
    """
    client_name = f"ai-sdk-proxy-cli-{env}"
    print(f"  Creating App Client: {client_name} ...")

    response = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=client_name,
        GenerateSecret=False,           # Public client — no secret needed for CLI
        ExplicitAuthFlows=[
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_SRP_AUTH",
        ],
        AccessTokenValidity=60,         # minutes
        IdTokenValidity=60,             # minutes
        RefreshTokenValidity=30,        # days
        TokenValidityUnits={
            "AccessToken": "minutes",
            "IdToken": "minutes",
            "RefreshToken": "days",
        },
        PreventUserExistenceErrors="ENABLED",
    )
    client = response["UserPoolClient"]
    print(f"  App Client ID : {client['ClientId']}")
    return client


def create_m2m_client(cognito, pool_id: str, env: str) -> dict:
    """
    Create an App Client for machine-to-machine (service) auth.
    Uses CLIENT_CREDENTIALS flow with a client secret.
    """
    client_name = f"ai-sdk-proxy-service-{env}"
    print(f"  Creating M2M App Client: {client_name} ...")

    # Resource server must exist before we can define custom scopes
    resource_server_id = f"https://ai-sdk-proxy-{env}"
    try:
        cognito.create_resource_server(
            UserPoolId=pool_id,
            Identifier=resource_server_id,
            Name=f"AI SDK Proxy {env}",
            Scopes=[
                {
                    "ScopeName": "invoke",
                    "ScopeDescription": "Permission to invoke LLM via AI SDK Proxy",
                }
            ],
        )
        print(f"  Resource Server : {resource_server_id}")
    except cognito.exceptions.InvalidParameterException as e:
        if "already exists" in str(e):
            print(f"  Resource Server already exists (skipped)")
        else:
            raise

    response = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=client_name,
        GenerateSecret=True,            # M2M clients use a secret
        ExplicitAuthFlows=[],           # not used for client_credentials
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthScopes=[f"{resource_server_id}/invoke"],
        AllowedOAuthFlowsUserPoolClient=True,
        SupportedIdentityProviders=["COGNITO"],
    )
    client = response["UserPoolClient"]
    print(f"  M2M Client ID     : {client['ClientId']}")
    print(f"  M2M Client Secret : {client['ClientSecret']}")
    return client


def get_pool_domain(cognito, pool_id: str, env: str) -> str:
    """
    Add a Cognito hosted domain (required for client_credentials OAuth flow).
    Domain prefix must be globally unique — uses pool_id suffix to help.
    """
    domain_prefix = f"ai-sdk-proxy-{env}-{pool_id.split('_')[1].lower()}"
    try:
        cognito.create_user_pool_domain(
            Domain=domain_prefix,
            UserPoolId=pool_id,
        )
        print(f"  Cognito Domain : {domain_prefix}.auth.<region>.amazoncognito.com")
    except cognito.exceptions.InvalidParameterException as e:
        if "already exists" in str(e):
            print(f"  Cognito Domain already exists (skipped)")
        else:
            raise
    return domain_prefix


# ---------------------------------------------------------------------------
# SNS
# ---------------------------------------------------------------------------

def create_sns_topic(sns, env: str) -> str:
    """Create the SNS audit topic (or fetch existing) and return its ARN."""
    topic_name = f"ai-sdk-proxy-audit-{env}"
    print(f"\nCreating SNS topic: {topic_name} ...")

    try:
        response = sns.create_topic(
            Name=topic_name,
            Tags=_tags_with_env(env),
        )
        topic_arn = response["TopicArn"]
        print(f"  SNS Topic ARN : {topic_arn}")
    except sns.exceptions.InvalidParameterException as e:
        if "already exists" in str(e) or "different tags" in str(e):
            # Topic exists with stale tags — fetch ARN then overwrite tags
            topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
            sns.tag_resource(
                ResourceArn=topic_arn,
                Tags=_tags_with_env(env),
            )
            print(f"  SNS Topic already exists — tags updated : {topic_arn}")
        else:
            raise

    return topic_arn


def set_sns_topic_policy(sns, sts, topic_arn: str) -> None:
    """
    Set a resource policy on the SNS topic that allows:
      - The current AWS account to publish (covers Lambda, ECS tasks, EC2 with IAM roles)
      - Anyone in the account can subscribe (for downstream consumers like RDS writer Lambda)
    """
    account_id = sts.get_caller_identity()["Account"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAccountPublish",
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{account_id}:root"
                },
                "Action": [
                    "SNS:Publish",
                    "SNS:Subscribe",
                    "SNS:ListSubscriptionsByTopic",
                    "SNS:GetTopicAttributes",
                ],
                "Resource": topic_arn,
            }
        ],
    }

    sns.set_topic_attributes(
        TopicArn=topic_arn,
        AttributeName="Policy",
        AttributeValue=json.dumps(policy),
    )
    print(f"  SNS policy set for account {account_id}")


# ---------------------------------------------------------------------------
# IAM — Lambda execution role
# ---------------------------------------------------------------------------

TAGS = [
    {"Key": "ClientName",      "Value": "UBI Internal"},
    {"Key": "EmployeeEmail",   "Value": "aabhimanyu@usefulbi.com"},
    {"Key": "ManagedBy",       "Value": "terraform"},
    {"Key": "ProjectName",     "Value": "SAS to Kiro"},
    {"Key": "ProjectTechLead", "Value": "Abhimanyu Acharya"},
    {"Key": "Resource",        "Value": "s3Resource"},
    {"Key": "ResourceName",    "Value": "sbx-sas-platform"},
    {"Key": "TechnologyArea",  "Value": "Generative AI"},
]


def _tags_with_env(env: str) -> list:
    return TAGS + [{"Key": "Environment", "Value": env}]


def create_lambda_role(iam, sts, env: str) -> str:
    """
    Create an IAM execution role for the audit Lambda.
    Grants: CloudWatch Logs write, SNS read (for trigger).
    Returns the role ARN.
    """
    role_name = f"ai-sdk-proxy-audit-lambda-{env}"
    account_id = sts.get_caller_identity()["Account"]
    print(f"\n--- IAM ---")
    print(f"Creating Lambda execution role: {role_name} ...")

    assume_role_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    })

    try:
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=assume_role_policy,
            Description="Execution role for AI SDK Proxy audit Lambda",
            Tags=_tags_with_env(env),
        )
        role_arn = response["Role"]["Arn"]
    except iam.exceptions.EntityAlreadyExistsException:
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        print(f"  Role already exists — updating tags ...")
        iam.tag_role(
            RoleName=role_name,
            Tags=_tags_with_env(env),
        )

    # Attach AWS managed policy for basic Lambda logging
    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
        print(f"  Attached AWSLambdaBasicExecutionRole")
    except iam.exceptions.NoSuchEntityException:
        pass  # already detached or role not found

    print(f"  Role ARN : {role_arn}")

    # IAM role propagation takes a few seconds — Lambda create will fail without this
    print("  Waiting 10s for IAM role to propagate ...")
    time.sleep(10)

    return role_arn


# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------

def _zip_lambda(source_path: str) -> bytes:
    """Zip the Lambda handler file in-memory and return the bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(source_path, arcname="lambda_function.py")
    return buf.getvalue()


def create_audit_lambda(aws_lambda, role_arn: str, topic_arn: str, env: str, region: str) -> str:
    """
    Create the audit printer Lambda and return its ARN.
    The handler file is lambda_audit_printer.py in the same scripts/ directory.
    """
    import os
    function_name = f"ai-sdk-proxy-audit-printer-{env}"
    print(f"\n--- Lambda ---")
    print(f"Creating Lambda function: {function_name} ...")

    handler_path = os.path.join(os.path.dirname(__file__), "lambda_audit_printer.py")
    zip_bytes = _zip_lambda(handler_path)

    try:
        response = aws_lambda.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": zip_bytes},
            Description="Prints AI SDK Proxy audit events from SNS to CloudWatch Logs",
            Timeout=30,
            MemorySize=128,
            Environment={
                "Variables": {
                    "ENV": env,
                }
            },
            Tags={t["Key"]: t["Value"] for t in _tags_with_env(env)},
        )
        function_arn = response["FunctionArn"]
        print(f"  Function ARN : {function_arn}")
    except aws_lambda.exceptions.ResourceConflictException:
        # Already exists — fetch the ARN and update tags
        response = aws_lambda.get_function(FunctionName=function_name)
        function_arn = response["Configuration"]["FunctionArn"]
        aws_lambda.tag_resource(
            Resource=function_arn,
            Tags={t["Key"]: t["Value"] for t in _tags_with_env(env)},
        )
        print(f"  Function already exists — tags updated : {function_arn}")

    return function_arn


def subscribe_lambda_to_sns(sns, aws_lambda, topic_arn: str, function_arn: str, env: str) -> None:
    """
    Subscribe the Lambda to the SNS topic and grant SNS permission to invoke it.
    """
    print(f"Subscribing Lambda to SNS topic ...")

    # Grant SNS permission to invoke the Lambda
    try:
        aws_lambda.add_permission(
            FunctionName=function_arn,
            StatementId=f"sns-invoke-{env}",
            Action="lambda:InvokeFunction",
            Principal="sns.amazonaws.com",
            SourceArn=topic_arn,
        )
        print(f"  Lambda invoke permission granted to SNS")
    except aws_lambda.exceptions.ResourceConflictException:
        print(f"  Lambda invoke permission already exists (skipped)")

    # Subscribe Lambda to SNS
    response = sns.subscribe(
        TopicArn=topic_arn,
        Protocol="lambda",
        Endpoint=function_arn,
        ReturnSubscriptionArn=True,
    )
    print(f"  SNS Subscription ARN : {response['SubscriptionArn']}")


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_env_file(output: dict, env: str) -> str:
    """Write a .env file that can be sourced or loaded by the SDK."""
    path = f".env.{env}"
    lines = [
        f"# AI SDK Proxy — {env} environment",
        f"# Generated by setup_infra.py",
        "",
        f"AI_SDK_COGNITO_USER_POOL_ID={output['user_pool_id']}",
        f"AI_SDK_COGNITO_CLIENT_ID={output['app_client_id']}",
        f"AI_SDK_COGNITO_REGION={output['region']}",
        f"AI_SDK_COGNITO_DOMAIN={output['cognito_domain']}",
        "",
        f"AI_SDK_M2M_CLIENT_ID={output['m2m_client_id']}",
        f"AI_SDK_M2M_CLIENT_SECRET={output['m2m_client_secret']}",
        "",
        f"AI_SDK_AUDIT_TOPIC_ARN={output['sns_topic_arn']}",
        f"AI_SDK_AUDIT_LAMBDA_ARN={output['lambda_arn']}",
        f"AWS_DEFAULT_REGION={output['region']}",
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def print_next_steps(output: dict, env: str) -> None:
    print("\n" + "=" * 60)
    print("Setup complete. Next steps:")
    print("=" * 60)
    print()
    print("1. Add users to Cognito (console or CLI):")
    print(f"   aws cognito-idp admin-create-user \\")
    print(f"     --user-pool-id {output['user_pool_id']} \\")
    print(f"     --username user@example.com \\")
    print(f"     --temporary-password 'TempPass123!' \\")
    print(f"     --user-attributes Name=email,Value=user@example.com")
    print()
    print("2. Add user to the ai-sdk-users group:")
    print(f"   aws cognito-idp admin-add-user-to-group \\")
    print(f"     --user-pool-id {output['user_pool_id']} \\")
    print(f"     --username user@example.com \\")
    print(f"     --group-name ai-sdk-users")
    print()
    print("3. Test login (CLI / human user):")
    print(f"   aws cognito-idp initiate-auth \\")
    print(f"     --auth-flow USER_PASSWORD_AUTH \\")
    print(f"     --client-id {output['app_client_id']} \\")
    print(f"     --auth-parameters USERNAME=user@example.com,PASSWORD=YourPassword")
    print()
    print("4. Use the SDK:")
    print(f"   from ai_sdk_proxy import BedrockRuntimeClient")
    print(f"   client = BedrockRuntimeClient(")
    print(f"       jwt='<id_token from step 3>',")
    print(f"       sns_topic_arn='{output['sns_topic_arn']}',")
    print(f"   )")
    print()
    print(f"5. Environment variables saved to: .env.{env}")
    print(f"   source .env.{env}")
    print()
    print(f"6. Check audit Lambda logs after sending a request:")
    print(f"   aws logs tail /aws/lambda/ai-sdk-proxy-audit-printer-{env} --follow --region {output['region']}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(env: str, region: str, profile: str | None) -> int:
    session = boto3.Session(profile_name=profile, region_name=region)
    cognito     = session.client("cognito-idp")
    sns         = session.client("sns")
    sts         = session.client("sts")
    iam         = session.client("iam")
    aws_lambda  = session.client("lambda")

    try:
        # -- Cognito --------------------------------------------------------
        print("\n--- Cognito ---")
        pool = create_user_pool(cognito, env)
        pool_id = pool["Id"]

        create_user_pool_group(cognito, pool_id)
        app_client = create_app_client(cognito, pool_id, env)
        m2m_client = create_m2m_client(cognito, pool_id, env)
        cognito_domain = get_pool_domain(cognito, pool_id, env)

        # -- SNS ------------------------------------------------------------
        topic_arn = create_sns_topic(sns, env)
        set_sns_topic_policy(sns, sts, topic_arn)

        # -- IAM + Lambda ---------------------------------------------------
        role_arn     = create_lambda_role(iam, sts, env)
        function_arn = create_audit_lambda(aws_lambda, role_arn, topic_arn, env, region)
        subscribe_lambda_to_sns(sns, aws_lambda, topic_arn, function_arn, env)

        # -- Output ---------------------------------------------------------
        output = {
            "user_pool_id":      pool_id,
            "app_client_id":     app_client["ClientId"],
            "m2m_client_id":     m2m_client["ClientId"],
            "m2m_client_secret": m2m_client["ClientSecret"],
            "cognito_domain":    cognito_domain,
            "sns_topic_arn":     topic_arn,
            "lambda_arn":        function_arn,
            "region":            region,
        }
        write_env_file(output, env)
        print_next_steps(output, env)
        return 0

    except ClientError as e:
        print(f"\nAWS error: {e}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bootstrap Cognito + SNS infrastructure for AI SDK Proxy"
    )
    parser.add_argument(
        "--env",
        default="dev",
        help="Environment name used as a suffix (default: dev)",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS CLI profile name (default: uses current environment credentials)",
    )
    args = parser.parse_args()
    return run(env=args.env, region=args.region, profile=args.profile)


if __name__ == "__main__":
    sys.exit(main())
