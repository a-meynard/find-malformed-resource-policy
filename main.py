import boto3
import re
import json
import logging


LOG_LEVEL = logging.WARN
ENABLE_BOTOCORE_LOGGING = False

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

if ENABLE_BOTOCORE_LOGGING:
    botocore_logs = logging.getLogger("botocore")
    botocore_logs.setLevel(LOG_LEVEL)


def is_arn(candidate: str):
    return candidate.startswith("arn:") and candidate.count(":") >= 5


def is_valid_policy_aws_principal(principal: str):
    if principal == "*":
        return True
    if re.match(r"^\d{12}$", principal) is not None:
        return True
    return is_arn(principal)


def policy_has_valid_principals(policy: str):
    principals = [
        statement["Principal"]["AWS"] for statement in json.loads(policy)["Statement"]
    ]
    for principal in principals:
        match principal:
            case list(principal):
                logger.info(f"Got following list of principals {principal}")
                for p in principal:
                    if not is_valid_policy_aws_principal(p):
                        logger.info(f"principal {p} was not valid")
                        return False
            case str(principal):
                logger.info(f"Got following principal {principal}")
                if not is_valid_policy_aws_principal(principal):
                    logger.info(f"principal {principal} was not valid")
                    return False
    return True


def get_secret_policy(client, secret_name: str):
    response = client.get_resource_policy(SecretId=secret_name)
    logger.debug(f"get_resource_policy response: {response}")
    try:
        return response["ResourcePolicy"]
    except KeyError:
        logger.info(f"secret {secret_name} do not have ResourcePolicy configured")
        return '{"Version":"2012-10-17", "Statement": []}'


def list_secrets(client):
    paginator = client.get_paginator("list_secrets")
    for page in paginator.paginate(PaginationConfig={}):
        for secret in page["SecretList"]:
            yield secret


def main():
    client = boto3.client("secretsmanager")
    for secret in list_secrets(client):
        policy = get_secret_policy(client, secret["Name"])
        if not policy_has_valid_principals(policy):
            print(f"{secret['Name']} has invalid resource policy")


if __name__ == "__main__":
    main()
