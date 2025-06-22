import boto3
from google.cloud import secretmanager
from google.api_core.exceptions import AlreadyExists
import google_crc32c  # type: ignore
import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

ch.setFormatter(formatter)
logger.addHandler(ch)


project_id = "XXXXX"


ssm_client = boto3.client("ssm")
secret_manager_client = secretmanager.SecretManagerServiceClient()
GCP_PROJECT = f"projects/{project_id}"


def get_ssm_parameters() -> list[str]:
    """Get the parameters from the parameter store"""
    parameters = []

    paginator = ssm_client.get_paginator('describe_parameters')
    for response in paginator.paginate():
        parameters.extend(response['Parameters'])
    return parameters


def get_ssm_parameters_value(parameter_names: list[str]) -> dict:
    """Get the value of the parameters from the parameter store"""
    response = ssm_client.get_parameters(Names=parameter_names, WithDecryption=True)
    return response["Parameters"]


def get_aws_parameters():
    """Get the parameters from the parameter store and return them as a dictionary"""
    aws_parameters = {}
    logger.info("Getting parameters from AWS SSM")
    parameters = get_ssm_parameters()
    logger.info(f"Got {len(parameters)} parameters from AWS SSM")
    logger.info("Getting values of parameters from AWS SSM")
    for i in range(0, len(parameters), 5):
        temp_parameters = parameters[i : i + 5]
        parameter_names = [parameter["Name"] for parameter in temp_parameters]
        parameters_value = get_ssm_parameters_value(parameter_names)
        for parameter in parameters_value:
            split_values = parameter["Name"].split("/")
            if len(split_values) > 1:
                name = "_".join(split_values[1:])
            else:
                name = split_values[0]
            aws_parameters[name] = parameter["Value"]
    logger.info(f"Got values of {len(aws_parameters)} parameters from AWS SSM")
    return aws_parameters


def update_secret_version(secret_name: str, secret_value: str) -> None:
    """Update the secret version with the given value"""
    parent = secret_manager_client.secret_path(project_id, secret_name)

    payload_bytes = secret_value.encode("UTF-8")

    crc32c = google_crc32c.Checksum()
    crc32c.update(payload_bytes)

    response = secret_manager_client.add_secret_version(
        request={
            "parent": parent,
            "payload": {
                "data": payload_bytes,
                "data_crc32c": int(crc32c.hexdigest(), 16),
            },
        }
    )

    # Print the new secret version name.
    logger.info(f"Added secret version: {response.name}")


def create_secret(secret_name: str, secret_value: str) -> None:
    """Create a secret in the gcp secret manager with the given name and value"""
    logger.info(f"Creating secret for {secret_name}")
    secret_exists = False
    try:
        secret = secret_manager_client.create_secret(
            request={
                "parent": GCP_PROJECT,
                "secret_id": secret_name,
                "secret": {"replication": {"automatic": {}}},
            }
        )
    except AlreadyExists as e:
        logger.info(f"secret {secret_name} already exists")
        secret_exists = True
    except Exception as e:
        logger.error(f"Error creating secret due to {e=}")
        return

    try:
        if (
            not secret_exists
        ):  # If secret already exists, we need to update the secret version
            secret_manager_client.add_secret_version(
                request={
                    "parent": secret.name,
                    "payload": {"data": secret_value.encode("UTF-8")},
                }
            )
            logger.info(f"Secret version created successfully for {secret_name}")
        else:
            logger.info(f"Updating secret version for {secret_name}")
            update_secret_version(secret_name, secret_value)
    except Exception as e:
        logger.error(f"Error creating secret version due to {e=}")


if __name__ == "__main__":
    aws_parameters = get_aws_parameters()

    for name, value in aws_parameters.items():
        create_secret(name, value)
