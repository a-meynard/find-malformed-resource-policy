# find-malformed-resource-policy

Find malformed resource policy in AWS SecretsManager

## Install

```bash
python3 -m venv venv
. venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Usage

Please [configure an AWS Profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html) to use this tool.

```bash
export AWS_PROFILE=<your_aws_profile>
python3 main.py
```

It will output a list of the secret that have a malformed resource policy
