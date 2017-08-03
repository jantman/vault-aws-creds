# vault-aws-creds

Python helper to export Vault-provided temporary AWS creds into the environment.

## Requirements

Python 2.7+ or Python 3. No external dependencies.

## Installation

1. Place ``vault-aws-creds.py`` somewhere on your system and make it executable.
2. Run ``vault-aws-creds.py --wrapper-func`` and put the output of that
  in your ``~/.bashrc``. The wrapper function allows using this Python script to
  set environment variables in the _existing_ shell process.
3. ``export VAULT_ADDR=<address to your Vault instance>``; it's recommended to
  put that in your ``~/.bashrc`` as well.

## Usage

### List available accounts

```bash
$ vault-aws-creds
Available Accounts:
"aws_dev" a.k.a. "dev"
"aws_prod" a.k.a. "prod"
"aws_uat" a.k.a. "uat"
```

### List available roles for account "dev"

```bash
$ vault-aws-creds --roles dev
Available Vault Roles for Account 'aws_dev/':
administrator
dba
deploy
developer
readonly
```

### Get STS credentials for the "foo" role in the "dev" account

```bash
$ vault-aws-creds dev foo
WARNING: STS credentials cannot call any IAM APIs or any STS APIs other than AssumeRole or GetCallerIdentity. If you need to call IAM APIs or other STS APIs, please generate new credentials with the --iam option.
Got credentials for account 'aws_dev/' role 'foo'
Request ID (for troubleshooting): c0e952d4-61ea-72e8-7b56-2df50538eacf
Lease (credentials) will expire in: 59m 59s
Outputting the following for shell evaluation:
        export AWS_REGION='us-east-1'
        export AWS_DEFAULT_REGION='us-east-1'
        export AWS_ACCESS_KEY_ID='ASIAxxxxxxxxxxxxxxxx'
        export AWS_SECRET_ACCESS_KEY='8xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxE'
        export AWS_SESSION_TOKEN='F...F'
```

"foo" will now be stored in ~/.vault-aws-creds.conf as the default role for the
"dev" ("aws_dev/") account. To get new creds for the same role, you can omit
the role name:

```bash
$ vault-aws-creds dev
WARNING: STS credentials cannot call any IAM APIs or any STS APIs other than AssumeRole or GetCallerIdentity. If you need to call IAM APIs or other STS APIs, please generate new credentials with the --iam option.
Got credentials for account 'aws_dev/' role 'foo'
Request ID (for troubleshooting): b02d0346-cce2-911f-d853-17cf8aa591a2
Lease (credentials) will expire in: 59m 59s
Outputting the following for shell evaluation:
        export AWS_REGION='us-east-1'
        export AWS_DEFAULT_REGION='us-east-1'
        export AWS_ACCESS_KEY_ID='ASIAzzzzzzzzzzzzzzzz'
        export AWS_SECRET_ACCESS_KEY='8zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzE'
        export AWS_SESSION_TOKEN='F...F'
```

### Get IAM User credentials for the "foo" role in the "dev" account

```bash
$ vault-aws-creds --iam dev foo
Got credentials for account 'aws_dev/' role 'foo'
Request ID (for troubleshooting): e123a94c-4819-f75d-22b1-d754ec92f589
Lease (credentials) will expire in: 1h
To renew, run: vault renew aws_dev/creds/foo/54078039-7b6c-be74-5fde-0adb3b209317
Outputting the following for shell evaluation:
        export AWS_REGION='us-east-1'
        export AWS_DEFAULT_REGION='us-east-1'
        export AWS_ACCESS_KEY_ID='AKIAxxxxxxxxxxxxxxxx'
        export AWS_SECRET_ACCESS_KEY='AzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzB'
        unset AWS_SESSION_TOKEN
```

## Suggested Vault Policies

In addition to the required policies to retrieve the credentials you need,
listing available accounts and roles requires the following policy:

```
# allows user to list mounts, to find all AWS secret backends
path "sys/mounts" {
    capabilities = ["read"]
}

# allows user to list available roles for AWS secret backends
# this assumes that all AWS backend mountpoints begin with "aws_"
path "aws_*/roles" {
    capabilities = ["list"]
}
```
