# vault-aws-creds

[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](http://www.repostatus.org/badges/latest/active.svg)](http://www.repostatus.org/#active)

Python helper to export Vault-provided temporary AWS credentials into the environment.
Also includes a helper script to generate a Console login URL from STS temporary credentials (from Vault).

## Requirements

Python 2.7+ or Python 3. No external dependencies.

## Installation

1. Place (or symlink) ``vault-aws-creds.py`` somewhere on your system and make it executable.
2. ``export VAULT_ADDR=<address to your Vault instance>``; it's recommended to
  put that in your ``~/.bashrc`` as well.
3. Add ``eval $(vault-aws-creds.py -w)`` to your shell initialization file (i.e. ``~/.bashrc``).
  If vault-aws-creds.py is not on your PATH, specify the absolute path to it in the
  above snippet. This will setup a function that allows vault-aws-creds.py to export environment
  variables back into your _existing_ shell process.
4. *(optional)* If you wish to use the Console login URL generator, place
  (or symlink) ``aws-sts-console-url.py`` somewhere on your system and make it
  executable.

## Usage

### List available accounts

```bash
$ vault-aws-creds
Available Accounts:
"aws_dev" a.k.a. "dev"
"aws_prod" a.k.a. "prod"
"aws_uat" a.k.a. "uat"
```

__Note:__ This requires that your token have "read" access to ``sys/mounts``.

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

__Note:__ This requires that your token have "list" access to ``roles`` under the specified mountpoint (i.e. ``aws_dev/roles`` in the above example).

### Get STS credentials for the "foo" role in the "dev" account

```bash
$ vault-aws-creds dev foo
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

### Get 4-hour-lifetime STS credentials for the "bar" role in the "prod" account

(Note: this requires that your user in Vault have "update" capabilities for the sts path. Users of older Vault installations may only have "read".)

```bash
$ vault-aws-creds --ttl=4h prod bar
Got credentials for account 'aws_dev/' role 'foo'
Request ID (for troubleshooting): b02d0346-cce2-911f-d853-17cf8aa591a2
Lease (credentials) will expire in: 3h 59m 59s
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

## aws-sts-console-url.py Usage

``aws-sts-console-url.py`` is a script that uses STS temporary credentials
from Vault to generate a pre-signed AWS Console login URL, allowing Console
access with temporary credentials from Vault. **This can only be used with STS
temporary credentials, i.e. not ``--iam`` credentials from ``vault-aws-creds``.**

To use, first obtain STS temporary credentials with ``vault-aws-creds`` as shown
above. Then, run ``aws-sts-console-url.py``; a Console login URL will be displayed
to STDOUT.  Alternatively, you can pass in the `-b` or `--browser` flag which
will open the console automatically in your default browser
`aws-sts-console-url.py --browser`.

### GovCloud and Other Partitions

By default, ``aws-sts-console-url.py`` uses the signin.aws.amazon.com endpoint for Console access and federation tokens. This can be overridden by setting the ``AWS_SIGNIN_HOST`` environment varibale, i.e. to something like ``signin.amazonaws-us-gov.com`` or ``us-gov-east-1.signin.amazonaws-us-gov.com`` for GovCloud or ``signin.amazonaws.cn`` for the China partition.

## Suggested Vault Policies

In addition to the required policies to retrieve the credentials you need,
listing available accounts and roles requires the following policy on your token:

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

## Similar Projects

I have nothing to do with the following projects, and haven't used them, but are listing them here for anyone who may be interested:

* https://github.com/FairwindsOps/vaultutil - A similar utility written in Go.
