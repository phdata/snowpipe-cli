# Snowpipe CLI

Snowpipe CLI provides access to
the [Snowpipe REST API](https://docs.snowflake.com/en/user-guide/data-load-snowpipe-rest-apis.html) via the CLI. The
script uses the [snowflake-ingest](https://github.com/snowflakedb/snowflake-ingest-python) python package to call the
REST endpoints.

In addition to calling the Snowpipe REST endpoints, you can use Snowpipe CLI
to [PUT](https://docs.snowflake.com/en/sql-reference/sql/put.html) local files in the stage used by the pipe and then
ingest. A single invocation of the ingest command handles any combination of already staged files and local files that
need to be staged.

There is also a JWT generator that you can use to simply generate a JWT for adhoc use.

## Installation

You can install the latest version with pip

```shell
pip install snowpipe-cli
```

**Note**: If you are installing into a virtual environment, you may need to deactivate and activate again in order for
the `snowpipe` command to work correctly from your shell.

### Requirements

Snowpipe CLI requires Python 3.8+.

### Configuration

Create a config file with the Snowflake credentials and account information. The config file must be YAML like below:

```yaml
url: phdata.snowflakecomputing.com
account: PHDATA
user: USER
key_fp: SHA256:something_from_snowflake_user
key_file: /path/to/user/private/key.pem
key_password: optional_password
```

See also [example config](example-config.yaml).

The `account` value must not include the region and cloud if present in the Snowflake URL. The `url` is the URL of the
Snowflake instance minus the scheme. For example, if your URL is https://tacos.us-east-2.azure.snowflakecomputing.com,
then the `account` will be `tacos` and the `url` will be `tacos.us-east-2.azure.snowflakecomputing.com`.

To generate a private key,
see [Key Pair Authentication & Key Pair Rotation](https://docs.snowflake.com/en/user-guide/key-pair-auth.html). When
verifying the fingerprint, record the value into the `key_fp` YAML key.

## Usage

The commands below are examples of calling the `snowpipe` script from your shell after it has been installed with pip.
If you have cloned the repository, you can also invoke the script from its parent directory with `./snowpipe.py`, or you
can run from the `src` directory with `python -m snowpipe_cli`.

Show the script help, including the subcommands:

```shell
snowpipe -h
```

Show subcommand help:

```shell
snowpipe <subcommand> -h
```

Run a subcommand:

```shell
snowpipe <subcommand> <config_file> <other_args>...
```

Enable debug logging:

```shell
snowpipe -d <subcommand> <config_file>
```

## Contributing

Install the prerequisites:

```shell
pip install -r requirements.txt
```

Build the package in the `dist` directory

```shell

python3 -m build
```

Upload to pypi

```shell
twine upload --repository pypi dist/*
```



