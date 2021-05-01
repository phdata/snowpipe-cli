# Snowpipe CLI

Snowpipe CLI provides access to
the [Snowpipe REST API](https://docs.snowflake.com/en/user-guide/data-load-snowpipe-rest-apis.html) via the CLI. The
script uses the [snowflake-ingest](https://github.com/snowflakedb/snowflake-ingest-python) python package to call the
REST endpoints.

There is also a JWT generator that you can use to simply generate a JWT for adhoc use.

## Requirements

The script requires Python3.6+, but has only been tested on Python 3.9.

Install the prerequisites:

```shell
pip install -r requirements.txt
```

Create a config file with the Snowflake credentials and account information. 

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

## Usage

Show the script help, including the subcommands:

```shell
./snowpipe.py -h
```

Show subcommand help:

```shell
./snowpipe.py <subcommand> -h
```

Run a subcommand:

```shell
./snowpipe.py <subcommand> <config_file> <other_args>...
```

Enable debug logging:

```shell
./snowpipe.py -d <subcommand> <config_file>
```
