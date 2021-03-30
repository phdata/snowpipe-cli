# Snowpipe CLI

Snowpipe CLI provides access to
the [Snowpipe REST API](https://docs.snowflake.com/en/user-guide/data-load-snowpipe-rest-apis.html) via the CLI.
Currently, only the load history report endpoints are available. The script does not use
the [snowflake-ingest](https://pypi.org/project/snowflake-ingest/)
package provided by Snowflake, although it probably should, especially if the `insertFiles` endpoint is added to the CLI
script.

The `snowflake-ingest` package does bring many additional dependencies, but it has more robust error handling and retry.
Furthermore, since it is maintained by Snowflake, it should be less likely to break due to changes in the REST APIs.

The script also provides a JWT generator that can be used without calling specific endpoints in the event that you
simply need a JWT for some other adhoc use.


## Requirements

The script requires Python3.6+, but has only been tested on Python 3.9.

Install the prerequisites:

```shell
pip install -r requirements.txt
```

Create a config file with the Snowflake credentials and account information. See
the [example config](example-config.yaml) for details. 

The `account` value must not include the region and cloud if
present in the Snowflake URL. The `url_prefix` must include the any portion of the subdomains prior
to `snowflakecomputing.com`. For example, if your URL is https://tacos.us-east-2.azure.snowflakecomputing.com, then
the `account` will be `tacos` and the `url_prefix` will be `tacos.us-east-2.azure`.


## Usage

Show the script help, including all the subcommands:

```shell
./snowpipe.py -h
```

Show subcommand help:

```shell
./snowpipe.py <subcommand> -h
```

Run a subcommand:

```shell
./snowpipe.py <config_file> <subcommand>
```

Enable debug logging:

```shell
./snowpipe.py -d <config_file> <subcommand>
```
