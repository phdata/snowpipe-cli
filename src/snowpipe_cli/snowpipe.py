#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
import sys
import uuid
from contextlib import AbstractContextManager
from datetime import datetime, timedelta
from functools import cached_property
from types import TracebackType
from typing import Optional, Type, Iterable

import jwt
import snowflake.connector
import yaml
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from snowflake.connector import DictCursor, SnowflakeConnection
from snowflake.ingest import SimpleIngestManager, StagedFile

logging.basicConfig(level=logging.WARNING, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger()


class Config:
    EXPIRATION_SECONDS = 3600

    @staticmethod
    def create(config_file: str):
        with open(config_file) as infile:
            content = yaml.safe_load(infile)
            return Config(**content)

    def __init__(self, url: str, account: str, user: str, key_fp: str, key_file: str,
                 key_password: Optional[str] = None) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.url = url.lower()
        self.account = account.upper()
        self.user = user.upper()
        self.key_fp = key_fp
        self.key_file = key_file
        self.key_password = key_password

    def _read_private_key_file(self, key_encoding: Encoding) -> bytes:
        self.logger.debug(f'Reading private key file: {self.key_file}')
        with open(self.key_file) as infile:
            content = infile.read()
        pw_bytes = None
        if self.key_password:
            pw_bytes = self.key_password.encode('utf-8')
        private_key = serialization.load_pem_private_key(content.encode('utf-8'), password=pw_bytes,
                                                         backend=default_backend())
        return private_key.private_bytes(key_encoding, PrivateFormat.PKCS8, NoEncryption())

    @cached_property
    def private_key_der(self) -> bytes:
        return self._read_private_key_file(Encoding.DER)

    @cached_property
    def private_key_pem(self) -> str:
        return self._read_private_key_file(Encoding.PEM).decode('utf-8')

    def generate_jwt(self, seconds: Optional[int] = None) -> bytes:
        if seconds is None:
            seconds = self.EXPIRATION_SECONDS
        payload = {
            'iss': f'{self.account}.{self.user}.{self.key_fp}',
            'sub': f'{self.account}.{self.user}',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=seconds)
        }
        return jwt.encode(
            payload,
            self.private_key_pem,
            'RS256')


class PipeStage(AbstractContextManager):
    COPY_PATTERN = re.compile(r"^copy into .+ from ('?@[^\s-]+'?)", re.IGNORECASE | re.MULTILINE)

    def __init__(self, config: Config) -> None:
        if not config:
            raise ValueError('config must be defined')
        self.config = config
        self.conn: SnowflakeConnection = None

    def __enter__(self):
        if self.conn is None:
            self.conn = self._connection()
        return self

    def __exit__(self, __exc_type: Type[BaseException], __exc_value: BaseException,
                 __traceback: TracebackType) -> bool:
        if self.conn:
            self.conn.close()
            self.conn = None

    def _connection(self) -> SnowflakeConnection:
        return snowflake.connector.connect(
            account=self.config.account,
            user=self.config.user,
            private_key=self.config.private_key_der,
        )

    def get_pipe_stage(self, pipe: str) -> str:
        with self.conn.cursor(DictCursor) as cur:
            result = cur.execute(f'desc pipe {pipe}').fetchone()
        definition = result['definition']
        match = self.COPY_PATTERN.match(definition)
        if not match:
            raise RuntimeError(f'Failed to find stage in pipe definition: {definition}')
        return match.group(1)

    def use_schema(self, name: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute(f'use schema {name}')

    def put_file(self, file_path: str, stage_path: str, *,
                 auto_compress: Optional[bool] = None,
                 overwrite: Optional[bool] = None,
                 parallel: Optional[int] = None,
                 source_compression: Optional[str] = None) -> str:
        stmt = f'put file://{file_path} {stage_path}'
        if auto_compress is not None:
            stmt += f' auto_compress = {auto_compress}'
        if overwrite is not None:
            stmt += f' overwrite = {overwrite}'
        if parallel is not None:
            stmt += f' parallel = {parallel}'
        if source_compression is not None:
            stmt += f' source_compression = {source_compression}'

        with self.conn.cursor(DictCursor) as cur:
            result = cur.execute(stmt).fetchone()
            return result['target']


class SnowpipeApi:
    def __init__(self, config: Config, pipe: str) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = config
        self.ingest_manager = SimpleIngestManager(
            account=self.config.account,
            host=self.config.url,
            user=self.config.user,
            private_key=self.config.private_key_pem,
            pipe=pipe,
        )

    def report(self, recent_seconds: Optional[int] = None) -> None:
        request_id = uuid.uuid4()
        self.logger.debug(f'request_id: {request_id}')
        body = self.ingest_manager.get_history(
            recent_seconds=recent_seconds,
            request_id=request_id
        )
        print(json.dumps(body, indent=4))

    def history(self, start_time: datetime, end_time: Optional[datetime] = None) -> None:
        if not start_time:
            raise ValueError('start_time must be defined')
        request_id = uuid.uuid4()
        self.logger.debug(f'request_id: {request_id}')
        body = self.ingest_manager.get_history_range(
            start_time_inclusive=start_time.isoformat(),
            end_time_exclusive=end_time.isoformat() if end_time else None,
            request_id=request_id
        )
        print(json.dumps(body, indent=4))

    def ingest(self, files: Iterable[str]) -> None:
        if not files:
            raise ValueError('files must be defined')
        request_id = uuid.uuid4()
        self.logger.debug(f'request_id: {request_id}')
        staged_files = [StagedFile(name, None) for name in files]
        body = self.ingest_manager.ingest_files(
            staged_files=staged_files,
            request_id=request_id,
        )
        print(json.dumps(body, indent=4))


class DateAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        d = datetime.fromisoformat(values)
        if d.tzinfo is None:
            local_tz = datetime.utcnow().astimezone().tzinfo
            d = d.replace(tzinfo=local_tz)
        setattr(namespace, self.dest, d)


def parse_jwt(args: argparse.Namespace) -> None:
    config = Config.create(args.config_file)
    print(config.generate_jwt(args.expiration_seconds))


def parse_report(args: argparse.Namespace) -> None:
    config = Config.create(args.config_file)
    api = SnowpipeApi(config, args.pipe)
    api.report(recent_seconds=args.recent_seconds)


def parse_history(args: argparse.Namespace) -> None:
    config = Config.create(args.config_file)
    api = SnowpipeApi(config, args.pipe)
    api.history(start_time=args.start_time, end_time=args.end_time)


def parse_ingest(args: argparse.Namespace) -> None:
    config = Config.create(args.config_file)
    pipe = args.pipe
    api = SnowpipeApi(config, pipe)

    all_files = []
    if args.file:
        all_files.extend(args.file)
    if args.files:
        with open(args.files) as infile:
            names = (name.strip() for name in infile.readlines() if name.strip())
        all_files.extend(names)

    if args.local_file:
        with PipeStage(config) as pipe_stage:
            stage = pipe_stage.get_pipe_stage(pipe)
            pipe_stage.use_schema(pipe[0:pipe.rindex('.')])
            for local_file in args.local_file:
                stage_path = ''
                stage_location = os.path.join(stage, stage_path)
                stage_file = pipe_stage.put_file(local_file, stage_location)
                all_files.append(os.path.join(stage_path, stage_file))

    logger.debug('Files to ingest:\n%s', '\n'.join(all_files))
    if not all_files:
        raise ValueError('At least one file must be provided')
    api.ingest(all_files)


def parse_pipe(args: argparse.Namespace) -> None:
    config = Config.create(args.config_file)
    with PipeStage(config) as pipe_stage:
        stage = pipe_stage.get_pipe_stage(args.pipe)
    print(stage)


def cli() -> None:
    parser = argparse.ArgumentParser(description='Make requests to the Snowpipe REST APIs')
    parser.add_argument('-i', '--info', help='Enable info logging', action='store_true')
    parser.add_argument('-d', '--debug', help='Enable debug logging', action='store_true')

    subparsers = parser.add_subparsers(help='Sub-commands', dest='command')

    jwt_parser = subparsers.add_parser('jwt', help='Generate and print JWT')
    jwt_parser.add_argument('config_file', help='Path to a YAML config file')
    jwt_parser.add_argument(
        '--expiration-seconds',
        help=f'JWT token expiration time in seconds. Default is {Config.EXPIRATION_SECONDS}.',
        default=Config.EXPIRATION_SECONDS
    )
    jwt_parser.set_defaults(func=parse_jwt)

    report_parser = subparsers.add_parser('report', help='Call the insertReport endpoint')
    report_parser.add_argument('config_file', help='Path to a YAML config file')
    report_parser.add_argument('pipe', help='The pipe to retrieve a report for')
    report_parser.add_argument('--recent-seconds', help='The number of seconds to go back')
    report_parser.set_defaults(func=parse_report)

    history_parser = subparsers.add_parser('history', help='Call the loadHistoryScan endpoint')
    history_parser.add_argument('config_file', help='Path to a YAML config file')
    history_parser.add_argument('pipe', help='The pipe to retrieve history for')
    history_parser.add_argument('start_time', action=DateAction,
                                help='The start time (inclusive) for the history in ISO-8601 format ')
    history_parser.add_argument('--end-time', action=DateAction,
                                help='The end time (exclusive) for the history in ISO-8601 format')
    history_parser.set_defaults(func=parse_history)

    ingest_parser = subparsers.add_parser('ingest', help='Call the ingest endpoint')
    ingest_parser.add_argument('config_file', help='Path to a YAML config file')
    ingest_parser.add_argument('pipe', help='The pipe to invoke')
    ingest_parser.add_argument('-f', '--file', action='append',
                               help='A staged file to ingest. May be specified multiple times.')
    ingest_parser.add_argument('--files', help='A path to a file where each line is a staged file to ingest')
    ingest_parser.add_argument('-l', '--local-file', action='append',
                               help='A local file to stage then ingest. May be specified multiple times.')
    ingest_parser.set_defaults(func=parse_ingest)

    pipe_parser = subparsers.add_parser('pipe', help='Grab the stage for the pipe')
    pipe_parser.add_argument('config_file', help='Path to a YAML config file')
    pipe_parser.add_argument('pipe', help='The pipe to invoke')
    pipe_parser.set_defaults(func=parse_pipe)

    args = parser.parse_args()

    if not args.command:
        print('A subcommand must be specified')
        parser.print_help()
        sys.exit(1)

    if args.debug:
        logger.setLevel(level=logging.DEBUG)
        logger.debug('Debug logging enabled')
    elif args.info:
        logger.setLevel(level=logging.INFO)
        logger.info('Info logging enabled')

    args.func(args)


if __name__ == '__main__':
    cli()
