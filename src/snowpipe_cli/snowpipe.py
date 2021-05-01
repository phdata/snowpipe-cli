#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timedelta

import jwt
import logging
import uuid
import yaml

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from snowflake.ingest import SimpleIngestManager, StagedFile

logging.basicConfig(level=logging.WARNING, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger()


class Config:
    EXPIRATION_SECONDS = 3600

    @staticmethod
    def create(config_file):
        with open(config_file) as infile:
            content = yaml.safe_load(infile)
            return Config(**content)

    def __init__(self, url, account, user, key_fp, key_file, key_password=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.url = url.lower()
        self.account = account.upper()
        self.user = user.upper()
        self.key_fp = key_fp
        self.key_file = key_file
        self.key_password = key_password
        self._private_key = None

    @property
    def private_key(self):
        if self._private_key is None:
            self.logger.debug(f'Reading private key file: {self.key_file}')
            with open(self.key_file) as infile:
                content = infile.read()
                pw_bytes = None
                if self.key_password:
                    pw_bytes = self.key_password.encode('utf-8')
                private_key = serialization.load_pem_private_key(content.encode('utf-8'), password=pw_bytes,
                                                                 backend=default_backend())
                self._private_key = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())\
                    .decode('utf-8')
        return self._private_key

    def generate_jwt(self, seconds=None):
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
           self.private_key,
           'RS256')


class SnowpipeApi:

    def __init__(self, config, pipe):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = config
        self.ingest_manager = SimpleIngestManager(
            account=self.config.account,
            host=self.config.url,
            user=self.config.user,
            private_key=self.config.private_key,
            pipe=pipe,
        )

    def report(self, recent_seconds: int = None):
        request_id = uuid.uuid4()
        self.logger.debug(f'request_id: {request_id}')
        body = self.ingest_manager.get_history(
            recent_seconds=recent_seconds,
            request_id=request_id
        )
        print(json.dumps(body, indent=4))

    def history(self, start_time: datetime, end_time: datetime = None):
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

    def ingest(self, files):
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


def parse_jwt(args):
    config = Config.create(args.config_file)
    print(config.generate_jwt(args.expiration_seconds))


def parse_report(args):
    config = Config.create(args.config_file)
    api = SnowpipeApi(config, args.pipe)
    api.report(recent_seconds=args.recent_seconds)


def parse_history(args):
    config = Config.create(args.config_file)
    api = SnowpipeApi(config, args.pipe)
    api.history(start_time=args.start_time, end_time=args.end_time)


def parse_ingest(args):
    config = Config.create(args.config_file)
    api = SnowpipeApi(config, args.pipe)

    all_files = []
    if args.file:
        all_files.extend(args.file)
    if args.files:
        with open(args.files) as infile:
            names = (name.strip() for name in infile.readlines() if name.strip())
        all_files.extend(names)

    logger.debug('Files to ingest:\n%s', '\n'.join(all_files))
    if not all_files:
        raise ValueError('At least one file must be provided')
    api.ingest(all_files)


def cli():
    parser = argparse.ArgumentParser(description='Make requests to the Snowpipe REST APIs')
    parser.add_argument('-i', '--info', help='Enable info logging', action='store_true')
    parser.add_argument('-d', '--debug', help='Enable debug logging', action='store_true')

    subparsers = parser.add_subparsers(help='Sub-commands')

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
    ingest_parser.set_defaults(func=parse_ingest)

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(level=logging.DEBUG)
        logger.debug('Debug logging enabled')
    elif args.info:
        logger.setLevel(level=logging.INFO)
        logger.debug('Info logging enabled')

    args.func(args)


if __name__ == '__main__':
    cli()
