#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timedelta

import jwt
import logging
import requests
import uuid
import yaml

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger()


class Config:
    EXPIRATION_SECONDS = 3600

    @staticmethod
    def create(config_file):
        with open(config_file) as infile:
            content = yaml.safe_load(infile)
            return Config(**content)

    def __init__(self, url_prefix, account, user, key_fp, key_file, key_password=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.url_prefix = url_prefix.lower()
        self.account = account.upper()
        self.user = user.upper()
        self.key_fp = key_fp
        self.key_file = key_file
        self.key_password = key_password
        self._private_key = None

    @property
    def private_key(self):
        if self._private_key is None:
            self.logger.debug('Reading private key file: %s', self.key_file)
            with open(self.key_file) as infile:
                content = infile.read()
                pw_bytes = None
                if self.key_password:
                    pw_bytes = self.key_password.encode('utf-8')
                self._private_key = serialization.load_pem_private_key(content.encode('utf-8'), password=pw_bytes,
                                                                       backend=default_backend())
        return self._private_key

    def generate_jwt(self, seconds=None):
        if seconds is None:
            seconds = self.EXPIRATION_SECONDS
        payload = {
          'iss': '{}.{}.{}'.format(self.account, self.user, self.key_fp),
          'sub': '{}.{}'.format(self.account, self.user),
          'iat': datetime.utcnow(),
          'exp': datetime.utcnow() + timedelta(seconds=seconds)
        }
        return jwt.encode(
           payload,
           self.private_key,
           'RS256')


class SnowpipeApi:
    URL_TEMPLATE = 'https://{}.snowflakecomputing.com/v1/data/pipes/{}'

    def __init__(self, config):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = config

    def _headers(self):
        token = self.config.generate_jwt()
        return {
            'Authorization': 'BEARER {}'.format(token),
        }

    def _url(self, endpoint, pipe):
        return self.URL_TEMPLATE.format(self.config.url_prefix, pipe) + '/' + endpoint

    def report(self, pipe, begin_mark=None):
        params = {
            'requestId': str(uuid.uuid4()),
        }
        if begin_mark:
            params['beginMark'] = begin_mark
        response = requests.get(
            self._url('insertReport', pipe),
            headers=self._headers(),
            params=params,
        )
        body = response.json()
        print(json.dumps(body, indent=4))

    def history(self, pipe, start_time: datetime, end_time: datetime = None):
        params = {
            'requestId': str(uuid.uuid4()),
            'startTimeInclusive': start_time.isoformat(),
        }
        if end_time:
            params['endTimeExclusive'] = end_time.isoformat()
        response = requests.get(
            self._url('loadHistoryScan', pipe),
            headers=self._headers(),
            params=params,
        )
        body = response.json()
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
    api = SnowpipeApi(config)
    api.report(args.pipe, begin_mark=args.begin_mark)


def parse_history(args):
    config = Config.create(args.config_file)
    api = SnowpipeApi(config)
    api.history(args.pipe, start_time=args.start_time, end_time=args.end_time)


def parse_args():
    parser = argparse.ArgumentParser(description='Make requests to the Snowpipe REST APIs')
    parser.add_argument('config_file', help='Path to a YAML config file')
    parser.add_argument('-d', '--debug', help='Enable debug logging', action='store_true')

    subparsers = parser.add_subparsers(help='Sub-commands')

    jwt_parser = subparsers.add_parser('jwt', help='Generate and print JWT')
    jwt_parser.add_argument(
        '--expiration-seconds',
        help='JWT token expiration time in seconds. Default is {}.'.format(Config.EXPIRATION_SECONDS),
        default=Config.EXPIRATION_SECONDS
    )
    jwt_parser.set_defaults(func=parse_jwt)

    report_parser = subparsers.add_parser('report', help='Call the insertReport endpoint')
    report_parser.add_argument('pipe', help='The pipe to retrieve a report for')
    report_parser.add_argument('--begin-mark', help='The begin mark')
    report_parser.set_defaults(func=parse_report)

    history_parser = subparsers.add_parser('history', help='Call the loadHistoryScan endpoint')
    history_parser.add_argument('pipe', help='The pipe to retrieve history for')
    history_parser.add_argument('start_time', action=DateAction,
                                help='The start time (inclusive) for the history in ISO-8601 format ')
    history_parser.add_argument('--end-time', action=DateAction,
                                help='The end time (exclusive) for the history in ISO-8601 format')
    history_parser.add_argument('--begin-mark', help='The begin mark')
    history_parser.set_defaults(func=parse_history)

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(level=logging.DEBUG)
        logger.debug('Debug logging enabled')
    args.func(args)


if __name__ == '__main__':
    parse_args()
