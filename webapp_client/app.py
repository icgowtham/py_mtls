# -*- coding: utf-8 -*-
"""HTTPs (mTLS) client application."""

import argparse
import sys

from http2_client import Http2Client
from logger import get_logger

__author__ = 'Ishwarachandra Gowtham'
__email__ = 'ic.gowtham@gmail.com'
__version__ = '1.0'

LOGGER = get_logger()
SUPPORTED_LOG_LEVELS = ('DEBUG', 'INFO', 'ERROR', 'FATAL', 'CRITICAL', 'WARNING')


def parse_args():
    """Function to parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='''
        {nm}: Client application to send HTTPs request(s).\n
        '''.format(nm=sys.argv[0]))
    parser.add_argument('-s',
                        '--host',
                        help='Server host, defaults to "0.0.0.0".',
                        required=False,
                        default='0.0.0.0')
    parser.add_argument('-p',
                        '--port',
                        help='Server port to connect to, defaults to "8008".',
                        required=False,
                        default='9009')
    parser.add_argument('-c',
                        '--cert',
                        help='Client certificate file with path,'
                             ' defaults to "client.pem" in current directory.',
                        required=False,
                        default='client.pem')
    parser.add_argument('-k',
                        '--key',
                        help='Client certificate key file with path,'
                             ' defaults to "client.key" in current directory.',
                        required=False,
                        default='client.key')
    parser.add_argument('-pw',
                        '--password',
                        help='Client certificate file password, defaults to None.',
                        required=False,
                        default=None)
    parser.add_argument('-ep',
                        '--endpoint',
                        help='URI endpoint, defaults to "/".',
                        required=False,
                        default='/')
    parser.add_argument('--log-level',
                        help='Logger level, defaults to "DEBUG"',
                        required=False,
                        default='DEBUG')
    parser.add_argument('-H',
                        dest='hostname_header',
                        help='Hostname header',
                        required=False,
                        default=None)
    return vars(parser.parse_args())


if __name__ == '__main__':
    ARGS = parse_args()
    if ARGS['log_level'] in SUPPORTED_LOG_LEVELS:
        LOGGER.setLevel(ARGS['log_level'])
    else:
        LOGGER.warning('Unknown value for "log-level", should be one of: %s',
                       SUPPORTED_LOG_LEVELS)
    client = Http2Client(host=ARGS['host'],
                         port=int(ARGS['port']),
                         certificate=ARGS['cert'],
                         cert_key=ARGS['key'],
                         cert_password=ARGS['password'])
    headers = None
    if ARGS['hostname_header']:
        headers = {
            'Host': ARGS['hostname_header']
        }
    res = client.do_post(uri=ARGS['endpoint'],
                         data='dummy',
                         headers=headers)
    LOGGER.info(res.read())
