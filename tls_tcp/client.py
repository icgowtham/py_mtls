# -*- coding: utf-8 -*-
"""TLS over TCP mock client."""

import argparse
import socket
import ssl
import sys

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
        {nm}: TCP over TLS mock client to accept requests.\n
        '''.format(nm=sys.argv[0]))
    parser.add_argument('-s',
                        '--host',
                        help='Server host, defaults to "0.0.0.0".',
                        required=False,
                        default='0.0.0.0')
    parser.add_argument('-p',
                        '--port',
                        help='Server port to connect to, defaults to "9999".',
                        required=False,
                        default='9999')
    parser.add_argument('-c',
                        '--cert',
                        help='Client certificate file with path,'
                             ' defaults to "ca_cert.pem" in current directory.',
                        required=False,
                        default='ca_cert.pem')
    parser.add_argument('-k',
                        '--key',
                        help='Client certificate key file with path,'
                             ' defaults to "client.key" in current directory.',
                        required=False,
                        default='client.key')
    parser.add_argument('--server-cert',
                        help='Server certificate file with path,'
                             ' defaults to "server.pem" in current directory.',
                        required=False,
                        dest='server_cert',
                        default='server.pem')
    parser.add_argument('--log-level',
                        help='Logger level, defaults to "DEBUG"',
                        required=False,
                        default='DEBUG')
    return vars(parser.parse_args())


def send_message(host, port, cert, key, server_cert):
    """
    Function to send dummy message to TLS TCP server.

    :param host: str
        Host or IP to connect to.
    :param port: int
        Server port to connect to.
    :param cert: str
        Client certificate file name with path.
    :param key: str
        Client key file name with path.
    :param server_cert: str
        Server certificate file name with path.
    :return: None
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setblocking(True)
        sock.connect((host, port))

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(server_cert)
        context.load_cert_chain(certfile=cert, keyfile=key)

        if ssl.HAS_SNI:
            secure_sock = context.wrap_socket(sock,
                                              server_side=False,
                                              server_hostname=host)
        else:
            secure_sock = context.wrap_socket(sock,
                                              server_side=False)

        cert = secure_sock.getpeercert()

        # Verify server
        if not cert or ('commonName', 'Dummy') not in cert['subject'][5]:
            LOGGER.error('Could not verify server.')

        secure_sock.write('Hello'.encode('utf-8'))
        response = secure_sock.read(1024)
        LOGGER.info('Response from server: %s', response.decode('utf-8'))

        secure_sock.close()
        # sock.close()


# Client
if __name__ == '__main__':
    ARGS = parse_args()
    if ARGS['log_level'] in SUPPORTED_LOG_LEVELS:
        LOGGER.setLevel(ARGS['log_level'])
    else:
        LOGGER.warning('Unknown value for "log-level", should be one of: %s',
                       SUPPORTED_LOG_LEVELS)
    send_message(host=ARGS['host'],
                 port=int(ARGS['port']),
                 cert=ARGS['cert'],
                 key=ARGS['key'],
                 server_cert=ARGS['server_cert'])
