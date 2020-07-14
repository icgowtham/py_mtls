# -*- coding: utf-8 -*-
"""TLS over TCP mock server."""

import argparse
import pprint
import socket
import ssl
import sys

from logger import get_logger

__author__ = 'Ishwarachandra Gowtham'
__email__ = 'ic.gowtham@gmail.com'
__version__ = '1.0'

LOGGER = get_logger()
MSG_LEN = 1094
SUPPORTED_LOG_LEVELS = ('DEBUG', 'INFO', 'ERROR', 'FATAL', 'CRITICAL', 'WARNING')


# pylint: disable=too-many-arguments,too-many-locals
class Server:
    """Server class."""

    def __init__(self, host, port, cert, key, ca_cert):
        """
        Initialization method.

        :param host: str
            Name or IP of the server.
        :param port: int
            Port where the server will be listening on.
        :param cert: str
            Server certificate file name with path.
        :param key: str
            Server certificate key file name with path.
        :param ca_cert: str
            Client certificate file name with path.
        """
        self._cert = cert
        self._cert_key = key
        self._ca_cert = ca_cert
        self._host = host
        self._port = port
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self._host, self._port))
        self._socket.listen(10)
        self._secure_sock = None

    def serve_forever(self):
        """
        Method to serve client requests.

        :return: None
        """
        try:
            while True:
                client, from_addr = self._socket.accept()
                LOGGER.debug(client)
                LOGGER.debug(from_addr)
                self._secure_sock = ssl.wrap_socket(client,
                                                    server_side=True,
                                                    ca_certs=self._ca_cert,
                                                    certfile=self._cert,
                                                    keyfile=self._cert_key,
                                                    cert_reqs=ssl.CERT_REQUIRED,
                                                    ssl_version=ssl.PROTOCOL_TLSv1_2)

                LOGGER.debug('Peer: ' + repr(self._secure_sock.getpeername()))
                LOGGER.debug('Cipher: %s', self._secure_sock.cipher())
                peer_cert = self._secure_sock.getpeercert()
                LOGGER.debug('Peer certificate: ')
                LOGGER.debug(pprint.pformat(peer_cert))

                # Verify client
                if not peer_cert or ('commonName', 'Dummy') not in peer_cert['subject'][5]:
                    LOGGER.error('Could not verify the client.')

                chunks = []
                bytes_recd = 0
                while True:
                    chunk = self._secure_sock.recv(MSG_LEN)
                    chunks.append(chunk)
                    bytes_recd = bytes_recd + len(chunk)
                    if not chunk or len(chunk) < MSG_LEN:
                        break
                LOGGER.info('Received "%s bytes".', str(bytes_recd))
                request_data = b''.join(chunks)
                LOGGER.debug(chunks)
                response = b'Hello from SERVER -> OK'
                self._secure_sock.send(response)
                client.close()
        except ssl.SSLError:
            LOGGER.exception('SSLError')
        except KeyboardInterrupt:
            self.close()
            sys.exit(0)
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception('Unknown exception encountered!')

    def close(self):
        """Cleanup."""
        LOGGER.debug('Closing the connections.')
        if self._secure_sock:
            self._secure_sock.close()
        if self._socket:
            self._socket.close()


def parse_args():
    """Function to parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='''
        {nm}: TCP over TLS server to accept requests.\n
        '''.format(nm=sys.argv[0]))
    parser.add_argument('-p',
                        '--port',
                        help='Server port to connect to, defaults to "9999".',
                        required=False,
                        default='9999')
    parser.add_argument('-c',
                        '--cert',
                        help='Server certificate file with path,'
                             ' defaults to "server.pem" in current directory.',
                        required=False,
                        default='server.pem')
    parser.add_argument('-k',
                        '--key',
                        help='Server certificate key file with path,'
                             ' defaults to "server.key" in current directory.',
                        required=False,
                        default='server.key')
    parser.add_argument('-ca',
                        '--cert-auth',
                        help='CA certificate file with path,'
                             ' defaults to "ca_cert.pem" in current directory.',
                        required=False,
                        dest='ca_cert',
                        default='ca_cert.pem')
    parser.add_argument('--log-level',
                        help='Logger level, defaults to "DEBUG"',
                        required=False,
                        default='DEBUG')
    return vars(parser.parse_args())


# Server
if __name__ == '__main__':
    ARGS = parse_args()
    if ARGS['log_level'] in SUPPORTED_LOG_LEVELS:
        LOGGER.setLevel(ARGS['log_level'])
    else:
        LOGGER.warning('Unknown value for "log-level", should be one of: %s',
                       SUPPORTED_LOG_LEVELS)
    SVR = Server(host='0.0.0.0',
                 port=int(ARGS['port']),
                 cert=ARGS['cert'],
                 key=ARGS['key'],
                 ca_cert=ARGS['ca_cert'])
    SVR.serve_forever()
