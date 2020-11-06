# -*- coding: utf-8 -*-
"""TLS over TCP mock server."""

import argparse
import pprint
import socket
import ssl
import sys

from threading import Event, Thread

from logger import get_logger

__author__ = 'Ishwarachandra Gowtham'
__email__ = 'ic.gowtham@gmail.com'
__version__ = '1.0'

LOGGER = get_logger()
CLIENT_CONNS = []
MSG_LEN = 2048
SUPPORTED_LOG_LEVELS = ('DEBUG', 'INFO', 'ERROR', 'FATAL', 'CRITICAL', 'WARNING')


# pylint: disable=broad-except,logging-not-lazy,unused-variable,no-member
class ClientThread(Thread):
    """Client class."""

    def __init__(self, client, secure_sock, event):
        """
        Initialization method.

        :param client: object
            Client object to log.
        :param secure_sock: object
            Secure socket connection object for this client.
        :param event: object
            Event to trigger thread termination.
        """
        super().__init__()
        self._client = client
        self._secure_sock = secure_sock
        self._event = event
        LOGGER.info('[+] New socket thread started to handle %s [+]',
                    str(self._client))
        LOGGER.debug('Peer: ' + repr(self._secure_sock.getpeername()))
        LOGGER.debug('Cipher: %s', self._secure_sock.cipher())
        peer_cert = self._secure_sock.getpeercert()
        LOGGER.debug('Peer certificate: ')
        LOGGER.debug(pprint.pformat(peer_cert))

    def run(self):
        """Run method."""
        while True:
            try:
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
                LOGGER.debug(request_data)
                response = b'Hello from SERVER -> OK'
                self._secure_sock.send(response)
                if self._event.wait(0):
                    break
            except ssl.SSLError:
                LOGGER.exception('SSLError')
            except (KeyboardInterrupt, OSError):
                if hasattr(self, '__terminate'):
                    res = self.__terminate


# pylint: disable=too-many-arguments,too-many-locals,disable=broad-except
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
        self._ssl_ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        self._ssl_ctx.load_verify_locations(self._ca_cert)
        self._ssl_ctx.load_cert_chain(self._cert, self._cert_key)
        self._ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    def serve_forever(self):
        """
        Method to serve client requests.

        :return: None
        """
        event = Event()
        try:
            while True:
                client, from_addr = self._socket.accept()
                LOGGER.debug(client)
                self._secure_sock = self._ssl_ctx.wrap_socket(client,
                                                              server_side=True)
                new_client_conn = ClientThread(from_addr, self._secure_sock, event)
                new_client_conn.start()
                CLIENT_CONNS.append(new_client_conn)
        except ssl.SSLError:
            LOGGER.exception('SSLError')
        except KeyboardInterrupt:
            event.set()
            self.close()
            sys.exit(0)
        except socket.error as sock_err:
            LOGGER.warning(str(sock_err))
            event.set()
            self.close()
            sys.exit(0)
        except Exception:
            LOGGER.exception('Unknown exception encountered!')

    def close(self):
        """Cleanup."""
        LOGGER.debug('Closing the connections.')
        for conn in CLIENT_CONNS:
            conn.join()
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


# Entry point.
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
