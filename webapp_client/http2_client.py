# -*- coding: utf-8 -*-
"""HTTP/2 client."""

import ssl
from hyper import HTTPConnection
from logger import get_logger

__author__ = 'Ishwarachandra Gowtham'
__email__ = 'ic.gowtham@gmail.com'
__version__ = '1.0'

LOGGER = get_logger()


class Http2Client:
    """HTTP/2 client class."""

    def __init__(self, host, port, certificate, cert_key, cert_password=None):
        """
        Initialization method.

        :param host: str
            Host URI to connect to.
        :param certificate: str
            Name along with path of the client certificate file.
        :param cert_key: str
            Name along with path of the client certificate key.
        :param cert_password: str
            Password for the client certificate, if any.
        """
        self._host = host
        self._port = port
        self._certificate = certificate
        self._cert_key = cert_key
        self._cert_password = cert_password
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self._context.load_cert_chain(certfile=self._certificate,
                                      keyfile=self._cert_key,
                                      password=self._cert_password)
        self._connection = HTTPConnection(host=self._host,
                                          port=self._port,
                                          secure=True,
                                          ssl_context=self._context)

    def do_get(self, uri):
        """
        GET request handler.

        :param uri: str
            URI value.
        :return: str
            Response of GET.
        """
        self._connection.request(method='GET', url=uri)
        response = self._connection.get_response()
        LOGGER.info(response.status, response.reason)
        return response.read()

    def do_post(self, uri, data, headers=None):
        """
        POST request handler.

        :param uri: str
        :param data: object
        :param headers: dict
        :return:
        """
        if not headers:
            headers = {
                'Content-Type': 'text/plain'
            }
        self._connection.request(method='POST',
                                 url=uri,
                                 headers=headers,
                                 body=data)
        response = self._connection.get_response()
        return response
