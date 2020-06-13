# -*- coding: utf-8 -*-
"""Requests handler."""

import os
import ssl

import OpenSSL
import werkzeug.serving
from flask import Flask
from yaml import safe_load

__author__ = 'Ishwarachandra Gowtham'
__email__ = 'ic.gowtham@gmail.com'
__version__ = '1.0'


class PeerCertWSGIRequestHandler(werkzeug.serving.WSGIRequestHandler):
    """Peer request handler class."""

    def make_environ(self):
        """Develop the environ hash that eventually forms part of the Flask request object."""
        environ = super().make_environ()
        x509_binary = self.connection.getpeercert(True)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_binary)
        environ['peercert'] = x509
        return environ


parent_path = os.path.dirname(os.path.dirname(__file__))
config_file = os.path.join(parent_path, 'config.yaml')
with open(config_file) as stream:
    config = safe_load(stream)

app = Flask(__name__)

# To establish an SSL socket we need the private key and certificate.
app_cert = config.get('server_cert', os.path.join(parent_path, 'server.pem'))
app_key = config.get('server_key', os.path.join(parent_path, 'server.key'))
app_key_password = None

# In order to verify client certificates we need the certificate of the
# CA that issued the client's certificate.
ca_cert = config.get('ca_cert', os.path.join(parent_path, 'ca_cert.pem'))

ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH,
                                         cafile=ca_cert)

ssl_context.load_cert_chain(certfile=app_cert,
                            keyfile=app_key,
                            password=app_key_password)
ssl_context.verify_mode = ssl.CERT_REQUIRED

from web_app import routes
