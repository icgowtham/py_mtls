# -*- coding: utf-8 -*-
"""HTTP2 server."""

from quart import Quart

__author__ = 'Ishwarachandra Gowtham'
__email__ = 'ic.gowtham@gmail.com'
__version__ = '1.0'


app = Quart(__name__)

from web_app import routes
