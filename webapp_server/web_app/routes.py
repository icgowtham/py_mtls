# -*- coding: utf-8 -*-
"""Route handler."""

import logging

from flask import request
from flask.logging import default_handler

from . import app

__author__ = 'Ishwarachandra Gowtham'
__email__ = 'ic.gowtham@gmail.com'
__version__ = '1.0'

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(default_handler)
LOGGER.setLevel(logging.DEBUG)


@app.route('/', methods=['GET', 'POST'])
def index():
    """Default route."""
    if request.method == 'POST':
        return 'POST response from mTLS server'
    return 'Hello from mTLS server!'
