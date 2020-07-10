# -*- coding: utf-8 -*-
"""Route handler."""

import logging

from quart import request
from quart.logging import default_handler

from . import app

__author__ = 'Ishwarachandra Gowtham'
__email__ = 'ic.gowtham@gmail.com'
__version__ = '1.0'

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(default_handler)
LOGGER.setLevel(logging.DEBUG)


@app.route('/', methods=['GET', 'POST'])
async def request_handler():
    """Default route."""
    if request.method == 'POST':
    	LOGGER.debug(request.headers)
        request_data = await request.data
        LOGGER.info('Received from client: ')
        LOGGER.info(request_data)
        return 'POST response from HTTP2 server'
    return 'Hello from HTTP2 server!'
