# -*- coding: utf-8 -*-
"""Entry point."""

from yaml import safe_load
from web_app import PeerCertWSGIRequestHandler, ssl_context, app as web_app

if __name__ == '__main__':
    with open('config.yaml') as stream:
        config = safe_load(stream)
    web_app.run(host=config.get('server_host', '0.0.0.0'),
                port=int(config.get('server_port', 9009)),
                ssl_context=ssl_context,
                request_handler=PeerCertWSGIRequestHandler,
                debug=True)
