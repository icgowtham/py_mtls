# Py mTLS
* Python based server and client application for using mTLS (mutual TLS).

### Introduction
* `py_mtls` is a Python based server and client application using mTLS (mutual TLS). It contains a webserver application and client along with TCP (TLS) server and client. It also contains a simple web server which serves HTTP/2.0.


### Sample usage:
#### Web application
* On one terminal first run the web server application:
```bash
$ cd webapp_server
$ python3 server.py
```
* On another terminal run the web client application:
```bash
$ cd webapp_client
$ python3 app.py
```
#### TCP server and client
* On one terminal first run the server application:
```bash
$ cd tls_tcp
$ python3 server.py
```
* On another terminal run the log processor application:
```bash
$ cd tls_tcp
$ python3 client.py
```
#### Simple HTTP2 server
* On one terminal first run the web application:
```bash
$ cd simple_http2_server
$ python3 http2_server.py
```
* On another terminal run the `curl` command:
```bash
$ curl -v --http2 http://0.0.0.0:9009/
$ curl -v --http2 -X POST http://0.0.0.0:9009/
```


### Development
Clone the git repo and follow the steps below on any linux  machine.

    git clone https://github.com/icgowtham/py_mtls.git
    cd py_mtls

Setup python virtual environment.

    make setup-env
    source env3/bin/activate
