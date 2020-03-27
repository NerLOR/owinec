#!/usr/bin/env python3

# owinec - Open Windows Event Collector
# Lorenz Stechauner, 2020

import argparse
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import ipaddress
import logging
from socketserver import ThreadingMixIn
import threading
import ntlm

WSMAN_PORT_HTTP = 5985
WSMAN_PORT_HTTPS = 5986


class WSManHandler(BaseHTTPRequestHandler):
    server_version = 'owinec/1.0'

    def do_GET(self):
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.wfile.write(b'Method Not Allowed')

    def do_PUT(self):
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.wfile.write(b'Method Not Allowed')

    def do_POST(self):
        threading.current_thread().setName(self.client_address[0])
        logger.debug(f'Got request from {self.client_address[0]}')
        self.send_response(HTTPStatus.NOT_IMPLEMENTED)
        self.end_headers()
        self.wfile.write(b'Not Implemented')

    def send_response(self, code: HTTPStatus, message=None):
        super().send_response(code, message=message)

    def log_message(self, format, *args):
        return


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='owinec - Open Windows Event Collector')
    parser.add_argument('-p', '--protocol', type=str, default='https', choices=['http', 'https'],
                        help='The protocol to use, default is https')
    parser.add_argument('-l', '--listen-address', type=ipaddress.ip_address, default='0.0.0.0',
                        help='The ip address to bind and listen to, default is 0.0.0.0')
    parser.add_argument('-P', '--port', type=int,
                        help='The tcp port to bind and listen to, default for http is 5985, for https is 5986')
    parser.add_argument('--cert', type=argparse.FileType('r'),
                        help='The certificate file to use for https')
    parser.add_argument('--key', type=argparse.FileType('r'),
                        help='The private key file to use for https')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Be verbose')
    args = parser.parse_args()

    logger = logging.getLogger('owinec')
    logger.setLevel(logging.DEBUG)

    cmd_handler = logging.StreamHandler()
    cmd_handler.setFormatter(logging.Formatter('[%(levelname)s][%(threadName)s] %(message)s'))
    logger.addHandler(cmd_handler)

    if args.verbose:
        cmd_handler.setLevel(logging.DEBUG)
    else:
        cmd_handler.setLevel(logging.INFO)

    logger.debug('Starting owinec...')
    logger.debug(f'Command line arguments: {args}')

    if args.protocol in ('http', 'https'):
        logger.debug(f'Using protocol {args.protocol}')
        bind_address = str(args.listen_address)
        bind_port = args.port or WSMAN_PORT_HTTP if args.protocol == 'http' else WSMAN_PORT_HTTPS

        httpd = ThreadedHTTPServer((bind_address, bind_port), WSManHandler)

        if args.protocol == 'https':
            if not args.cert or not args.key:
                raise FileNotFoundError('certificate and private key have to be specified when using https')
            httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True,
                                           certfile=args.cert.name, keyfile=args.key.name)

        logger.info(f'Listening on {args.protocol}://{bind_address}:{bind_port}/')

        httpd.serve_forever()
    else:
        raise NotImplementedError()
