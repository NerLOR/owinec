#!/usr/bin/env python3

# owinec - Open Windows Event Collector
# Lorenz Stechauner, 2020

import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import ipaddress

WSMAN_PORT_HTTP = 5985
WSMAN_PORT_HTTPS = 5986


class WSManHandler(BaseHTTPRequestHandler):
    server_version = 'owinec/1.0'

    def do_POST(self):
        self.send_response(501)
        self.end_headers()
        self.wfile.write(b'Not Implemented')


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
    args = parser.parse_args()

    if args.protocol in ('http', 'https'):
        bind_address = str(args.listen_address)
        bind_port = args.port or WSMAN_PORT_HTTP if args.protocol == 'http' else WSMAN_PORT_HTTPS
        httpd = HTTPServer((bind_address, bind_port), WSManHandler)

        if args.protocol == 'https':
            if not args.cert or not args.key:
                raise FileNotFoundError('certificate and private key have to be specified when using https')
            httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True,
                                           certfile=args.cert.name, keyfile=args.key.name)

        httpd.serve_forever()
    else:
        raise NotImplementedError()
