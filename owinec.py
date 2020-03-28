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
import base64
import re
import requests

WSMAN_PORT_HTTP = 5985
WSMAN_PORT_HTTPS = 5986

WSMAN_PATTERN = re.compile(r'(https?)://([^:/]+)(:(\d+))?(/.*)')


class WSManHandler(BaseHTTPRequestHandler):
    server_version = 'owinec/1.0'

    def parse_request(self):
        threading.current_thread().setName(self.address_string())
        return super().parse_request()

    def do_GET(self):
        logger.debug(f'GET {self.path} from {self.address_string()}, invalid method')
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.end_headers()
        self.wfile.write(b'Method Not Allowed')

    def do_PUT(self):
        logger.debug(f'PUT {self.path} from {self.address_string()}, invalid method')
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.end_headers()
        self.wfile.write(b'Method Not Allowed')

    def do_POST(self):
        logger.debug(f'POST {self.path} from {self.address_string()}')

        if forward:
            headers = {
                'Content-Length': self.headers['Content-Length'],
                'Content-Type': self.headers['Content-Type'],
                'Authorization': self.headers['Authorization']
            }
            payload = self.rfile.read(int(self.headers['Content-Length']))
            url = f'{forward[0]}://{forward[1]}:{forward[2]}{forward[3]}'
            logger.debug(f'Forwarding request: {url}')
            print(f'<-AUTH: {headers["Authorization"]}')
            msg_1 = ntlm.decode_message(base64.b64decode(headers['Authorization'].split(' ')[1]))
            print(f'<-NTLM: {msg_1}')
            print(f'<-PAYLOAD: {payload.decode("utf16")}')
            r = requests.post(url, headers=headers, data=payload)
            logger.debug(f'Proxy-Reply: {r.status_code}')
            print(f'->AUTH: {r.headers["WWW-Authenticate"]}')
            msg_2 = ntlm.decode_message(base64.b64decode(r.headers['WWW-Authenticate'].split(' ')[1]))
            print(f'->NTLM: {msg_2}')
            print(f'->PAYLOAD: {r.text}')

            self.send_response(r.status_code)
            self.send_header('Content-Length', r.headers['Content-Length'])
            self.send_header('Content-Type', r.headers['Content-Type'] if 'Content-Type' in r.headers else None)
            self.send_header('WWW-Authenticate', r.headers['WWW-Authenticate'])
            self.end_headers()
            self.wfile.write(r.content)
            return

        auth = self.headers['Authorization']
        if auth is None:
            logger.info(f'POST {self.path} - 401 Unauthorized - Header field Authorization missing')
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header('WWW-Authenticate', 'Negotiate')
            self.end_headers()
            self.wfile.write(b'Header field Authorization missing')
            return

        auth = auth.split(' ')
        logger.debug(f'Authentication protocol: {auth[0]}')
        if auth[0] != 'Negotiate':
            logger.info(f'POST {self.path} - 401 Unauthorized - Authentication protocol not supported')
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header('WWW-Authenticate', 'Negotiate')
            self.end_headers()
            self.wfile.write(b'Authentication protocol not supported')
            return

        # TODO handle client sessions
        payload = self.rfile.read(int(self.headers['Content-Length'])).decode('utf16')
        print(payload)

        try:
            msg = ntlm.decode_message(base64.b64decode(auth[1]))
        except Exception as e:
            logger.exception(f'POST {self.path} - 500 Internal server error while parsing NTLM message - '
                             f'{e.__class__.__name__}: {e}')
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.send_header('WWW-Authenticate', 'Negotiate')
            self.end_headers()
            self.wfile.write(b'Internal server error while parsing NTLM message')
            return

        if msg.type == ntlm.NEGOTIATE_MESSAGE:
            logger.debug(f'NEGOTIATE_MESSAGE received')
            challenge_msg = msg.response(None, None, None)
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header('WWW-Authenticate', 'Negotiate ' + base64.b64encode(challenge_msg.encode()).decode('ascii'))
            self.end_headers()
            return
        elif msg.type == ntlm.AUTHENTICATE_MESSAGE:
            logger.debug(f'AUTHENTICATE_MESSAGE received')

        logger.info(f'POST {self.path} - 501 Not implemented')
        self.send_response(HTTPStatus.NOT_IMPLEMENTED)
        self.send_header('WWW-Authenticate', 'Negotiate')
        self.end_headers()
        self.wfile.write(b'Not Implemented')

    def send_response(self, code: HTTPStatus, message=None):
        return super().send_response(code, message=message)

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
    parser.add_argument('-f', '--forward', type=str,
                        help='Forwards all requests here')
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
    cmd_handler.setFormatter(logging.Formatter('[%(threadName)s][%(levelname)s] %(message)s'))
    logger.addHandler(cmd_handler)

    if args.verbose:
        cmd_handler.setLevel(logging.DEBUG)
    else:
        cmd_handler.setLevel(logging.INFO)

    logger.debug('Starting owinec...')
    logger.debug(f'Command line arguments: {args}')

    if args.forward:
        forward_m = WSMAN_PATTERN.fullmatch(args.forward)
        if forward_m:
            forward = (forward_m.group(1),
                       forward_m.group(2),
                       forward_m.group(4) or WSMAN_PORT_HTTP if forward_m.group(1) == 'http' else WSMAN_PORT_HTTPS,
                       forward_m.group(5))
            logger.info(f'Proxying to {forward[0]}://{forward[1]}:{forward[2]}{forward[3]}')
        else:
            logger.critical('Cannot parse --forward argument')
            exit(1)

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
        else:
            # TODO remove warning for http payload encryption
            logger.warning('If using http, the client will send encrypted payload, that cannot be decrypted')

        logger.info(f'Listening on {args.protocol}://{bind_address}:{bind_port}/')

        httpd.serve_forever()
    else:
        raise NotImplementedError()
