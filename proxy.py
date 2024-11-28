import http.server
import argparse
import logging
import os
import random
import sys
import io
import ssl
import socket
import re
import urllib.parse
import threading
import json
import base64
from requests.structures import CaseInsensitiveDict

logging.basicConfig()

logger = logging.getLogger(__name__)
#


context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')


import threading
import queue
from concurrent.futures import Future
import concurrent.futures

# Queue that helps handle tasks and waiting for their results
class SyncQueue(queue.Queue):
    # TODO: Remove futures that are too old
    # TODO: handle hash collisions?
    def __init__(self):
        self.q = queue.Queue()
        self.futures = {}

    def process(self, t, timeout=None):
        print(f"Adding to SyncQueue: {t['url']}", file=sys.stderr)
        future = Future()
        h = hash(future)
        self.q.put((h, t))
        self.futures[h] = future
        try:
            ret = future.result(timeout=timeout)
        except TimeoutError as e:
            ret = None
        except concurrent.futures._base.TimeoutError as e:
            ret = None
        self.futures[h].cancel()
        del self.futures[h]
        return ret

    def qsize(self):
        return self.q.qsize()

    def get(self, block=True, timeout=None):
        return self.q.get(block=block, timeout=timeout)

    def putResult(self, f, r):
        #print(f"Adding result to SyncQueue: {r}", file=sys.stderr)
        self.futures[f].set_result(r)
        self.q.task_done()

def sendHTTPResponse(server, statusCode, headers={}, data=None, automake_json=True):
    headers = CaseInsensitiveDict(headers)
    if data is None:
        data = b''
    if type(data) is str:
        data = data.encode()
    if type(data) is not bytes and automake_json:
        data = json.dumps(data).encode()
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
    if type(data) is not bytes:
        raise ValueError(f'Data is of invalid type: {repr(data)}')
    
    headers['Content-Length'] = str(len(data))
    headers['Content-Encoding'] = 'identity' # TODO: Implement compression?
    server.log_request(statusCode)
    server.send_response_only(statusCode)
    for k,v in headers.items():
        server.send_header(k, v)
    server.end_headers()
    server.wfile.write(data)

class ProxyBackendHandler(http.server.BaseHTTPRequestHandler):
    # TODO: Add authentication
    # TODO: Add multi-browser support
    def do_GET(self):
        if self.path == '/proxy':
            with open('proxy.html','r') as f:
                data = f.read()
            data = data.replace("localhost:8000",self.server.pubaddr)
            return sendHTTPResponse(self, 200, headers={'Content-Type':'text/html'}, data=data)
        elif self.path == '/cert':
            with open('cert.pem','r') as f:
                data = f.read()
            return sendHTTPResponse(self, 200, headers={'Content-Type':'application/x-pem-file'}, data=data)
        elif self.path == '/queue':
            # Requests to /queue are blocking until we have something to return
            reqs = []
            #print(f'/queue start: {self.server.syncQueue.qsize()}')
            try:
                while True:
                    f, m = self.server.syncQueue.get(block=(len(reqs) == 0))
                    m['requestId'] = f
                    reqs.append(m)

            except queue.Empty:
                pass
            
            #print(f'/queue end: {len(reqs)}')
            #print(f"Queue is: {reqs}", file=sys.stderr)
            return sendHTTPResponse(self, 200, data=reqs)
        else:
            return sendHTTPResponse(self, 200, data={'status':'notfound'})

    def do_POST(self):
        if self.path == '/result':
            content_len = int(self.headers.get('Content-Length'))
            if content_len < 1:
                sendHTTPResponse(self, 403,data={'status':'Fail'})
                return
            
            post_body = self.rfile.read(content_len)
            response = json.loads(post_body)
            # TODO: Add exception handling
            id = int(response['requestId'])
            statusCode = int(response['statusCode'])
            data = base64.b64decode(response['responseData'])
            headers = response['responseHeaders']
            for k,v in headers.items():
                assert(type(k) is str)
                assert(type(v) is str)

            result = {
                'statusCode': statusCode,
                'responseData': data, 
                'responseHeaders': headers
            }

            self.server.syncQueue.putResult(id, result)
            return sendHTTPResponse(self, 200,data={'status':'OK'})
        else:
            return sendHTTPResponse(self, 404,data={'status':'notfound'})
            

class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def read_raw_httpreq(self, s):
        d = s.recv(65537, socket.MSG_PEEK)
        try:
            # TODO: Do not assume HTTP request uses CRLF even though required my standard.
            i = d.index(b'\r\n\r\n')+4
            s.recv(i)
            return d[:i]
        except ValueError as e:
            return None

    def setup(self):
        self.connect_host = None
        # Socket is in self.request
        if self.timeout is not None:
            self.request.settimeout(self.timeout)

        try:
            # We are checking for CONNECT already in setup as this is the point before the socket in
            # self.request has not been split into self.rfile, self.wfile and has not been read yet.
            # So we can safely peek it and replace it here, while later it is harder.

            h = self.request.recv(8, socket.MSG_PEEK)[:8]
            if h == b"CONNECT ":
                httpReq = self.read_raw_httpreq(self.request)
                if httpReq is None:
                    self.log_error("Failed to read first header, assuming non SSL: %r", e)
                    return
                self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                try:
                    self.connect_host = httpReq.split(b' ')[1].decode('latin1')
                except IndexError as e:
                    self.log_error("Malformed connect method, assuming non SSL: %r", e)
                    # TODO: Stop the connection
                    return

                if not re.fullmatch('[a-zA-Z0-9-_.]+(:[0-9]+)?', self.connect_host):
                    self.log_error("Invalid CONNECT host: %s", self.connect_host)
                    # TODO: Stop the connection
                    return
                try:
                    self.request = context.wrap_socket(self.request, server_side=True)
                except ssl.SSLError as e:
                    if e.reason == 'SSLV3_ALERT_CERTIFICATE_UNKNOWN':
                        self.log_error("Proxy client rejected our SSL cert. Install it in your client")
                        # TODO: Stop the connection
                        return
                    raise e
        except TimeoutError as e:
            self.log_error("Failed to read first header, assuming non SSL: %r", e)
            return
        finally:
            super().setup()

    def do_HEAD(self):
        self.proxy()
    
    def do_GET(self):
        # TODO: Add host that provides the cert for installation, similar to https://burp
        self.proxy()
    
    def do_POST(self):
        self.proxy()

    def do_PATCH(self):
        self.proxy()
    
    def do_PUT(self):
        self.proxy()

    def do_DELETE(self):
        self.proxy()

    def proxy(self):
        if self.connect_host is not None:
            url = urllib.parse.urljoin(f"https://{self.connect_host}/",self.path)
        else:
            url = self.path
        data = b''
        if 'Content-Length' in self.headers:
            content_len = max(0,int(self.headers.get('Content-Length')))
            data = self.rfile.read(content_len)

        d = {
            'method': self.command,
            'url':    url,
            'data':   base64.b64encode(data).decode(),
            'headers':dict(self.headers),
        }
        result = self.server.syncQueue.process(d, timeout=None)
        if result is not None:
            status = result['statusCode']
            body = result['responseData']
            headers = CaseInsensitiveDict(result['responseHeaders'])
        else:
            status = 503
            body = ""
            headers = {'Retry-After': '1'}

        if 'Content-Length' in headers:
            del headers['Content-Length']
        if 'Content-Encoding' in headers:
            del headers['Content-Encoding']
        # TODO: Add content-encoding
        return sendHTTPResponse(self, status,headers=headers, data=body)

def parse_args(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='Either Proxy or Echo HTTP requests')
    parser.add_argument('--pport', dest='pport', type=int, default=8080,
                       help='Proxy Port(default: 8080)')
    parser.add_argument('--wport', dest='wport', type=int, default=8000,
                       help='Web Port(default: 8000)')
    parser.add_argument('--waddr', dest='waddr', type=str, default="0.0.0.0",
                       help='Address web backend to listen on (default: 0.0.0.0)')
    parser.add_argument('--paddr', dest='paddr', type=str, default="127.0.0.1",
                       help='Address for proxy to listen on (default: 127.0.0.1)')
    parser.add_argument('--publicaddr', dest='pubaddr', type=str, default='localhost', help='Modify content of proxy.html using this on endpoint /proxy.')
    args = parser.parse_args(argv)
    return args

def main(argv=sys.argv[1:]):
    syncQueue = SyncQueue()
    
    args = parse_args(argv)
    pubaddr = args.pubaddr
    if ':' not in pubaddr: # TODO: support ipv6
        pubaddr += f":{args.wport}"
    
    print(f'Proxy port: {args.pport}')
    proxy_server = http.server.ThreadingHTTPServer((args.paddr, args.pport), ProxyHTTPRequestHandler)
    # TODO: Our way of providing the syncQueue is not so pretty
    proxy_server.syncQueue = syncQueue
    proxyT = threading.Thread(target=proxy_server.serve_forever)
    proxyT.daemon = True
    proxyT.start()

    print(f'Web server port {args.wport}')
    webServer = http.server.ThreadingHTTPServer((args.waddr, args.wport), ProxyBackendHandler)
    webServer.syncQueue = syncQueue
    webServer.pubaddr = pubaddr
    webServer.serve_forever()
    
if __name__ == '__main__':
    main()