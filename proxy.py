#!/usr/bin/env python
#
# From https://github.com/senko/tornado-proxy/blob/master/tornado_proxy/proxy.py
# with minor alterations
#
# Simple asynchronous HTTP proxy with tunnelling (CONNECT).
#
# GET/POST proxying based on
# http://groups.google.com/group/python-tornado/msg/7bea08e7a049cf26
#
# Copyright (C) 2012 Senko Rasic <senko.rasic@dobarkod.hr>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
import json
import logging
import os
import sys
import socket
from urlparse import urlparse

import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.web
import tornado.httpclient
import tornado.httputil

logger = logging.getLogger('tornado_proxy')

__all__ = ['ProxyHandler', 'run_proxy']


def get_proxy(url):
    url_parsed = urlparse(url, scheme='http')
    proxy_key = '%s_proxy' % url_parsed.scheme
    return os.environ.get(proxy_key)


def parse_proxy(proxy):
    proxy_parsed = urlparse(proxy, scheme='http')
    return proxy_parsed.hostname, proxy_parsed.port


def fetch_request(url, callback, **kwargs):
    proxy = get_proxy(url)
    if proxy:
        logger.debug('Forward request via upstream proxy %s', proxy)
        tornado.httpclient.AsyncHTTPClient.configure(
            'tornado.curl_httpclient.CurlAsyncHTTPClient')
        host, port_val = parse_proxy(proxy)
        kwargs['proxy_host'] = host
        kwargs['proxy_port'] = port_val

    req = tornado.httpclient.HTTPRequest(url, **kwargs)
    client = tornado.httpclient.AsyncHTTPClient()
    client.fetch(req, callback, raise_error=False)


def get_local_home():
    if sys.platform == "win32":
        return os.environ["LOCALAPPDATA"]
    else:
        return os.path.expanduser("~")


def contents(filename):
    with open(filename, "rb") as handle:
        return handle.read()


def json_load(filename):
    with open(filename, "r") as handle:
        return json.load(handle)


class FakeResponse(object):
    def __init__(self, metadata, body):
        self.code = metadata["code"]
        error = metadata["error"]
        if error is not None:
            error = tornado.web.HTTPError(*error)
        self.error = error
        self.headers = FakeHeaders(metadata["headers"])
        self.reason = metadata["reason"]
        self.body = body


class FakeHeaders(object):
    def __init__(self, headers):
        self.headers = headers

    def get_all(self):
        return self.headers


def json_save(filename, obj):
    with open(filename, "w") as handle:
        json.dump(obj, handle)


def file_save(filename, contents):
    with open(filename, "wb") as handle:
        handle.write(contents)


class ProxyBackend(object):
    def __init__(self):
        self.proxy_dir = os.path.join(get_local_home(), "proxy_mesh")
        print "using proxy dir %s" % self.proxy_dir
        if not os.path.exists(self.proxy_dir):
            os.mkdir(self.proxy_dir)

    def get_cache_dir(self, url):
        for prefix in ["http://", "https://"]:
            if url.lower().startswith(prefix):
                host_start = url[len(prefix):]

                hostname, path = host_start.split("/", 1)
                path_parts = path.split("/")
                for part in path_parts:
                    assert part not in ["..", "."]
                local_dir = os.path.join(self.proxy_dir, hostname, *path_parts)
                return local_dir
        else:
            assert False, "unknown proto in " + url

    def get_url(self, url):
        local_dir = self.get_cache_dir(url)
        if os.path.exists(local_dir):
            metadata = json_load(os.path.join(local_dir, "meta.json"))
            body_data = contents(os.path.join(local_dir, "body"))
            return FakeResponse(metadata, body_data)
        return None

    def save_url(self, url, response):
        """:type response: tornado.web.Response"""

        error = response.error
        if error is not None:
            error = error.args

        metadata = {"code": response.code,
                    "error": error,
                    "headers": list(response.headers.get_all()),
                    "reason": response.reason
                    }
        local_dir = self.get_cache_dir(url)
        if not os.path.isdir(local_dir):
            os.makedirs(local_dir)
        json_save(os.path.join(local_dir, "meta.json"), metadata)
        file_save(os.path.join(local_dir, "body"), response.body)


_proxy_backend = None
""":type: ProxyBackend"""


def init_proxy_backend():
    global _proxy_backend
    assert _proxy_backend is None
    _proxy_backend = ProxyBackend()


class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT']

    def compute_etag(self):
        return None # disable tornado Etag

    @tornado.web.asynchronous
    def get(self):
        print 'Handle %s request to %s' % (self.request.method, self.request.uri)

        def handle_response(response, loaded=False):
            if not loaded:
                if self.request.method == "GET" and self.request.body == "" and 200 <= response.code < 300:
                    print "Saving %s %s %s" % (self.request.method, response.code, self.request.uri)
                    _proxy_backend.save_url(self.request.uri, response)
                else:
                    print "Skipping saving %s %s %s" % (self.request.method, response.code, self.request.uri)
            if response.error and not isinstance(response.error, tornado.httpclient.HTTPError):
                self.set_status(500)
                self.write('Internal server error:\n' + str(response.error))
            else:
                self.set_status(response.code, response.reason)
                self._headers = tornado.httputil.HTTPHeaders() # clear tornado default header

                for header, v in response.headers.get_all():
                    if header not in ('Content-Length', 'Transfer-Encoding', 'Content-Encoding', 'Connection'):
                        self.add_header(header, v) # some header appear multiple times, eg 'Set-Cookie'

                if response.body:
                    self.set_header('Content-Length', len(response.body))
                    self.write(response.body)
            self.finish()

        body = self.request.body
        if not body:
            body = None

        if self.request.method == "GET" and self.request.body == "":
            proxy_response = _proxy_backend.get_url(self.request.uri)
            if proxy_response is not None:
                print "Using saved %s" % self.request.uri
                handle_response(proxy_response, True)
                return

        try:
            if 'Proxy-Connection' in self.request.headers:
                del self.request.headers['Proxy-Connection']
            fetch_request(
                self.request.uri, handle_response,
                method=self.request.method, body=body,
                headers=self.request.headers, follow_redirects=False,
                allow_nonstandard_methods=True)
        except tornado.httpclient.HTTPError as e:
            if hasattr(e, 'response') and e.response:
                handle_response(e.response)
            else:
                self.set_status(500)
                self.write('Internal server error:\n' + str(e))
                self.finish()

    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def connect(self):
        logger.debug('Start CONNECT to %s', self.request.uri)
        host, port_val = self.request.uri.split(':')
        client = self.request.connection.stream

        def read_from_client(data):
            upstream.write(data)

        def read_from_upstream(data):
            client.write(data)

        def client_close(data=None):
            if upstream.closed():
                return
            if data:
                upstream.write(data)
            upstream.close()

        def upstream_close(data=None):
            if client.closed():
                return
            if data:
                client.write(data)
            client.close()

        def start_tunnel():
            logger.debug('CONNECT tunnel established to %s', self.request.uri)
            client.read_until_close(client_close, read_from_client)
            upstream.read_until_close(upstream_close, read_from_upstream)
            client.write(b'HTTP/1.0 200 Connection established\r\n\r\n')

        def on_proxy_response(data=None):
            if data:
                first_line = data.splitlines()[0]
                http_v, status, text = first_line.split(None, 2)
                if int(status) == 200:
                    logger.debug('Connected to upstream proxy %s', proxy)
                    start_tunnel()
                    return

            self.set_status(500)
            self.finish()

        def start_proxy_tunnel():
            upstream.write('CONNECT %s HTTP/1.1\r\n' % self.request.uri)
            upstream.write('Host: %s\r\n' % self.request.uri)
            upstream.write('Proxy-Connection: Keep-Alive\r\n\r\n')
            upstream.read_until('\r\n\r\n', on_proxy_response)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        upstream = tornado.iostream.IOStream(s)

        proxy = get_proxy(self.request.uri)
        if proxy:
            proxy_host, proxy_port = parse_proxy(proxy)
            upstream.connect((proxy_host, proxy_port), start_proxy_tunnel)
        else:
            upstream.connect((host, int(port_val)), start_tunnel)


def run_proxy(port_val, start_ioloop=True):
    """
    Run proxy on the specified port. If start_ioloop is True (default),
    the tornado IOLoop will be started immediately.
    """
    app = tornado.web.Application([
        (r'.*', ProxyHandler),
    ])
    app.listen(port_val)
    ioloop = tornado.ioloop.IOLoop.instance()
    if start_ioloop:
        ioloop.start()

if __name__ == '__main__':
    port = 8888
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    print ("Starting HTTP proxy on port %d" % port)
    run_proxy(port)
