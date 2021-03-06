#!/usr/bin/env python
#
# From https://github.com/senko/tornado-proxy/blob/master/tornado_proxy/proxy.py
# with heavy modifications
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
import hashlib
import json
import logging
import os
import rfc822
import sys
import socket
import urllib
from urlparse import urlparse

import sqlite3
import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.web
import tornado.httpclient
import tornado.httputil
import zlib

LAUNCH_INITIAL_SYNC_SIMULTANEOUS_DOWNLOADS = 4

REQUEST_TIMEOUT = 3600.0
MAX_BODY_SIZE = 2 * 1024 * 1024 * 1024

CACHE_EXCLUDE_PATTERNS = []

ALWAYS_SERVE_ENCODED_GZIP = []

META_JSON = "meta.json"

MAX_WRITE_CHUNK_SIZE = 1024 * 1024
MAX_WRITE_BUFFER_SIZE = 16 * 1024 * 1024

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
    client = tornado.httpclient.AsyncHTTPClient(max_body_size=MAX_BODY_SIZE)
    client.fetch(req, callback, raise_error=False)


def get_local_home():
    if sys.platform == "win32":
        return os.environ["LOCALAPPDATA"]
    else:
        return os.path.expanduser("~")


def contents(filename):
    with open(filename, "rb") as handle:
        return handle.read()


def get_size(filename):
    st = os.stat(filename)
    return st.st_size


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


class WriteBufferFriendlyWrite(object):
    def __init__(self, request_handler, data_to_write):
        """
        Write data to the given request handler, limiting the amount of
        unflushed data at any given time, and then call finish().
        :param request_handler: request to write the data to
        :param data_to_write: the data to write
        :type data_to_write: str
        """
        assert isinstance(request_handler, tornado.web.RequestHandler)
        # noinspection PyProtectedMember
        if request_handler._auto_finish:
            raise ValueError("The request handler %r was not tagged @tornado.web.asynchronous." % request_handler)
        self.request_handler = request_handler
        self.data_to_write = data_to_write
        self.offset = 0
        self.unflushed_bytes = 0
        self.write_in_progress = False
        self.do_write()

    def do_write(self):
        self.write_in_progress = True
        while self.offset < len(self.data_to_write):
            # we treat the last chunk as a full sized chunk for buffer accounting purposes
            # to avoid additional state for its size
            if self.unflushed_bytes > MAX_WRITE_BUFFER_SIZE:
                self.write_in_progress = False
                return
            write_size = MAX_WRITE_CHUNK_SIZE
            chunk_data = self.data_to_write[self.offset:self.offset + write_size]
            self.offset += write_size
            self.unflushed_bytes += write_size
            self.request_handler.write(chunk_data)
            self.request_handler.flush(callback=self.flush_callback)
        self.request_handler.finish()

    def flush_callback(self):
        self.unflushed_bytes -= MAX_WRITE_CHUNK_SIZE
        if not self.write_in_progress:
            self.do_write()


class FakeHeaders(object):
    def __init__(self, headers):
        self.headers = headers

    def get_all(self):
        return self.headers

    def __getitem__(self, key):
        for cur_key, value in self.headers:
            if key.lower() == cur_key.lower():
                return value
        raise KeyError("Unknown key " + key)

    def __contains__(self, key):
        for cur_key, _ in self.headers:
            if cur_key.lower() == key.lower():
                return True
        return False


def json_save(filename, obj):
    with open(filename, "w") as handle:
        json.dump(obj, handle)


def file_save(filename, file_contents):
    with open(filename, "wb") as handle:
        handle.write(file_contents)


class LimitTracker(object):
    def __init__(self, limit):
        self.limit = limit
        self.cur_count = 0
        self.index = 0
        self.keys_done = set()

    def unique(self, key):
        assert key not in self.keys_done
        self.keys_done.add(key)

    def at_limit(self):
        return self.cur_count >= self.limit

    def started(self, *key):
        self.unique(key)
        self.cur_count += 1

    def cur_index(self):
        return self.index

    def next_index(self):
        self.index += 1
        return self.index

    def queue_empty(self):
        return self.cur_count == 0

    def done(self):
        if self.index > 0:
            self.cur_count -= 1


class ProxyBackend(object):
    def __init__(self, our_ip, our_port, proxy_dir, rebuild_db):
        self.peers = []
        self.our_ip = our_ip
        self.our_port = our_port
        if proxy_dir is None:
            proxy_dir = os.path.join(get_local_home(), "proxy_mesh")
        self.proxy_dir = proxy_dir
        self.cache_db = os.path.join(proxy_dir, "cache.sqlite3")

        self.downloads_in_progress_with_metadata = {}

        print "using proxy dir %s" % self.proxy_dir
        if not os.path.exists(self.proxy_dir):
            os.mkdir(self.proxy_dir)

        if rebuild_db and os.path.exists(self.cache_db):
            print "removing existing db"
            os.remove(self.cache_db)

        self.cache_db_conn = sqlite3.connect(self.cache_db)

        create_table_sql = """CREATE TABLE IF NOT EXISTS cache_entries
            (url TEXT PRIMARY KEY ASC, last_modified INTEGER, json TEXT NOT NULL)
        """
        create_timestamp_index_sql = """CREATE INDEX IF NOT EXISTS cache_entries_last_modified ON cache_entries (last_modified)"""

        conn = self.cache_db_conn
        with conn:
            conn.execute(create_table_sql)
            conn.execute(create_timestamp_index_sql)

        if rebuild_db:
            print "rebuilding db"
            self.rebuild_db()
            print "done rebuilding db"

    def update_metadata_database_entry(self, url, metadata, metadata_json=None):
        """Caller is responsible for committing the transaction, so they can do multiple updates in one transaction for performance"""
        if metadata_json is None:
            metadata_json = json.dumps(metadata_json)
        last_modified_epoch = None
        for key, value in metadata["headers"]:
            if key.lower() == "last-modified":
                last_modified_epoch = rfc822.mktime_tz(rfc822.parsedate_tz(value))
                break

        self.cache_db_conn.execute("""insert or replace into cache_entries (url, last_modified, json) values (?, ?, ?)""", (url, last_modified_epoch, metadata_json))

    INITIAL_LIST_SQL = """SELECT url, last_modified FROM cache_entries ORDER BY url LIMIT ?"""
    SUBSEQUENT_LIST_SQL = """SELECT url, last_modified FROM cache_entries WHERE url >= ? ORDER BY url LIMIT ?"""

    def list_entries(self, count, next_key=None):
        """
        :type count: int
        :type next_key: str or None
        :rtype: (list of {'url': str, 'last_modified': int}, str or None)
        """
        with self.cache_db_conn:
            c = self.cache_db_conn.cursor()
            try:
                if next_key is None:
                    c.execute(self.INITIAL_LIST_SQL, (count + 1,))
                else:
                    c.execute(self.SUBSEQUENT_LIST_SQL, (next_key, count + 1))

                out = []
                rows = c.fetchall()
                for url, last_modified in rows[:count]:
                    out.append({"url": url, "last_modified": last_modified})

                if len(rows) > count:
                    new_next_key, _ = rows[-1]
                else:
                    new_next_key = None
            finally:
                c.close()

            return out, new_next_key

    def check_existing_entry(self, url, last_modified_epoch):
        """Check if we have an the same as or newer than the given details; return True if so and False if not"""
        with self.cache_db_conn:
            c = self.cache_db_conn.cursor()
            try:
                c.execute("select 1 from cache_entries where url = ? and last_modified >= ?", (url, last_modified_epoch))
                return len(c.fetchall()) > 0
            finally:
                c.close()

    def rebuild_db(self):
        with self.cache_db_conn:
            for dirpath, dirnames, filenames in os.walk(self.proxy_dir):
                if META_JSON in filenames:
                    print dirpath
                    metadata_json = contents(os.path.join(dirpath, META_JSON))
                    metadata = json.loads(metadata_json)

                    rel = os.path.relpath(dirpath, self.proxy_dir)
                    parts = rel.split(os.sep)
                    url = "http://" + "/".join(parts)

                    self.update_metadata_database_entry(url, metadata, metadata_json)

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
        if os.path.exists(local_dir) and os.path.exists(os.path.join(local_dir, META_JSON)):
            metadata = json_load(os.path.join(local_dir, META_JSON))
            body_data_filename = os.path.join(local_dir, "body")

            headers = FakeHeaders(metadata["headers"])
            if "Content-length" in headers and ("X-Consumed-Content-Encoding" not in headers or headers["X-Consumed-Content-Encoding"] != "gzip"):
                content_length_str = headers["Content-length"]
                if content_length_str is not None:
                    if get_size(body_data_filename) != int(content_length_str):
                        print "Ignoring cached resource as size doesn't match content-length from headers"
                        return None

            body_data = contents(body_data_filename)
            fr = FakeResponse(metadata, body_data)
            return fr
        return None

    def save_url(self, url, response):
        """
        Save URL result into the cache
        :type url: str
        :type response: tornado.web.Response
        """
        error = response.error
        if error is not None:
            error = error.args

        handle = self.save_url_handle(url, response.code, error, response.reason, response.headers, save_immediate=True)
        try:
            handle.write(response.body)
        finally:
            handle.close()

    def save_url_handle(self, url, code, error, reason, headers, save_immediate=False):
        metadata = {"code": code,
                    "error": error,
                    "headers": list(headers.get_all()),
                    "reason": reason
                    }

        assert url not in self.downloads_in_progress_with_metadata

        local_dir = self.get_cache_dir(url)
        if not os.path.isdir(local_dir):
            os.makedirs(local_dir)
        if save_immediate:
            self.save_metadata(url, metadata)
        else:
            self.downloads_in_progress_with_metadata[url] = metadata
        return open(os.path.join(local_dir, "body"), "wb")

    def save_current_download_metadata(self, url):
        metadata = self.downloads_in_progress_with_metadata.pop(url)
        self.save_metadata(url, metadata)
        return metadata

    def save_metadata(self, url, metadata):
        local_dir = self.get_cache_dir(url)
        json_save(os.path.join(local_dir, META_JSON), metadata)
        with self.cache_db_conn:
            self.update_metadata_database_entry(url, metadata)

    def download_remote_service_entry(self, ip, port, url, done_callback):
        proxy_prefix = "http://%s:%d/" % (ip, port)

        def download_complete(response):
            assert isinstance(response, tornado.httpclient.HTTPResponse)
            if 200 <= response.code < 300:
                self.save_url(url, response)
            else:
                print "Proxy download got code %d; ignoring" % response.code
            done_callback()

        headers = tornado.httputil.HTTPHeaders()
        headers.add("Cache-only", "true")
        print "SYNC DOWNLOAD %s from proxy %s:%d" % (url, ip, port)

        fetch_request(proxy_prefix + url, download_complete, headers=headers, request_timeout=REQUEST_TIMEOUT)
        # fetch_request(url, download_complete, proxy_host=ip, proxy_port=port, headers=headers)

    def download_entries(self, ip, port, entries, done_callback, tracker):
        assert isinstance(tracker, LimitTracker)
        tracker.done()
        while tracker.cur_index() < len(entries):
            metadata_record = entries[tracker.cur_index()]
            tracker.next_index()
            url = metadata_record["url"]
            last_modified_epoch = metadata_record["last_modified"]
            if not self.check_existing_entry(url, last_modified_epoch):
                assert not tracker.at_limit()
                self.download_remote_service_entry(ip, port, url, lambda: self.download_entries(ip, port, entries, done_callback, tracker))
                tracker.started(ip, port, url)
                if tracker.at_limit():
                    # we can't start any more downloads right now
                    return
        if tracker.queue_empty():
            done_callback()

    def sync_remote_service(self, ip, port):
        uri_format = "http://%s:%d/mesh-request"

        def handle_response(response):
            """
            :type response: tornado.httpclient.HTTPResponse
           """
            assert isinstance(response, tornado.httpclient.HTTPResponse)

            if response.code == 400:
                print "This proxy does not appear to support this; ignoring"
                return

            content_type = response.headers.get("Content-type")
            if content_type != "application/json":
                assert False, "mesh listing content-type was %s" % content_type
            response_obj = json.loads(response.body)

            entries = response_obj["entries"]
            next_key = response_obj["next_key"]

            def after_entries():
                if next_key is not None:
                    next_page_uri = uri_format % (ip, port) + "?" + urllib.urlencode({"next_key": next_key})

                    print "SYNC FETCHING LISTING %s" % next_page_uri
                    fetch_request(next_page_uri, handle_response)
                else:
                    print "SYNC COMPLETE"

            tracker = LimitTracker(LAUNCH_INITIAL_SYNC_SIMULTANEOUS_DOWNLOADS)
            self.download_entries(ip, port, entries, after_entries, tracker)

        uri = uri_format % (ip, port)

        print "SYNC WITH %s:%d" % (ip, port)
        print "SYNC FETCHING LISTING %s" % uri

        fetch_request(
            uri, handle_response,
            method="GET")

    def on_peer_added(self, ip, port):
        entry = (ip, port)
        if entry not in self.peers:
            self.peers.append(entry)
            self.sync_remote_service(ip, port)

    def on_peer_removed(self, ip, port):
        try:
            self.peers.remove((ip, port))
        except ValueError:
            pass

    def notify_peers_about_new_content(self, url, metadata):
        if len(self.peers) == 0:
            return
        payload_body = {
            "url": url,
            "metadata": metadata,
            "proxy_ip": self.our_ip,
            "proxy_port": self.our_port,
        }
        payload_json = json.dumps(payload_body)
        for peer_ip, port in self.peers:
            print "MESH-NOTIFY %s:%d %s" % (peer_ip, port, url)

            def handle_response(response):
                assert isinstance(response, tornado.httpclient.HTTPResponse)
                if response.code != 200:
                    print "MESH-NOTIFY %s:%d %s failed with %s %s" % (peer_ip, port, url, response.code, response.reason)

            headers = tornado.httputil.HTTPHeaders()
            headers.add("Content-type", "application/json")
            fetch_request("http://%s:%d/mesh-notify" % (peer_ip, port), handle_response, method="POST", body=payload_json, headers=headers)


_proxy_backend = None
""":type: ProxyBackend"""


def init_proxy_backend(our_ip, our_port, proxy_dir, rebuild_db):
    global _proxy_backend
    assert _proxy_backend is None
    _proxy_backend = ProxyBackend(our_ip, our_port, proxy_dir, rebuild_db)
    return _proxy_backend


def get_proxy_backend():
    """:rtype: ProxyBackend"""
    return _proxy_backend


class ParseHelper(object):
    def __init__(self, on_headers_done, debug_sizes=False):
        self.headers = None
        self.response_start_line = None
        self.header_lines = []
        self.on_headers_done = on_headers_done
        self.code = None
        self.reason = None
        self.write_handle = None
        self.error = None
        self.body_size = 0
        self.debug_sizes = debug_sizes
        self.response_handled = False

    def handle_header_line(self, line):
        if len(self.header_lines) >= 1 and line == "\r\n":
            # headers done, toss them
            self.response_start_line = tornado.httputil.parse_response_start_line(self.header_lines[0])

            self.code = self.response_start_line.code
            self.reason = self.response_start_line.reason

            if 400 <= self.code < 600:
                self.error = tornado.web.HTTPError(self.code, reason=self.reason)

            self.headers = tornado.httputil.HTTPHeaders.parse("".join(self.header_lines[1:]))
            if self.on_headers_done is not None:
                self.on_headers_done()
        else:
            self.header_lines.append(line)

    def handle_data_chunk(self, data):
        if self.debug_sizes:
            print "chunk offset %d is len %d chunk sha1 %s" % (self.body_size, len(data), calc_sha1(data))
        if self.write_handle is not None:
            self.write_handle.write(data)
        self.body_size += len(data)


def calc_sha1(data):
    s = hashlib.sha1()
    s.update(data)
    return s.hexdigest()


class ProxyHandler(tornado.web.RequestHandler):
    def __init__(self, *args, **kwargs):
        super(ProxyHandler, self).__init__(*args, **kwargs)
        self.get_count = 0

    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT']

    def data_received(self, chunk):
        # not a streaming mode request handler
        assert False

    def compute_etag(self):
        return None  # disable tornado Etag

    @tornado.web.asynchronous
    def get(self):
        cur_get_num = self.get_count
        # self.request.cur_get_num = cur_get_num
        self.get_count += 1

        def getlog(msg):
            print "%s.get() #%d %s" % (self, cur_get_num, msg)

        getlog("begins")
        getlog('CLIENT REQUEST %s %s' % (self.request.method, self.request.uri))

        gzip_encode_response = any(pattern in self.request.uri for pattern in ALWAYS_SERVE_ENCODED_GZIP)
        compressor = None
        if gzip_encode_response:
            getlog("gzip encoding response")
            compressor = zlib.compressobj()

        def is_cachable_request():
            is_range_request = "Range" in self.request.headers
            if is_range_request:
                getlog('RANGE REQUEST %s %s %s' % (self.request.method, self.request.uri, self.request.headers["Range"]))
            return self.request.method == "GET" and \
                self.request.body == "" and \
                not is_range_request

        def handle_headers_done():
            getlog("headers done")
            getlog("UPSTREAM RESPONSE %s %s %s %s" % (self.request.method, self.request.uri, parse_helper.code, parse_helper.reason))
            if is_cachable_request() and 200 <= parse_helper.code < 300:
                getlog("Saving stream %s %s %s" % (self.request.method, parse_helper.code, self.request.uri))
                parse_helper.write_handle = _proxy_backend.save_url_handle(self.request.uri, parse_helper.code, parse_helper.error, parse_helper.reason, parse_helper.headers)
            elif is_cachable_request() and parse_helper.code == 301:
                new_url = parse_helper.headers.get("Location")
                getlog("Skipping saving stream %s %s %s to %s %s" % (self.request.method, parse_helper.code, parse_helper.reason, new_url, self.request.uri))
            else:
                getlog("Skipping saving stream %s %s %s" % (self.request.method, parse_helper.code, self.request.uri))

            if converted_request_to_conditional and parse_helper.code == 304:
                # We converted a request to conditional and found our cache was up to date
                # so serve the original cache-based response
                getlog("Conditional request passed")
                handle_response(cache_response, loaded_from_cache=True)
                return

            self.set_status(parse_helper.code, parse_helper.reason)
            self._headers = tornado.httputil.HTTPHeaders()  # clear tornado default header

            for header, v in parse_helper.headers.get_all():
                if header in ('Content-Length', 'Transfer-Encoding', 'Content-Encoding', 'Connection'):
                    getlog("Skipping header %s: %s" % (header, v))
                else:
                    self.add_header(header, v)  # some header appear multiple times, eg 'Set-Cookie'

            if gzip_encode_response:
                self.add_header("Content-Encoding", "gzip")

            # if response.body:
            #     self.set_header('Content-Length', len(response.body))
            #     self.write(response.body)

        # debug_sizes = self.request.uri.endswith("/eb240536122cef2bc1bd30437180ce2fd4af02eaad2472884b72716d7eb12c2f")
        debug_sizes = False
        parse_helper = ParseHelper(handle_headers_done, debug_sizes=debug_sizes)

        def handle_data_chunk(data):
            if gzip_encode_response:
                data_to_send = compressor.compress(data)
            else:
                data_to_send = data
            self.write(data_to_send)
            self.flush()
            parse_helper.handle_data_chunk(data)

        def handle_response(response, loaded_from_cache=False):
            getlog("handle_response")
            if parse_helper.response_handled:
                return
            parse_helper.response_handled = True
            if not loaded_from_cache:
                # if self.request.method == "GET" and self.request.body == "" and 200 <= response.code < 300:
                #     print "Saving %s %s %s" % (self.request.method, response.code, self.request.uri)
                #     _proxy_backend.save_url(self.request.uri, response)
                # else:
                #     print "Skipping saving %s %s %s" % (self.request.method, response.code, self.request.uri)

                if parse_helper.write_handle is not None:
                    parse_helper.write_handle.close()
                    parse_helper.write_handle = None
            if response.error and not isinstance(response.error, tornado.httpclient.HTTPError):
                self.set_status(500)
                self.write('Internal server error:\n' + str(response.error))
            elif loaded_from_cache:
                self.set_status(response.code, response.reason)
                self._headers = tornado.httputil.HTTPHeaders()  # clear tornado default header

                for header, v in response.headers.get_all():
                    if header not in ('Content-Length', 'Transfer-Encoding', 'Content-Encoding', 'Connection'):
                        self.add_header(header, v)  # some header appear multiple times, eg 'Set-Cookie'

                if response.body:
                    data_to_send = response.body
                    if gzip_encode_response:
                        self.add_header("Content-Encoding", "gzip")
                        data_to_send = compressor.compress(data_to_send) + compressor.flush()
                    self.set_header('Content-Length', len(data_to_send))
                    WriteBufferFriendlyWrite(self, data_to_send)
                    return
            elif is_cachable_request() and response.error and 400 <= response.code < 600:
                assert not loaded_from_cache
                url = self.request.uri
                print "%s: Error during serving of uncached content: %s" % (url, response.error)
            elif is_cachable_request():
                assert not loaded_from_cache
                if "Content-Length" in response.headers:
                    content_length = int(response.headers["Content-Length"])
                    getlog("%s content-length %d" % (self.request.uri, content_length))
                    if parse_helper.body_size != content_length:
                        print "WARNING content length mismatch got body bytes %d expected content-length %d" % (parse_helper.body_size, content_length)
                url = self.request.uri
                if url in _proxy_backend.downloads_in_progress_with_metadata:
                    metadata = _proxy_backend.save_current_download_metadata(url)
                    _proxy_backend.notify_peers_about_new_content(url, metadata)

            if gzip_encode_response and not loaded_from_cache:
                getlog("blockwise gzip flushing")
                self.write(compressor.flush())

            self.finish()

        body = self.request.body
        if not body:
            body = None

        cache_response = None
        converted_request_to_conditional = False

        if is_cachable_request():

            should_check_cache = True

            headers = self.request.headers
            assert isinstance(headers, tornado.httputil.HTTPHeaders)

            cache_only = "Cache-only" in headers

            if "If-Modified-Since" in headers or "If-None-Match" in headers:
                assert not cache_only
                print "IMS", headers.get("If-Modified-Since"), "INM", headers.get("If-None-Match")
                # always put these through since upstream could have a newer version
                # we want and if it doesn't it is already doing data reduction
                should_check_cache = False

            if any(pattern in self.request.uri for pattern in CACHE_EXCLUDE_PATTERNS):
                should_check_cache = False

            if should_check_cache:
                cache_lookup_uri = self.request.uri
                if cache_only and cache_lookup_uri.startswith("/"):
                    cache_lookup_uri = cache_lookup_uri[1:]
                cache_response = _proxy_backend.get_url(cache_lookup_uri)

                # NB we prefer INM to IMS as suggested by RFC 7232
                # https://stackoverflow.com/a/35169178/60422

                if cache_response is not None:
                    # print cache_response.headers.get_all()

                    if ("Etag" in cache_response.headers or "Last-Modified" in cache_response.headers) and not cache_only:
                        converted_request_to_conditional = True
                        if "Etag" in cache_response.headers:
                            # Make this an INM
                            self.request.headers.add("If-None-Match", cache_response.headers["Etag"])
                        if "Last-Modified" in cache_response.headers:
                            # Make this an IMS
                            self.request.headers.add("If-Modified-Since", cache_response.headers["Last-Modified"])
                    else:
                        print "Using saved %s" % self.request.uri
                        handle_response(cache_response, loaded_from_cache=True)
                        return
                else:
                    assert not cache_only

        try:
            if 'Proxy-Connection' in self.request.headers:
                del self.request.headers['Proxy-Connection']
            fetch_request(
                self.request.uri, handle_response,
                method=self.request.method, body=body,
                headers=self.request.headers, follow_redirects=False,
                request_timeout=REQUEST_TIMEOUT,
                allow_nonstandard_methods=True,
                streaming_callback=handle_data_chunk,
                header_callback=parse_helper.handle_header_line,
                decompress_response=False,
            )
        except tornado.httpclient.HTTPError as e:
            if hasattr(e, 'response') and e.response:
                handle_response(e.response)
            else:
                self.set_status(500)
                self.write('Internal server error:\n' + str(e))
                self.finish()

        getlog("ends")

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


def main():
    port = 8888
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    print ("Starting HTTP proxy on port %d" % port)
    run_proxy(port)


if __name__ == '__main__':
    main()
