import argparse
import json
import socket

import tornado.web
import tornado.ioloop
import tornado.template
import zeroconf

from proxy import ProxyHandler, init_proxy_backend, get_proxy_backend
from utils import get_ip


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", "-p", type=int, help="TCP port to listen on", default=8000)
    parser.add_argument("--proxy-dir", help="A place to put the proxy data")
    parser.add_argument("--rebuild-db", default=False, action="store_true", help="Rebuild the database of download metadata")

    return parser.parse_args()


class MeshRequestHandler(tornado.web.RequestHandler):

    PAGE_LIMIT = 26

    def get(self, slug):
        next_key = self.get_argument("next_key", None)

        backend = get_proxy_backend()
        entries, next_key = backend.list_entries(self.PAGE_LIMIT, next_key)

        self.add_header("Content-type", "application/json")
        self.finish(json.dumps({"entries": entries, "next_key": next_key}))


def main():
    options = parse_args()
    port = options.port

    print "Getting IP"
    ip = get_ip()

    print "Setting up IP on zeroconf (for avahi access)"
    ad = Advertisement()
    ad.advertise_proxy("_apt_proxy._tcp.local.", ip, port)
    try:

        print "Starting HTTP proxy on port %d" % port
        rebuild_db = options.rebuild_db
        run_proxy(options.proxy_dir, port, rebuild_db=rebuild_db)

    finally:
        ad.close()


class Advertisement(object):

    def __init__(self):
        self.zc = zeroconf.Zeroconf()
        self.info_entries = []

        self.our_ip = None
        self.browser = zeroconf.ServiceBrowser(self.zc, "_apt_proxy._tcp.local.", self)

    def close(self):
        self.cancel_our_ads()
        self.browser.cancel()
        if self.zc is not None:
            self.zc.close()
            self.zc = None

    def advertise_proxy(self, service_type, ip, port):
        name = "Bonk._apt_proxy._tcp.local."
        print "zeroconf service type name " + zeroconf.service_type_name(name)
        desc = {}
        self.our_ip = socket.inet_aton(ip)
        info = zeroconf.ServiceInfo(service_type, name, self.our_ip, port, 0, 0, desc, "Bonk.local.")
        self.zc.register_service(info)
        self.info_entries.append(info)

    def remove_service(self, zeroconf, type, name):
        print("Service %s removed" % (name,))

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        print("Service %s added, service info: %s" % (name, info))
        if info.address != self.our_ip:
            self.on_remote_service_added(socket.inet_ntoa(info.address), info.port)

    def on_remote_service_added(self, ip, port):
        backend = get_proxy_backend()
        backend.sync_remote_service(ip, port)

    def cancel_our_ads(self):
        infos = self.info_entries
        self.info_entries = []
        for info in infos:
            self.zc.unregister_service(info)


class MeshProxyHandler(ProxyHandler):
    def __init__(self, *args, **kwargs):
        super(MeshProxyHandler, self).__init__(*args, **kwargs)


def run_proxy(proxy_dir, port_val, start_ioloop=True, rebuild_db=False):
    """
    Run proxy on the specified port. If start_ioloop is True (default),
    the tornado IOLoop will be started immediately.
    """
    init_proxy_backend(proxy_dir, rebuild_db)
    app = tornado.web.Application([
        # routes
        (r"/mesh-request/(.+)", MeshRequestHandler),
        (r'.*', MeshProxyHandler),
    ])
    app.listen(port_val)
    ioloop = tornado.ioloop.IOLoop.instance()
    if start_ioloop:
        ioloop.start()


if __name__ == "__main__":
    main()
