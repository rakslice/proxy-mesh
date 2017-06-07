import argparse
import socket

import tornado.web
import tornado.ioloop
import tornado.template
import zeroconf

from proxy import ProxyHandler, init_proxy_backend
from utils import get_ip


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", "-p", type=int, help="TCP port to listen on", default=8000)
    parser.add_argument("--proxy-dir", help="A place to put the proxy data")

    return parser.parse_args()


class MeshRequestHandler(tornado.web.RequestHandler):
    def get(self, slug):
        pass


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
        run_proxy(options.proxy_dir, port)

    finally:
        ad.cancel_our_ads()


class Advertisement(object):

    def __init__(self):
        self.zc = zeroconf.Zeroconf()
        self.info_entries = []

    def advertise_proxy(self, service_type, ip, port):
        name = "Bonk._apt_proxy._tcp.local."
        print "ztn " + zeroconf.service_type_name(name)
        desc = {}
        info = zeroconf.ServiceInfo(service_type, name, socket.inet_aton(ip), port, 0, 0, desc, "Bonk.local.")
        self.zc.register_service(info)
        self.info_entries.append(info)

    def cancel_our_ads(self):
        infos = self.info_entries
        self.info_entries = []
        for info in infos:
            self.zc.unregister_service(info)


def run_proxy(proxy_dir, port_val, start_ioloop=True):
    """
    Run proxy on the specified port. If start_ioloop is True (default),
    the tornado IOLoop will be started immediately.
    """
    init_proxy_backend(proxy_dir)
    app = tornado.web.Application([
        # routes
        (r"/mesh-request/(.+)", MeshRequestHandler),
        (r'.*', ProxyHandler),
    ])
    app.listen(port_val)
    ioloop = tornado.ioloop.IOLoop.instance()
    if start_ioloop:
        ioloop.start()


if __name__ == "__main__":
    main()
