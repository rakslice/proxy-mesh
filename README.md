# proxy-mesh #

This is a python-based web proxy for use as a cache for APT repositories (network sources of Ubuntu and Debian packages) for machines on the local LAN.

Debian and derivatives have an included `squid-deb-proxy` pre-packaged APT proxy server set-up which advertises itself using `zeroconf`/`avahi` so that once you install the corresponding `squid-deb-proxy-client` package on clients, they will use the proxy for APT downloads automatically.  `proxy-mesh` is an alternative to `squid-deb-proxy` that works with the same clients running `squid-deb-proxy-client` but doesn't use `squid` for the actual web proxying.

The main reasons I decided I wanted an alternative are:

- I wanted something cross platform (a Windows box is the most convenient almost-always-on box for me to run a service like this on)
- I want to run multiple instances some of the time and have them operate as a mesh -- automatically synchronizing cached files to each other, something that is super not straightforward with squid, so that I can save download bandwidth on updating things even when my main instance on the Windows box is down (for instance dual booting).  

Notes:

- Unlike the stock `squid-deb-proxy` service, this one does not limit source networks to private networks or destination domains to those that are expected to be in the APT `sources.list*`. It's up to you to make sure that you run it inside an appropriately secure network and to correctly configure your `apt` clients' `sources.list*`. 
