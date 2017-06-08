# proxy-mesh #

This is a python-based web proxy for use as a cache for APT repositories (network sources of Ubuntu and Debian packages) for machines on the local LAN.

It's an alternative to the `squid-deb-proxy` package set-up which uses `squid` for proxying, and client machines will pick it up automatically using `zeroconf`/`avahi` once you install the stock `squid-deb-proxy-client` package on them.

The main reasons I decided I wanted an alternative are:

- It's cross platform (a Windows box is the most convenient almost-always-on box for me to run a service like this on)
- I want to run multiple instances some of the time and have them operate as a mesh -- automatically synchronizing cached files to each other, something that is not super straightforward with squid, so that I can save download bandwidth on updating things even when my main instance on the Windows box is down (for instance dual booting).  

Notes:

- Unlike the stock `squid-deb-proxy` service, this one does not limit source networks to private networks or destination domains to those that are expected to be in the APT `sources.list*`. It's up to you to make sure that you run it inside an appropriately secure network and to correctly configure your `apt` clients' `sources.list*`. 