#!/bin/bash
set -e -x

sudo apt-get install python-virtualenv python-dev
virtualenv ~/proxy-mesh-virtualenv
~/proxy-mesh-virtualenv/bin/pip install -r requirements.txt


