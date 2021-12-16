#!/bin/bash

apt-get install python3-venv
python3 -m venv flan_api_venv
source ./flan_api_venv/bin/activate
pip install -r ./requirements.txt
cp flan_api.service /lib/systemd/system/
systemctl daemon-reload
