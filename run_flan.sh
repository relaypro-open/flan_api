#!/bin/bash
source /opt/flan_api/flan_api_venv/bin/activate
export FLASK_RUN_PORT=5001 
export FLASK_APP=flan_scan_api.py 

flask run
