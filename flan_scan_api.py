from flask import Flask, escape, request, redirect
import sys
import json
import urllib.request as urllib
import os
import glob
import xmltodict
import boto3
from datetime import datetime as DT
from datetime import timedelta as TD
import hashlib

app = Flask(__name__)

context_root = "/flan_api"

@app.route(context_root + '/<location>/<env>/<content>')
def get_s3_object(location, env, content):
    try:
        client = boto3.client('s3')
        response = client.get_object(
                Bucket='flan-scans',
                Key='flan_api/' + location + '/' + env + '/' + content)['Body'].read()
        return response
    except ClientError as e:
        print(e)
        return json.dumps(e)

@app.route(context_root + '/list_s3_objects')
def list_objects():
    environment_prefix = os.environ.get('ENV_PREFIX', '')
    client = boto3.client('s3')
    response = client.list_objects_v2(
            Bucket='flan-scans',
            Prefix=environment_prefix)['Contents']

    get_last_modified = lambda obj: int(obj['LastModified'].strftime('%s'))
    return sorted(response, key=get_last_modified, reverse=True)[0]
