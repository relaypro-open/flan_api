from flask import Flask, escape, request
import sys
import json
import urllib.request as urllib
import os
import glob
import xmltodict
import boto3
from datetime import datetime as DT
from datetime import timedelta as TD

app = Flask(__name__)

context_root = "/flan_api"

response = open('./config.json', 'r')
config = json.loads(response.read())
response.close()

s3_bucket = config['s3_bucket']

@app.route(context_root + '/flan_scans')
def parse_scans():
    flan_scan = FlanScan()
    return flan_scan.results

@app.route(context_root + '/vulners_by_hostname')
def vulners_by_hostname():
    flan_scan = VulnersByHostname()
    flan_scan.parse_scan()
    return flan_scan.results

@app.route(context_root + '/flan_ips')
def parse_ips():
    flan_ips = FlanIps()
    flan_ips.parse_scan()
    return flan_ips.results

@app.route(context_root + '/list_s3_objects')
def list_objects():
    client = boto3.client('s3')
    response = client.list_objects_v2(
            Bucket=s3_bucket)['Contents']

    get_last_modified = lambda obj: int(obj['LastModified'].strftime('%s'))
    return sorted(response, key=get_last_modified, reverse=True)[0]

def create_host_dict():
    hosts = []
    env = str(os.getenv('DOG_ENV'))
    d = {}

    try:

        if ("url" in config):
            response = urllib.urlopen(config['url'])
            hosts = response.readlines()
            for line in hosts:
                try:
                    [ip, hostname] = line.decode('utf-8').rstrip().split()
                    if "-" + env + "-" in hostname:
                        d[ip] = hostname
                except ValueError:
                    continue
        elif ("file" in config):
            response = open(config['file'], 'r')
            hosts = response.read().split('\n')
            for line in hosts:
                try:
                    [ip, hostname] = line.rstrip().split()
                    if "-" + env + "-" in hostname:
                        d[ip] = hostname
                except ValueError:
                    continue
            response.close()
        else:
            print("the hosts_type and hosts_location configs are missing....exiting")
            sys.exit(1)

    except FileNotFoundError:
        print("there is not configuration file pointing to hosts source....exiting")
        sys.exit(1)


    return d

class VulnersByHostname:
    def __init__(self):
        self.hosts_dict = create_host_dict()
        self.results = {}
        self.flan_scan = FlanScan()
        #self.flan_scan.parse_results()

    def parse_scan(self):
        for app in self.flan_scan.results.keys():
            ip_list = self.flan_scan.results[app]['locations']
            for ip in ip_list.keys():
                if (ip in self.hosts_dict):
                    print(self.hosts_dict[ip])
                    if (app in self.results):
                        self.results[app]['locations'][self.hosts_dict[ip]] = self.flan_scan.results[app]['locations'][ip]
                    else:
                        print(self.flan_scan.results[app])
                        if ('vulns' in self.flan_scan.results[app]):
                            self.results[app] = {'locations': {self.hosts_dict[ip]: self.flan_scan.results[app]['locations'][ip]}, 'vulns': self.flan_scan.results[app]['vulns']}


class FlanIps:
    def __init__(self):
        self.hosts_dict = create_host_dict()
        self.results = {}
        self.flan_scan = FlanScan()
        #self.flan_scan.parse_results()

    def parse_scan(self):
        for app in self.flan_scan.results.keys():
            ip_list = self.flan_scan.results[app]['locations']
            for ip in ip_list.keys():
                vulns = []
                if ('vulns' in self.flan_scan.results[app]):
                    vulns = self.flan_scan.results[app]['vulns']
                data = {'ip': ip,
                        'port': ip_list[ip],
                        'app': app,
                        'vulns': vulns} 
                if (ip in self.hosts_dict):
                    if (self.hosts_dict[ip] in self.results):
                        self.results[self.hosts_dict[ip]].append(data)
                    else:
                        self.results[self.hosts_dict[ip]] = [data]


class FlanScan:
    def __init__(self):
        self.results = {}
        self.vulnerable_services = []
        f = self.get_flan_scan()
        self.data = xmltodict.parse(f)
        self.parse_results()

    def get_flan_scan(self):
        client = boto3.client('s3')

        today = DT.utcnow()
        latest_scan = None
        
        get_last_modified = lambda obj: int(obj['LastModified'].strftime('%s'))

        for i in range(7):
            date_prefix = (today - TD(days=i)).strftime("%Y.%m.%d")

            objects = client.list_objects_v2(
                    Prefix=date_prefix,
                    Bucket='flan-scans')

            if( 'Contents' in objects ):
                latest_scan = sorted(objects['Contents'], key=get_last_modified, reverse=True)[0]['Key']
                break
            
        if (latest_scan == None):
            objects = client.list_objects_v2(
                    Bucket='flan-scans')['Contents']

            latest_scan = sorted(objects, key=get_last_modified, reverse=True)[0]['Key']

        response = client.get_object(
                Bucket='flan-scans',
                Key=latest_scan)['Body'].read()
        return response
    
    def parse_vuln(self, ip_addr, port, app_name, vuln):
        vuln_name = ''
        severity = ''
        type = ''
        for field in vuln:
            if field['@key'] == 'cvss':
                severity = float(field['#text'])
            elif field['@key'] == 'id':
                vuln_name = field['#text']
            elif field['@key'] == 'type':
                type = field['#text']
        vuln = {'app': app_name,
                'name': vuln_name,
                'type': type,
                'severity': severity,
                'description': self.get_description(vuln_name, type)}
        if 'vulns'in self.results[app_name].keys():
            self.results[app_name]['vulns'].append(vuln)
        else:
            self.results[app_name]['vulns'] = [vuln]
    
    
    def parse_script(self, ip_addr, port, app_name, script):
        if 'table' in script.keys():
            self.vulnerable_services.append(app_name)
            script_table = script['table']['table']
            if isinstance(script_table, list):
                for vuln in script_table:
                    self.parse_vuln(ip_addr, port, app_name, vuln['elem'])
            else:
                self.parse_vuln(ip_addr, port, app_name, script_table['elem'])
        else:
            print('ERROR in script: ' + script['@output'] + " at location: " + ip_addr + " port: " + port + " app: " + app_name)
    
    
    def get_app_name(self, service):
        app_name = ''
        if '@product' in service.keys():
            app_name += service['@product'] + " "
            if '@version' in service.keys():
                app_name += service['@version'] + " "
        elif '@name' in service.keys():
            app_name += service['@name'] + " "
    
        if('cpe' in service.keys()):
            if isinstance(service['cpe'], list):
                for cpe in service['cpe']:
                    app_name += '(' + cpe + ")"
            else:
                app_name += '(' + service['cpe'] + ")"
        return app_name
    
    
    def parse_port(self, ip_addr, port):
        connection_state = ' (' + port['@protocol'] + ", " + port['state']['@state'] + ', ' + port['state']['@reason'] + ')'
        app_name = "undefined"
        if 'service' in port:
            app_name = self.get_app_name(port['service'])
    
        port_num = port['@portid']
    
        if app_name in self.results.keys():
            if ip_addr in self.results[app_name]['locations'].keys():
                self.results[app_name]['locations'][ip_addr].append(port_num + connection_state)
            else:
                self.results[app_name]['locations'][ip_addr] = [port_num + connection_state]
        else:
            self.results[app_name] = {'locations': {ip_addr: [port_num + connection_state]}}
            if 'script' in port.keys():
                scripts = port['script']
                if isinstance(scripts, list):
                    for s in scripts:
                        if s['@id'] == 'vulners':
                            self.parse_script(ip_addr, port_num, app_name, s)
                else:
                    if scripts['@id'] == 'vulners':
                        self.parse_script(ip_addr, port_num, app_name, scripts)
    
    
    def parse_host(self, host):
        addresses = host['address']
        if isinstance(addresses, list):
            for addr in addresses:
                if "ip" in addr['@addrtype']:
                    ip_addr = addr['@addr']
        else:
            ip_addr = addresses['@addr']
    
        if host['status']['@state'] == 'up' and 'port' in host['ports'].keys():
            ports = host['ports']['port']
            if isinstance(ports, list):
                for p in ports:
                    self.parse_port(ip_addr, p)
            else:
                self.parse_port(ip_addr, ports)
    
    
    def parse_results(self):
        if 'host' in self.data['nmaprun'].keys():
            hosts = self.data['nmaprun']['host']
    
            if isinstance(hosts, list):
                for h in hosts:
                    self.parse_host(h)
            else:
                self.parse_host(hosts)
    
    
    def convert_severity(sev):
        if sev < 4:
            return 'Low'
        elif sev < 7:
            return 'Medium'
        else:
            return 'High'
    
    
    def get_description(self, vuln, type):
        if type == 'cve':
            year = vuln[4:8]
            section = vuln[9:-3] + 'xxx'
            url = """https://raw.githubusercontent.com/CVEProject/cvelist/master/{}/{}/{}.json""".format(year, section, vuln)
            cve_json = json.loads(urllib.urlopen(url).read().decode("utf-8"))
            return cve_json["description"]["description_data"][0]["value"]
        else:
            return ''

if __name__ == "__main__":
        app.run()
