#!/usr/bin/env python3
"""NetBox dynamic inventory script for AWX"""
import os
import sys
import json
import urllib.request

NETBOX_API = os.environ.get('NETBOX_API', 'http://netbox.netbox.svc.cluster.local')
NETBOX_TOKEN = os.environ.get('NETBOX_TOKEN', '')

def get_headers():
    h = {'Content-Type': 'application/json'}
    if NETBOX_TOKEN:
        h['Authorization'] = f'Token {NETBOX_TOKEN}'
    return h

def get_devices():
    req = urllib.request.Request(
        f'{NETBOX_API}/api/dcim/devices/?limit=100',
        headers=get_headers()
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())['results']

def build_inventory():
    devices = get_devices()
    inventory = {
        'all': {'hosts': [], 'children': []},
        '_meta': {'hostvars': {}}
    }
    groups = {}

    for d in devices:
        name = d['name']
        role = d['role']['slug']

        inventory['all']['hosts'].append(name)

        if role not in groups:
            groups[role] = {'hosts': []}
        groups[role]['hosts'].append(name)

        inventory['_meta']['hostvars'][name] = {
            'netbox_id': d['id'],
            'netbox_status': d['status']['value'],
            'netbox_role': role,
            'netbox_site': d['site']['name'] if d['site'] else '',
        }

    inventory.update(groups)
    return inventory

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--host':
        print(json.dumps({}))
    else:
        print(json.dumps(build_inventory(), indent=2))
