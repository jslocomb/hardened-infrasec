#!/bin/bash
TOKEN="MljKpd4FZz3pklFqkkuZzJBQE5WHIglKKsf4Vxpe"
BASE="http://localhost:8080/api"

post() {
  curl -s -X POST "$BASE/$1/" \
    -H "Authorization: Token $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$2" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('name','?'), '-> id:', d.get('id','ERROR'), d.get('detail',''))"
}

echo "=== Adding devices ==="
post "dcim/devices" '{"name":"k8s-w01","device_type":1,"role":2,"platform":1,"site":1,"status":"active"}'
post "dcim/devices" '{"name":"k8s-w02","device_type":1,"role":2,"platform":1,"site":1,"status":"active"}'

echo "=== Adding IP addresses ==="
post "ipam/ip-addresses" '{"address":"10.0.10.113/24","status":"active","dns_name":"ipa01.lab.internal","description":"ipa01"}'
post "ipam/ip-addresses" '{"address":"10.0.10.146/24","status":"active","dns_name":"k8s-cp01.lab.internal","description":"k8s-cp01"}'
post "ipam/ip-addresses" '{"address":"10.0.10.227/24","status":"active","dns_name":"k8s-w01.lab.internal","description":"k8s-w01"}'
post "ipam/ip-addresses" '{"address":"10.0.10.117/24","status":"active","dns_name":"k8s-w02.lab.internal","description":"k8s-w02"}'

echo "=== Done ==="
echo "Devices in NetBox:"
curl -s "$BASE/dcim/devices/?limit=10" \
  -H "Authorization: Token $TOKEN" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); [print(x['name'], x['role']['name']) for x in d['results']]"
