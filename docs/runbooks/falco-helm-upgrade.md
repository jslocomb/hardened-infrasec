# Falco Helm Upgrade Runbook

After any `helm upgrade` of the Falco release, the `falco-falcosidekick`
secret is reset by Helm and `SPLUNK_TOKEN` is blanked out. Run this
patch immediately after every upgrade.

## Step 1 — Patch the secret
```bash
ssh k8s-cp01 "sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  -n falco patch secret falco-falcosidekick \
  --type=json \
  -p='[{\"op\":\"replace\",\"path\":\"/data/SPLUNK_TOKEN\",\"value\":\"ZWNiNDI1ZGItYmM3ZS00MTZjLWJhMDAtMGFjYzVlNmQ5ZDcx\"}]'"
```

## Step 2 — Bounce falcosidekick pods
```bash
ssh k8s-cp01 "sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  -n falco delete pods -l app.kubernetes.io/name=falcosidekick"
```

## Step 3 — Verify
```bash
sleep 30 && ssh k8s-cp01 "sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  -n falco logs deployment/falco-falcosidekick --tail=5"
```

Expected: `Enabled Outputs: [Splunk]` followed by `POST OK (200)` within 60s.

## Token reference

The base64 value `ZWNiNDI1ZGItYmM3ZS00MTZjLWJhMDAtMGFjYzVlNmQ5ZDcx`
decodes to the HEC token stored in `pass Lab/falco/falco-token`.

## Full upgrade command
```bash
scp k8s/falco/falcosidekick-values.yaml k8s-cp01:/tmp/
scp k8s/falco/custom_rules.yaml k8s-cp01:/tmp/

ssh k8s-cp01 "sudo /usr/local/bin/helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true \
  --set falco.http_output.enabled=true \
  --set falco.http_output.url=http://falco-falcosidekick:2801 \
  --set falco.json_output=true \
  --set falcoctl.artifact.install.enabled=false \
  --set falcoctl.artifact.follow.enabled=false \
  --set tty=true \
  --set falcosidekick.existingSecret=falcosidekick-splunk-token \
  --set falcosidekick.config.splunk.host='https://10.0.10.117:8088/services/collector/event' \
  --set falcosidekick.config.splunk.checkcert=false \
  --set falcosidekick.config.splunk.minimumpriority=notice \
  --set falcosidekick.config.splunk.index=falco_alerts \
  --set falcosidekick.config.splunk.sourcetype=falco \
  --set 'extraConfigMaps.falco-custom-rules=/etc/falco/rules.d' \
  --values /tmp/falcosidekick-values.yaml \
  --timeout 10m"
```

Then run Steps 1-3 above.
