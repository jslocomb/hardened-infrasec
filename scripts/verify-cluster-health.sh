#!/bin/bash
# verify-cluster-health.sh
# Post-deployment sanity checks for the full homelab stack.
set -uo pipefail

PASS=0
FAIL=0

check() {
  local desc="$1"
  local cmd="$2"
  if eval "$cmd" &>/dev/null; then
    echo "  ✅ $desc"
    ((PASS++))
  else
    echo "  ❌ $desc"
    ((FAIL++))
  fi
}

echo ""
echo "═══════════════════════════════════════════"
echo "  Homelab K8s Cluster Health Check"
echo "═══════════════════════════════════════════"

echo ""
echo "── Nodes ─────────────────────────────────"
check "Control plane ready" "kubectl get node k8s-cp01.lab.internal | grep Ready"
check "Worker 1 ready"      "kubectl get node k8s-w01.lab.internal | grep Ready"
check "Worker 2 ready"      "kubectl get node k8s-w02.lab.internal | grep Ready"
check "Worker 3 ready"      "kubectl get node k8s-w03.lab.internal | grep Ready"

echo ""
echo "── Core Services ─────────────────────────"
check "CoreDNS running"     "kubectl -n kube-system get deploy coredns | grep -E '[1-9]/[1-9]'"
check "MetalLB running"     "kubectl -n metallb-system get deploy controller | grep -E '[1-9]/[1-9]'"
check "ingress-nginx running" "kubectl -n ingress-nginx get deploy ingress-nginx-controller | grep -E '[1-9]/[1-9]'"
check "cert-manager running" "kubectl -n cert-manager get deploy cert-manager | grep -E '[1-9]/[1-9]'"
check "Longhorn running"    "kubectl -n longhorn-system get deploy longhorn-manager | grep -E '[1-9]/[1-9]'"

echo ""
echo "── Applications ──────────────────────────"
check "GitLab CE running"   "kubectl -n devops get deploy gitlab-webservice-default 2>/dev/null | grep -E '[1-9]/[1-9]'"
check "AWX web running"     "kubectl -n devops get deploy awx-web 2>/dev/null | grep -E '[1-9]/[1-9]'"
check "Prometheus running"  "kubectl -n monitoring get statefulset prometheus-kube-prometheus-stack-prometheus | grep -E '[1-9]/[1-9]'"
check "Grafana running"     "kubectl -n monitoring get deploy kube-prometheus-stack-grafana | grep -E '[1-9]/[1-9]'"
check "Zabbix web running"  "kubectl -n monitoring get deploy zabbix-zabbix-web 2>/dev/null | grep -E '[1-9]/[1-9]'"
check "NetBox running"      "kubectl -n netops get deploy netbox 2>/dev/null | grep -E '[1-9]/[1-9]'"
check "Splunk running"      "kubectl -n logging get statefulset splunk-standalone-standalone 2>/dev/null | grep -E '[1-9]/[1-9]'"

echo ""
echo "── Storage ───────────────────────────────"
check "Longhorn default StorageClass" "kubectl get storageclass longhorn | grep '(default)'"
check "No pending PVCs" "[[ \$(kubectl get pvc --all-namespaces | grep Pending | wc -l) -eq 0 ]]"

echo ""
echo "── Ingress ───────────────────────────────"
check "Ingress has LoadBalancer IP" "kubectl -n ingress-nginx get svc ingress-nginx-controller | grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'"
check "AWX ingress exists"    "kubectl -n devops get ingress awx-ingress"
check "GitLab ingress exists" "kubectl -n devops get ingress gitlab-ingress"
check "Grafana ingress exists" "kubectl -n monitoring get ingress grafana-ingress"

echo ""
echo "═══════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════"
echo ""

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
