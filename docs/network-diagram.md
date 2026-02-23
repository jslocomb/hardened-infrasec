# Network Diagram

## Logical Topology

```
Internet / Home Router (192.168.1.1)
        │
        │ vmbr0 (Proxmox management)
        │
┌───────▼────────────────────────────────────────────────────────────┐
│  PROXMOX HOST  (192.168.1.x mgmt / 192.168.10.x lab)              │
│                                                                    │
│  vmbr1 ── Lab Bridge 192.168.10.0/24                              │
│      │                                                             │
│      ├── ipa01          192.168.10.5    FreeIPA                    │
│      ├── k8s-cp01       192.168.10.10   K8s Control Plane          │
│      ├── k8s-w01        192.168.10.11   K8s Worker 1               │
│      ├── k8s-w02        192.168.10.12   K8s Worker 2               │
│      └── k8s-w03        192.168.10.13   K8s Worker 3               │
│                                                                    │
│  MetalLB Pool: 192.168.10.200-220                                  │
│      └── 192.168.10.200  ← ingress-nginx LoadBalancer IP           │
│                            (All *.lab.internal A records → .200)   │
└────────────────────────────────────────────────────────────────────┘
```

## K8s Internal Network

```
Pod CIDR:     10.42.0.0/16   (Canal/Flannel default)
Service CIDR: 10.43.0.0/16
DNS:          10.43.0.10     (CoreDNS)
```

## DNS Flow

```
Client browser resolves awx.lab.internal
        │
        ▼
FreeIPA DNS (192.168.10.5)
        │
        ▼ Returns 192.168.10.200 (MetalLB ingress IP)
        │
        ▼
ingress-nginx (192.168.10.200:443)
        │  SNI routing on awx.lab.internal
        ▼
AWX Service (devops namespace, ClusterIP)
        │
        ▼
AWX Pod
```

## Port Reference

| Port | Protocol | Service | Direction |
|---|---|---|---|
| 22 | TCP | SSH | Management → All VMs |
| 80/443 | TCP | HTTP/HTTPS | Clients → ingress |
| 389/636 | TCP | LDAP/LDAPS | Cluster → FreeIPA |
| 88 | TCP/UDP | Kerberos | Cluster → FreeIPA |
| 6443 | TCP | K8s API | Workers → Control Plane |
| 9345 | TCP | RKE2 Supervisor | Workers → Control Plane |
| 2379-2380 | TCP | etcd | Internal CP only |
| 10250 | TCP | Kubelet | Control Plane → Workers |
| 8472 | UDP | VXLAN (Canal) | Workers ↔ Workers |
| 9500-9502 | TCP | Longhorn | Workers ↔ Workers |
