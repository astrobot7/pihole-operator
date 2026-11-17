# pihole-operator

A Kubernetes operator that runs [Pi-hole](https://pi-hole.net) v6 as a set of replicas behind one DNS Service and configures all of them from custom resources.

Pi-hole has no clustering of its own: each instance keeps its own gravity database and settings. The operator treats the CRs as the source of truth and pushes the same configuration to every replica through the Pi-hole v6 REST API. It re-checks each replica on an interval, so changes made in a replica's web UI get reverted.

## Custom resources

| Kind | Short name | What it does |
|---|---|---|
| `PiholeCluster` | `phc` | The deployment: replicas, image, upstream DNS, Services, storage, extra `pihole.toml` settings and an optional pod template |
| `PiholeBlocklist` | `phbl` | Adlist subscriptions (block or allow), optionally scoped to groups |
| `PiholeDomainList` | `phdl` | Exact or regex allow/deny rules |
| `PiholeLocalRecord` | `phlr` | Local A/AAAA and CNAME records |
| `PiholeGroup` | `phg` | A group and the clients (IP, CIDR, MAC, hostname, `:interface`) assigned to it |

Configuration objects point at their cluster with `spec.clusterRef.name` and must live in the same namespace.

```yaml
apiVersion: pihole.io/v1alpha1
kind: PiholeCluster
metadata:
  name: home
spec:
  replicas: 2
  upstreams: [1.1.1.1, 9.9.9.9]
  dnsService:
    type: LoadBalancer
    externalTrafficPolicy: Local   # keeps client IPs visible to Pi-hole
---
apiVersion: pihole.io/v1alpha1
kind: PiholeBlocklist
metadata:
  name: ads
spec:
  clusterRef: {name: home}
  lists:
    - url: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt
```

More examples are in [`config/samples`](config/samples).

## How it works

- Each replica is a pod in a StatefulSet with its own PVC for `/etc/pihole` (default 1Gi; set `storage.size: "0"` for an emptyDir).
- Settings that need a restart (upstreams, timezone, `spec.ftl` keys) are passed as `FTLCONF_*` environment variables, which also makes them read-only in the web UI. Changing them rolls the pods one at a time. A `preStop` delay keeps each pod answering until kube-proxy stops sending it traffic, so rollouts don't drop queries.
- Lists, domains, groups, clients and local records go through the API without restarts. When lists are added or removed, the operator rebuilds gravity on one replica at a time.
- Every entry the operator creates carries `managed by pihole-operator` in its comment. With the default `prunePolicy: ManagedOnly`, entries without that marker (including the StevenBlack list the image ships with) are left alone. `prunePolicy: All` removes anything not declared in a CR.
- The operator generates the admin password into `<cluster>-admin` unless you set `adminPasswordSecretRef`.

### Groups and clients

Pi-hole keeps every client in the built-in `Default` group, so Default lists apply to everyone. A `PiholeGroup` with `excludeFromDefault: true` takes its clients out of Default, leaving only the lists and rules tagged with that group (via `spec.groups` on a blocklist or domain list). Name a group `Default` to assign clients to the built-in group explicitly.

### Pod template

`spec.podTemplate` is strategic-merged over the generated pod template. Containers, volumes and env vars merge by name, so you can patch the `pihole` container, add sidecars or set scheduling and security settings. The operator always keeps control of the selector labels, the `pihole.io/config-hash` annotation and the admin password variable. Setting `affinity` replaces the default anti-affinity across nodes. [`pihole_v1alpha1_piholecluster_exporter.yaml`](config/samples/pihole_v1alpha1_piholecluster_exporter.yaml) adds a Prometheus exporter sidecar this way.

## Status, events and metrics

`kubectl get phc` shows ready replicas and a `Synced` condition. `status.replicas` has per-pod sync state, and every configuration CR gets its own `Synced` condition. The operator records events on the `PiholeCluster` for applied changes, sync failures and gravity rebuilds, with the pod as the related object.

The operator's metrics endpoint exports:

| Metric | Type |
|---|---|
| `pihole_operator_replica_syncs_total{result}` | counter |
| `pihole_operator_sync_changes_total` | counter |
| `pihole_operator_gravity_rebuilds_total{result}` | counter |
| `pihole_operator_gravity_duration_seconds` | histogram |
| `pihole_operator_replicas_ready` | gauge |
| `pihole_operator_replicas_synced` | gauge |
| `pihole_operator_cluster_synced` | gauge |

All carry `namespace` and `cluster` labels.

## Install

Requires Kubernetes 1.31 or later (the CRDs use the CEL `isIP()` function) and Pi-hole 2025.x (v6). Pi-hole v5 is not supported.

```sh
make docker-build docker-push IMG=<registry>/pihole-operator:<tag>
make deploy IMG=<registry>/pihole-operator:<tag>
kubectl create namespace dns
kubectl -n dns apply -k config/samples
```

The `PiholeCluster` CRD embeds the full pod template schema and is larger than client-side `kubectl apply` allows, so apply the CRDs with `--server-side`. The Makefile targets already do.

## Development

```sh
make test   # unit tests and envtest controller tests
make lint
```

The API client and sync engine also have contract tests against a real Pi-hole:

```sh
docker run -d -p 18080:80 -e FTLCONF_webserver_api_password=pw pihole/pihole:2025.11.0
PIHOLE_TEST_URL=http://localhost:18080 PIHOLE_TEST_PASSWORD=pw go test ./internal/piholeapi ./internal/piholesync
```

| Path | Contents |
|---|---|
| `api/v1alpha1` | CRD types |
| `internal/piholeapi` | Pi-hole v6 REST client, plus an in-memory fake for tests |
| `internal/piholesync` | Builds the desired state from CRs and converges one Pi-hole to it |
| `internal/controller` | Workload management, per-pod sync, gravity sequencing, status, events and metrics |

## Limitations

- DHCP is not managed. Several replicas handing out leases would conflict.
- Query logs and statistics are per replica. Use an exporter sidecar to collect them.
- Behind a ClusterIP Service or `externalTrafficPolicy: Cluster`, Pi-hole may see node IPs instead of client IPs, which breaks per-client groups. Use a LoadBalancer with `externalTrafficPolicy: Local`.

## License

Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
