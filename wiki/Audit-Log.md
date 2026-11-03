# Audit log detections (`--audit-log`)

The eBPF probe sees what runs on a node; the API server's audit log sees what
is done **to the cluster**. `watch --audit-log <PATH>` follows that log (like
`tail -F`: appends, rotation, truncation) and emits a `source: "k8s-audit"`,
`kind: "audit"` event for what an attack looks like, never the stream itself.

```bash
sudo k3sec watch --audit-log /var/log/k3s-audit.log            # k3s
sudo k3sec watch --audit-log /var/log/kubernetes/audit/audit.log # kubeadm (your --audit-log-path)
sudo k3sec watch --audit-log /var/log/audit/kube/kube-apiserver.log  # Talos, on by default
sudo k3sec watch --audit-log ./audit.log --rollback             # an existing log, from its start
```

| Detection | Severity | MITRE |
|-----------|----------|-------|
| An anonymous request on a resource went through (not `/healthz`, not a 401/403) | critical | T1078.001 |
| A `cluster-admin` (Cluster)RoleBinding created or updated | critical | T1098 |
| A pod or workload (Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob) with `hostPID` / `hostNetwork` / `hostIPC`, a privileged container, `SYS_ADMIN` / `SYS_PTRACE` / `SYS_MODULE` / `ALL`, or a hostPath of `/`, `/etc`, `/proc`, `/root`, `/run`, `/var/lib/kubelet` or a runtime socket | critical | T1611 |
| `nodes/proxy`: the kubelet API through the API server | critical | T1609 |
| `exec` / `attach` into a pod | warning | T1609 |
| `port-forward` to a pod | warning | T1572 |
| Secrets listed or watched | warning | T1552.007 |
| A service account token minted (`kubectl create token`) | warning | T1528 |
| A service account enumerating its permissions (`auth can-i --list`) | warning | T1613 |
| A service account denied (403): a stolen token probing | warning | T1613 |
| Events deleted | warning | T1070 |

The control plane's own users (`system:kube-controller-manager`,
`system:k3s-supervisor`, `system:node:*`, kube-system's service accounts) are
left out where they do this all day (secrets, tokens, the pods a DaemonSet
makes: judged on the DaemonSet). `system:admin`, k3s's admin, is not. With
`--as`, a request is judged as the impersonated user: "system:admin as
system:serviceaccount:cvss:default list secrets in cvss: forbidden".
`-n` keeps the namespaced requests of one namespace (cluster-wide ones stay).
Each event keeps the audit record as its `payload`, so
[`--detect`](eBPF-Probe#detection-rules---detect) rules can drop what is
expected (`kind == 'audit' && meta.user == 'system:serviceaccount:argocd:argocd-server'`).

Real output, on the k3s lab:

```text
k8s-audit warning  T1609     | system:admin get pods/exec cvss/writer: exec into a pod
k8s-audit warning  T1552.007 | system:admin list secrets in cvss: secrets listed
k8s-audit warning  T1528     | system:admin create serviceaccounts/token cvss/default: a service account token minted
k8s-audit warning  T1613     | system:admin as system:serviceaccount:cvss:default list secrets in cvss: forbidden (a service account probing its permissions?)
k8s-audit critical T1098     | system:admin create clusterrolebindings d12-pwn: cluster-admin granted
k8s-audit critical T1611     | system:admin create pods cvss/d12-priv: hostPID, privileged container x, hostPath /
k8s-audit critical T1609     | system:admin get nodes/proxy k3sec-lab-node: the kubelet API through the API server (nodes/proxy)
k8s-audit critical T1078.001 | system:anonymous list pods in cvss: an anonymous request went through
```

No detection in a minute of an idle cluster's audit stream.

## Policy

What a request asked for (the role a binding grants, a pod's spec) is only in
the log at `Request` level. A policy that gives the detections everything
they read, without ever logging a secret's content:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
  - level: None
    resources:
      - group: coordination.k8s.io
        resources: [leases]
  - level: Request
    verbs: [create, update]
    resources:
      - group: ""
        resources: [pods]
      - group: apps
        resources: [deployments, daemonsets, statefulsets, replicasets]
      - group: batch
        resources: [jobs, cronjobs]
      - group: rbac.authorization.k8s.io
        resources: [clusterrolebindings, rolebindings]
  - level: Metadata
```

k3s: in `/etc/rancher/k3s/config.yaml`,

```yaml
kube-apiserver-arg:
  - audit-log-path=/var/log/k3s-audit.log
  - audit-policy-file=/etc/rancher/k3s/audit-policy.yaml
```

At `Metadata` level only (Talos's default policy), the detections that read a
body (cluster-admin, risky pod specs) stay silent; the others work.

The log is on the control-plane nodes: run this `watch` there (the DaemonSet
reaches it at `/proc/1/root/<path>` on a control-plane node). A patch
(`kubectl patch`, `apply` server-side) carries a diff, not the object, and is
not judged.
