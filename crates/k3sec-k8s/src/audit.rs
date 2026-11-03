//! Detections on the API server's audit log (`watch --audit-log <PATH>`):
//! the file the API server writes (`--audit-log-path`; Talos:
//! `/var/log/audit/kube/kube-apiserver.log`), followed like `tail -F`, one
//! JSON `audit.k8s.io/v1` `Event` per line. Only what an attack looks like is
//! emitted (exec into a pod, a cluster-admin grant, a privileged pod, an
//! anonymous request that went through, secrets listed…), never the stream
//! itself. Detections on a request body (privileged pod, the role a binding
//! grants) need the policy to log those resources at `Request` level.

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio_util::sync::CancellationToken;

use k3sec_core::{EventSink, EventSource, SecEvent, Severity, Source};

pub struct AuditLogSource {
    path: PathBuf,
    namespace: Option<String>,
    /// Read the file from its start instead of its end (`--rollback`).
    from_start: bool,
}

impl AuditLogSource {
    pub fn new(path: PathBuf, namespace: Option<String>, from_start: bool) -> Self {
        Self {
            path,
            namespace,
            from_start,
        }
    }
}

#[async_trait]
impl EventSource for AuditLogSource {
    fn name(&self) -> &'static str {
        "k8s-audit"
    }

    async fn run(self: Box<Self>, sink: EventSink, cancel: CancellationToken) -> Result<()> {
        let mut from_start = self.from_start;
        let mut opened = false;
        loop {
            // A rotated (renamed, recreated) or truncated file is reopened
            // from its start: its new lines are all unread.
            let file = match tokio::fs::File::open(&self.path).await {
                Ok(f) => f,
                // Between a rotation's rename and the new file: wait for it.
                Err(_) if opened => {
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_millis(500)) => continue,
                    }
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("cannot open the audit log {}", self.path.display())
                    })
                }
            };
            opened = true;
            let inode = file.metadata().await?.ino();
            let mut reader = BufReader::new(file);
            if !from_start {
                reader.seek(std::io::SeekFrom::End(0)).await?;
            }
            from_start = true;
            let mut pos = reader.stream_position().await?;
            let mut line = String::new();
            loop {
                let n = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    n = reader.read_line(&mut line) => n?,
                };
                if n == 0 || !line.ends_with('\n') {
                    // At the end, or a line still being written: wait for more.
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    match std::fs::metadata(&self.path) {
                        Ok(m) if m.ino() == inode && m.len() >= pos => continue,
                        _ => break,
                    }
                }
                pos += line.len() as u64;
                if let Some(ev) = serde_json::from_str::<Value>(&line)
                    .ok()
                    .and_then(|v| to_sec_event(v, self.namespace.as_deref()))
                {
                    if sink.send(ev).await.is_err() {
                        return Ok(());
                    }
                }
                line.clear();
            }
        }
    }
}

/// What an audit event is evidence of.
struct Finding {
    severity: Severity,
    what: String,
    mitre: &'static str,
}

fn finding(severity: Severity, what: impl Into<String>, mitre: &'static str) -> Option<Finding> {
    Some(Finding {
        severity,
        what: what.into(),
        mitre,
    })
}

fn str_at<'a>(v: &'a Value, pointer: &str) -> &'a str {
    v.pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// The control plane's own components (`system:kube-controller-manager`,
/// `system:k3s-supervisor`, `system:node:<name>`…) and kube-system's service
/// accounts. Not `system:admin`: k3s's admin kubeconfig, a human.
fn is_control_plane(user: &str) -> bool {
    match user.strip_prefix("system:serviceaccount:") {
        Some(sa) => sa.starts_with("kube-system:"),
        None => user.starts_with("system:") && !matches!(user, "system:admin" | "system:anonymous"),
    }
}

fn detect(ev: &Value) -> Option<Finding> {
    // Authorized as the impersonated user, when there is one.
    let user = match str_at(ev, "/impersonatedUser/username") {
        "" => str_at(ev, "/user/username"),
        imp => imp,
    };
    let verb = str_at(ev, "/verb");
    let resource = str_at(ev, "/objectRef/resource");
    let sub = str_at(ev, "/objectRef/subresource");
    let code = ev
        .pointer("/responseStatus/code")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let allowed = code < 400;
    let sa = user.starts_with("system:serviceaccount:");

    if user == "system:anonymous" && allowed && !resource.is_empty() {
        return finding(
            Severity::Critical,
            "an anonymous request went through",
            "T1078.001",
        );
    }
    if !allowed {
        // A workload's token probing what it may do: denied requests outside
        // the control plane.
        return (code == 403 && sa && !is_control_plane(user)).then(|| Finding {
            severity: Severity::Warning,
            what: "forbidden (a service account probing its permissions?)".into(),
            mitre: "T1613",
        });
    }
    match (resource, sub, verb) {
        ("pods", "exec" | "attach", "create" | "get") => {
            finding(Severity::Warning, format!("{sub} into a pod"), "T1609")
        }
        ("pods", "portforward", "create" | "get") => {
            finding(Severity::Warning, "port-forward to a pod", "T1572")
        }
        ("nodes", "proxy", _) => finding(
            Severity::Critical,
            "the kubelet API through the API server (nodes/proxy)",
            "T1609",
        ),
        ("secrets", "", "list" | "watch") if !is_control_plane(user) => {
            finding(Severity::Warning, "secrets listed", "T1552.007")
        }
        ("serviceaccounts", "token", "create") if !is_control_plane(user) => {
            finding(Severity::Warning, "a service account token minted", "T1528")
        }
        ("clusterrolebindings" | "rolebindings", "", "create" | "update")
            if user != "system:apiserver" =>
        {
            let role = str_at(ev, "/requestObject/roleRef/name");
            (role == "cluster-admin").then(|| Finding {
                severity: Severity::Critical,
                what: "cluster-admin granted".into(),
                mitre: "T1098",
            })
        }
        ("selfsubjectrulesreviews" | "selfsubjectaccessreviews", "", "create")
            if sa && !is_control_plane(user) =>
        {
            finding(
                Severity::Warning,
                "a service account enumerating its permissions",
                "T1613",
            )
        }
        ("events", "", "delete" | "deletecollection") if !is_control_plane(user) => {
            finding(Severity::Warning, "events deleted", "T1070")
        }
        (
            "pods" | "deployments" | "daemonsets" | "statefulsets" | "replicasets" | "jobs"
            | "cronjobs",
            "",
            "create" | "update",
        ) => {
            // Pods a controller makes from a workload were judged on the workload.
            if resource == "pods" && is_control_plane(user) {
                return None;
            }
            let obj = ev.get("requestObject")?;
            let spec = [
                "/spec/jobTemplate/spec/template/spec",
                "/spec/template/spec",
                "/spec",
            ]
            .iter()
            .find_map(|p| obj.pointer(p).filter(|s| s.get("containers").is_some()))?;
            let risks = pod_risks(spec);
            (!risks.is_empty()).then(|| Finding {
                severity: Severity::Critical,
                what: risks.join(", "),
                mitre: "T1611",
            })
        }
        _ => None,
    }
}

/// What in a pod spec gives the node away.
fn pod_risks(spec: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for host in ["hostPID", "hostNetwork", "hostIPC"] {
        if spec.get(host).and_then(Value::as_bool) == Some(true) {
            out.push(host.to_string());
        }
    }
    let containers = ["initContainers", "containers", "ephemeralContainers"]
        .iter()
        .filter_map(|k| spec.get(k).and_then(Value::as_array))
        .flatten();
    for c in containers {
        let name = str_at(c, "/name");
        if c.pointer("/securityContext/privileged")
            .and_then(Value::as_bool)
            == Some(true)
        {
            out.push(format!("privileged container {name}"));
        }
        let caps = c
            .pointer("/securityContext/capabilities/add")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|c| matches!(*c, "SYS_ADMIN" | "SYS_PTRACE" | "SYS_MODULE" | "ALL"));
        out.extend(caps.map(|cap| format!("{cap} in {name}")));
    }
    const HOST_PATHS: &[&str] = &[
        "/",
        "/etc",
        "/proc",
        "/root",
        "/var/run",
        "/run",
        "/var/lib/kubelet",
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/var/run/containerd/containerd.sock",
    ];
    for v in spec
        .get("volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let path = str_at(v, "/hostPath/path").trim_end_matches('/');
        let path = if path.is_empty() && v.pointer("/hostPath").is_some() {
            "/"
        } else {
            path
        };
        if HOST_PATHS.contains(&path) {
            out.push(format!("hostPath {path}"));
        }
    }
    out
}

fn to_sec_event(ev: Value, namespace: Option<&str>) -> Option<SecEvent> {
    // RequestReceived is followed by ResponseComplete: judge each request once.
    let stage = str_at(&ev, "/stage");
    if !(stage.is_empty() || stage == "ResponseComplete" || stage == "Panic") {
        return None;
    }
    let ns = str_at(&ev, "/objectRef/namespace");
    if namespace.is_some_and(|want| !ns.is_empty() && ns != want) {
        return None;
    }
    let f = detect(&ev)?;
    let user = str_at(&ev, "/user/username");
    let verb = str_at(&ev, "/verb");
    let resource = match str_at(&ev, "/objectRef/subresource") {
        "" => str_at(&ev, "/objectRef/resource").to_string(),
        sub => format!("{}/{sub}", str_at(&ev, "/objectRef/resource")),
    };
    let name = str_at(&ev, "/objectRef/name");
    let target = match (ns, name) {
        ("", "") => resource.clone(),
        ("", n) => format!("{resource} {n}"),
        (ns, "") => format!("{resource} in {ns}"),
        (ns, n) => format!("{resource} {ns}/{n}"),
    };
    let as_user = match str_at(&ev, "/impersonatedUser/username") {
        "" => user.to_string(),
        imp => format!("{user} as {imp}"),
    };
    let at = ["/stageTimestamp", "/requestReceivedTimestamp"]
        .iter()
        .find_map(|p| DateTime::parse_from_rfc3339(str_at(&ev, p)).ok())
        .map_or_else(Utc::now, |t| t.with_timezone(&Utc));
    let code = ev.pointer("/responseStatus/code").and_then(Value::as_u64);
    let source_ip = str_at(&ev, "/sourceIPs/0").to_string();
    let user_agent = str_at(&ev, "/userAgent").to_string();
    let mut b = SecEvent::builder(Source::K8sAudit, at)
        .kind("audit")
        .severity(f.severity)
        .maybe_namespace(Some(ns.to_string()))
        .message(format!("{as_user} {verb} {target}: {}", f.what))
        .meta("user", user.to_string())
        .meta("verb", verb.to_string())
        .meta("resource", resource.clone())
        .meta("source_ip", source_ip)
        .meta("user_agent", user_agent)
        .meta("mitre", f.mitre)
        .meta("code", code.map(|c| c.to_string()).unwrap_or_default());
    if !name.is_empty() {
        b = b.object(format!("{resource}/{name}"));
    }
    Some(b.payload(ev).build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(user: &str, verb: &str, resource: &str, sub: &str, code: u64) -> Value {
        json!({"kind": "Event", "apiVersion": "audit.k8s.io/v1", "stage": "ResponseComplete",
               "verb": verb, "user": {"username": user}, "sourceIPs": ["10.0.0.9"],
               "objectRef": {"resource": resource, "subresource": sub, "namespace": "web", "name": "api-0"},
               "responseStatus": {"code": code},
               "stageTimestamp": "2026-11-03T19:00:00.000000Z"})
    }

    #[test]
    fn detections() {
        let exec = to_sec_event(ev("system:admin", "create", "pods", "exec", 101), None).unwrap();
        assert_eq!(exec.source, Source::K8sAudit);
        assert_eq!(exec.severity, Severity::Warning);
        assert_eq!(
            exec.message,
            "system:admin create pods/exec web/api-0: exec into a pod"
        );
        assert_eq!(exec.metadata["mitre"], "T1609");
        assert_eq!(exec.object.as_deref(), Some("pods/exec/api-0"));

        // Namespace scoping, the request's first stage, the plain stream.
        assert!(to_sec_event(
            ev("system:admin", "create", "pods", "exec", 101),
            Some("db")
        )
        .is_none());
        let mut first = ev("system:admin", "create", "pods", "exec", 101);
        first["stage"] = json!("RequestReceived");
        assert!(to_sec_event(first, None).is_none());
        assert!(to_sec_event(ev("alice", "get", "pods", "", 200), None).is_none());

        let anon = to_sec_event(ev("system:anonymous", "list", "secrets", "", 200), None).unwrap();
        assert_eq!(anon.severity, Severity::Critical);
        assert!(to_sec_event(ev("system:anonymous", "list", "secrets", "", 403), None).is_none());

        let probe = to_sec_event(
            ev("system:serviceaccount:web:api", "list", "secrets", "", 403),
            None,
        );
        assert_eq!(probe.unwrap().metadata["mitre"], "T1613");
        let mut imp = ev("system:admin", "list", "secrets", "", 403);
        imp["impersonatedUser"] = json!({"username": "system:serviceaccount:web:api"});
        let imp = to_sec_event(imp, None).unwrap();
        assert!(imp
            .message
            .starts_with("system:admin as system:serviceaccount:web:api list"));
        assert!(to_sec_event(
            ev(
                "system:serviceaccount:kube-system:x",
                "list",
                "secrets",
                "",
                200
            ),
            None
        )
        .is_none());

        let mut crb = ev("bob", "create", "clusterrolebindings", "", 201);
        crb["requestObject"] = json!({"roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}});
        assert_eq!(
            to_sec_event(crb.clone(), None).unwrap().severity,
            Severity::Critical
        );
        crb["requestObject"]["roleRef"]["name"] = json!("view");
        assert!(to_sec_event(crb, None).is_none());
    }

    #[test]
    fn control_plane_users() {
        assert!(is_control_plane("system:k3s-supervisor") && is_control_plane("system:node:n1"));
        assert!(is_control_plane("system:serviceaccount:kube-system:helm"));
        assert!(!is_control_plane("system:admin") && !is_control_plane("system:anonymous"));
        assert!(!is_control_plane("system:serviceaccount:web:api") && !is_control_plane("alice"));
    }

    #[test]
    fn risky_pod_specs() {
        let mut ds = ev("bob", "create", "daemonsets", "", 201);
        ds["requestObject"] = json!({"spec": {"template": {"spec": {
            "hostPID": true,
            "containers": [{"name": "x", "securityContext": {"privileged": true,
                            "capabilities": {"add": ["NET_ADMIN", "SYS_ADMIN"]}}}],
            "volumes": [{"name": "root", "hostPath": {"path": "/"}},
                        {"name": "logs", "hostPath": {"path": "/var/log"}}]}}}});
        let e = to_sec_event(ds, None).unwrap();
        assert_eq!(e.severity, Severity::Critical);
        assert!(
            e.message
                .ends_with("hostPID, privileged container x, SYS_ADMIN in x, hostPath /"),
            "{}",
            e.message
        );

        // The controller's pods were judged on their workload; a plain pod is fine.
        let mut pod = ev(
            "system:serviceaccount:kube-system:daemon-set-controller",
            "create",
            "pods",
            "",
            201,
        );
        pod["requestObject"] = json!({"spec": {"hostPID": true, "containers": [{"name": "x"}]}});
        assert!(to_sec_event(pod.clone(), None).is_none());
        pod["user"]["username"] = json!("bob");
        assert!(to_sec_event(pod.clone(), None).is_some());
        pod["requestObject"] = json!({"spec": {"containers": [{"name": "x"}]}});
        assert!(to_sec_event(pod, None).is_none());
    }

    #[tokio::test]
    async fn follows_appends_and_rotation() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let line = |user: &str| format!("{}\n", ev(user, "create", "pods", "exec", 101));
        std::fs::write(&path, line("old")).unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let cancel = CancellationToken::new();
        let src = Box::new(AuditLogSource::new(path.clone(), None, false));
        let task = tokio::spawn(src.run(tx, cancel.clone()));
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(line("appended").as_bytes()).unwrap();
        let got = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            got.metadata["user"], "appended",
            "the existing line is skipped"
        );

        // Rotated: renamed away, a new file in its place.
        std::fs::rename(&path, dir.path().join("audit.log.1")).unwrap();
        std::fs::write(&path, line("rotated")).unwrap();
        let got = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.metadata["user"], "rotated");
        cancel.cancel();
        task.await.unwrap().unwrap();
    }
}
