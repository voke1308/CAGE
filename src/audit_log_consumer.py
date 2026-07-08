import subprocess
import json
import threading
import queue
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("audit-consumer")

SYSTEM_USERS = {
    "system:kube-controller-manager",
    "system:kube-scheduler",
    "system:apiserver",
}

# RBAC objects considered "already elevated" if bound directly
ELEVATED_CLUSTER_ROLES = {"cluster-admin"}
RBAC_BINDING_RESOURCES = {"clusterrolebindings", "rolebindings"}
RBAC_ROLE_RESOURCES = {"clusterroles", "roles"}
RBAC_READ_RESOURCES = RBAC_BINDING_RESOURCES | RBAC_ROLE_RESOURCES

RBAC_DISCOVERY_THRESHOLD = 10       # reads on RBAC objects...
RBAC_DISCOVERY_WINDOW_SECONDS = 30  # ...within this window, by one user

class AuditLogConsumer:
    def __init__(self, cache, out_queue: queue.Queue):
        self.cache = cache
        self.out_queue = out_queue
        self._rbac_activity = {}  # username -> [timestamps] for discovery-burst detection

    def start(self):
        threading.Thread(target=self._read_loop, daemon=True).start()
        log.info("Audit log consumer started")

    def _read_loop(self):
        cmd = ["docker", "exec", "cage-control-plane", "stdbuf", "-oL",
               "tail", "-f", "-n", "0", "/var/log/kubernetes/audit.log"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
            for line in iter(proc.stdout.readline, ''):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    for ev in self._process(raw):
                        self.out_queue.put(ev)
                except Exception as e:
                    log.warning(f"Audit parse error: {e}")
        except Exception as e:
            log.error(f"Audit consumer failed: {e}")

    def _process(self, raw: dict):
        if raw.get("stage") != "ResponseComplete":
            return []

        verb = raw.get("verb", "").lower()
        obj = raw.get("objectRef", {})
        resource = obj.get("resource", "")
        subresource = obj.get("subresource", "")
        username = raw.get("user", {}).get("username", "")
        extra = raw.get("user", {}).get("extra", {})

        if any(username.startswith(s) for s in SYSTEM_USERS) or username.startswith("system:node:"):
            return []

        events = []

        if resource == "secrets" and verb in ("get", "list", "create", "patch", "delete"):
            pod_name, pod_uid, namespace = self._extract_pod_identity(obj, extra)
            if pod_name and pod_name not in ("legitimate-app",):
                secret_name = obj.get("name", "<list>")
                log.info(f"[AUDIT] secret {verb} by {username} | pod={pod_name}")
                events.append({
                    "timestamp": raw.get("requestReceivedTimestamp", datetime.now().isoformat()),
                    "event_type": "k8s_secret_access",
                    "verb": verb,
                    "secret_name": secret_name,
                    "namespace": namespace,
                    "user": username,
                    "pod_uid": pod_uid,
                    "pod_name": pod_name,
                })

        # --- Privileged pod / container creation (T1548) ---
        if resource == "pods" and verb == "create" and not subresource:
            priv_event = self._check_privileged_pod_spec(raw, obj, username)
            if priv_event:
                events.append(priv_event)

        # --- RBAC abuse: elevated binding or wildcard role granted (T1548.005) ---
        if resource in RBAC_BINDING_RESOURCES and verb in ("create", "update", "patch"):
            rbac_event = self._check_rbac_binding(raw, obj, resource, username)
            if rbac_event:
                events.append(rbac_event)

        if resource in RBAC_ROLE_RESOURCES and verb in ("create", "update", "patch"):
            rbac_event = self._check_rbac_wildcard_role(raw, obj, resource, username)
            if rbac_event:
                events.append(rbac_event)

        # --- Impersonation / token minting for another identity ---
        if verb == "impersonate" or (resource == "serviceaccounts" and subresource == "token" and verb == "create"):
            log.info(f"[AUDIT] impersonation/token-mint by {username} on {resource}/{obj.get('name','')}")
            events.append({
                "timestamp": raw.get("requestReceivedTimestamp", datetime.now().isoformat()),
                "event_type": "rbac_abuse",
                "reason": f"{'Impersonation' if verb == 'impersonate' else 'Service account token minted'} "
                          f"by {username} targeting {obj.get('namespace','')}/{obj.get('name','')}",
                "namespace": obj.get("namespace", "cluster-wide"),
                "user": username,
            })

        # --- Discovery: burst of RBAC reads by the same identity (T1613) ---
        if resource in RBAC_READ_RESOURCES and verb in ("get", "list"):
            discovery_event = self._track_rbac_discovery(raw, username)
            if discovery_event:
                events.append(discovery_event)

        if resource == "pods" and subresource == "exec" and verb == "get":
            target_pod = obj.get("name", "")
            namespace = obj.get("namespace", "default")
            target_uid = self.cache.resolve_by_name(namespace, target_pod)
            log.info(f"[AUDIT] pod/exec by {username} -> {namespace}/{target_pod}")
            events.append({
                "timestamp": raw.get("requestReceivedTimestamp", datetime.now().isoformat()),
                "event_type": "pod_exec",
                "target_pod": target_pod,
                "target_uid": target_uid,
                "namespace": namespace,
                "user": username,
                "pod_uid": target_uid,
                "pod_name": target_pod,
            })

        return events

    def _check_privileged_pod_spec(self, raw, obj, username):
        """Inspect a pod-create audit record's requestObject for privileged
        securityContext, host namespaces, or dangerous added capabilities."""
        req = raw.get("requestObject") or {}
        spec = req.get("spec", {})
        if not spec:
            return None

        reasons = []
        if spec.get("hostPID"):
            reasons.append("hostPID=true")
        if spec.get("hostNetwork"):
            reasons.append("hostNetwork=true")
        if spec.get("hostIPC"):
            reasons.append("hostIPC=true")

        containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])
        for c in containers:
            sc = c.get("securityContext") or {}
            if sc.get("privileged"):
                reasons.append(f"container '{c.get('name')}' privileged=true")
            if sc.get("allowPrivilegeEscalation"):
                reasons.append(f"container '{c.get('name')}' allowPrivilegeEscalation=true")
            added_caps = (sc.get("capabilities") or {}).get("add") or []
            dangerous = [cap for cap in added_caps if cap.upper() in
                         {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"}]
            if dangerous:
                reasons.append(f"container '{c.get('name')}' added capabilities {dangerous}")

        if not reasons:
            return None

        pod_name = obj.get("name", "")
        namespace = obj.get("namespace", "default")
        log.info(f"[AUDIT] privileged pod create by {username} -> {namespace}/{pod_name}: {reasons}")
        return {
            "timestamp": raw.get("requestReceivedTimestamp", datetime.now().isoformat()),
            "event_type": "privileged_pod_created",
            "reason": "; ".join(reasons),
            "namespace": namespace,
            "pod_name": pod_name,
            "pod_uid": None,
            "user": username,
        }

    def _check_rbac_binding(self, raw, obj, resource, username):
        """Flag RoleBinding/ClusterRoleBinding creation or edits that grant
        cluster-admin (direct privilege escalation via RBAC)."""
        req = raw.get("requestObject") or {}
        role_ref = req.get("roleRef", {}) or {}
        role_name = role_ref.get("name", "")
        if role_name not in ELEVATED_CLUSTER_ROLES:
            return None

        subjects = req.get("subjects", []) or []
        subj_desc = ", ".join(f"{s.get('kind')}:{s.get('name')}" for s in subjects) or "unknown subject"
        log.info(f"[AUDIT] RBAC binding to {role_name} by {username} -> {subj_desc}")
        return {
            "timestamp": raw.get("requestReceivedTimestamp", datetime.now().isoformat()),
            "event_type": "rbac_abuse",
            "reason": f"{resource[:-1]} '{obj.get('name','')}' grants '{role_name}' to {subj_desc}",
            "namespace": obj.get("namespace", "cluster-wide"),
            "user": username,
        }

    def _check_rbac_wildcard_role(self, raw, obj, resource, username):
        """Flag Role/ClusterRole creation or edits containing wildcard verbs,
        resources, or apiGroups — classic RBAC over-permissioning."""
        req = raw.get("requestObject") or {}
        rules = req.get("rules", []) or []
        for rule in rules:
            verbs = rule.get("verbs", []) or []
            resources = rule.get("resources", []) or []
            api_groups = rule.get("apiGroups", []) or []
            if "*" in verbs or "*" in resources or "*" in api_groups:
                log.info(f"[AUDIT] wildcard {resource[:-1]} '{obj.get('name','')}' created/edited by {username}")
                return {
                    "timestamp": raw.get("requestReceivedTimestamp", datetime.now().isoformat()),
                    "event_type": "rbac_abuse",
                    "reason": f"{resource[:-1]} '{obj.get('name','')}' contains a wildcard "
                              f"rule (verbs={verbs}, resources={resources}, apiGroups={api_groups})",
                    "namespace": obj.get("namespace", "cluster-wide"),
                    "user": username,
                }
        return None

    def _track_rbac_discovery(self, raw, username):
        """Track get/list calls on RBAC objects per-user; flag a burst as
        Discovery (T1613) — an attacker enumerating roles/bindings to find
        an escalation path."""
        if not username or username == "system:anonymous":
            return None
        ts_raw = raw.get("requestReceivedTimestamp", datetime.now().isoformat())
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now()

        window = self._rbac_activity.setdefault(username, [])
        window.append(ts)
        cutoff = ts - timedelta(seconds=RBAC_DISCOVERY_WINDOW_SECONDS)
        self._rbac_activity[username] = [t for t in window if t > cutoff]
        count = len(self._rbac_activity[username])

        if count == RBAC_DISCOVERY_THRESHOLD:  # fire exactly once per burst
            log.info(f"[AUDIT] RBAC discovery burst: {username} made {count} reads "
                      f"in {RBAC_DISCOVERY_WINDOW_SECONDS}s")
            return {
                "timestamp": ts_raw,
                "event_type": "rbac_discovery",
                "user": username,
                "count": count,
                "window_seconds": RBAC_DISCOVERY_WINDOW_SECONDS,
            }
        return None

    def _extract_pod_identity(self, obj, extra):
        namespace = obj.get("namespace", "default")
        pod_name_list = extra.get("authentication.kubernetes.io/pod-name", [])
        pod_uid_list = extra.get("authentication.kubernetes.io/pod-uid", [])
        pod_name = pod_name_list[0] if pod_name_list else None
        pod_uid = pod_uid_list[0] if pod_uid_list else None
        return pod_name, pod_uid, namespace
