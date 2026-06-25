import subprocess
import json
import threading
import queue
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("audit-consumer")

SYSTEM_USERS = {
    "system:kube-controller-manager",
    "system:kube-scheduler",
    "system:apiserver",
}

class AuditLogConsumer:
    def __init__(self, cache, out_queue: queue.Queue):
        self.cache = cache
        self.out_queue = out_queue

    def start(self):
        threading.Thread(target=self._read_loop, daemon=True).start()
        log.info("Audit log consumer started")

    def _read_loop(self):
        cmd = ["docker", "exec", "cage-control-plane",
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

        if any(username.startswith(s) for s in SYSTEM_USERS):
            return []

        events = []

        # T1552: secret access
        if resource == "secrets" and verb in ("get", "list", "create", "patch", "delete"):
            pod_name, pod_uid, namespace = self._extract_pod_identity(obj, extra)
            if pod_name and pod_name not in ("legitimate-app",):
                secret_name = obj.get("name", "<list>")
                log.info(f"[AUDIT] secret {verb} by {username} | pod={pod_name} | secret={secret_name}")
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

        # T1021: pods/exec — remote execution into a pod (lateral movement)
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

    def _extract_pod_identity(self, obj, extra):
        namespace = obj.get("namespace", "default")
        pod_name_list = extra.get("authentication.kubernetes.io/pod-name", [])
        pod_uid_list = extra.get("authentication.kubernetes.io/pod-uid", [])
        pod_name = pod_name_list[0] if pod_name_list else None
        pod_uid = pod_uid_list[0] if pod_uid_list else None
        if pod_uid:
            meta = self.cache.get_meta(pod_uid)
            if meta:
                namespace = meta["ns"]
        return pod_name, pod_uid, namespace
