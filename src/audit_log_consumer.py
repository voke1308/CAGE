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
                    tagged = self._process(raw)
                    if tagged:
                        self.out_queue.put(tagged)
                except Exception as e:
                    log.warning(f"Audit parse error: {e}")
        except Exception as e:
            log.error(f"Audit consumer failed: {e}")

    def _process(self, raw: dict):
        if raw.get("stage") != "ResponseComplete":
            return None

        verb = raw.get("verb", "").lower()
        obj = raw.get("objectRef", {})
        resource = obj.get("resource", "")

        if resource != "secrets":
            return None
        if verb not in ("get", "list", "create", "patch", "delete"):
            return None

        username = raw.get("user", {}).get("username", "")
        if any(username.startswith(s) for s in SYSTEM_USERS):
            return None

        # Extract pod identity directly from audit log extra fields
        extra = raw.get("user", {}).get("extra", {})
        pod_name = None
        pod_uid = None
        namespace = obj.get("namespace", "default")

        pod_name_list = extra.get("authentication.kubernetes.io/pod-name", [])
        pod_uid_list = extra.get("authentication.kubernetes.io/pod-uid", [])

        if pod_name_list:
            pod_name = pod_name_list[0]
        if pod_uid_list:
            pod_uid = pod_uid_list[0]
            meta = self.cache.get_meta(pod_uid)
            if meta:
                namespace = meta["ns"]

        # Only alert on attacker-labelled pods, skip legitimate-app
        if pod_name and pod_name in ("legitimate-app",):
            return None

        secret_name = obj.get("name", "<list>")
        log.info(f"[AUDIT] secret {verb} by {username} | pod={pod_name} | secret={secret_name}")

        return {
            "timestamp": raw.get("requestReceivedTimestamp", datetime.now().isoformat()),
            "event_type": "k8s_secret_access",
            "verb": verb,
            "secret_name": secret_name,
            "namespace": namespace,
            "user": username,
            "pod_uid": pod_uid,
            "pod_name": pod_name,
        }
