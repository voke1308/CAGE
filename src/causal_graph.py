import threading
import logging
from datetime import datetime, timedelta
import networkx as nx

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("causal-graph")

# Pods/namespaces known to legitimately spawn shells
SHELL_WHITELIST_NAMESPACES = {"kube-system", "local-path-storage"}
SHELL_WHITELIST_POD_PREFIXES = ("legitimate-app", "debug-", "init-")

class CausalGraph:
    def __init__(self):
        self._lock = threading.RLock()
        self.graph = nx.DiGraph()
        self.alerts = []
        self._event_window = {}

    def add_event(self, event: dict) -> list:
        with self._lock:
            alerts = []
            t1059 = self._check_t1059(event)
            if t1059:
                alerts.append(t1059)
            t1552 = self._check_t1552(event)
            if t1552:
                alerts.append(t1552)
            alerts.extend(self._check_chains(event))

            pod_uid = event.get("pod_uid")
            if pod_uid and event.get("timestamp"):
                try:
                    ts = datetime.fromisoformat(
                        event["timestamp"].replace("Z", "+00:00")
                    )
                    if pod_uid not in self._event_window:
                        self._event_window[pod_uid] = []
                    self._event_window[pod_uid].append((ts, event))
                    self._event_window[pod_uid] = [
                        (t, e) for t, e in self._event_window[pod_uid]
                        if (ts - t) < timedelta(seconds=60)
                    ]
                except Exception:
                    pass
            return alerts

    def _is_whitelisted(self, event: dict) -> bool:
        ns = event.get("namespace", "")
        pod = event.get("pod_name", "") or ""
        if ns in SHELL_WHITELIST_NAMESPACES:
            return True
        if any(pod.startswith(p) for p in SHELL_WHITELIST_POD_PREFIXES):
            return True
        return False

    def _check_t1059(self, event: dict):
        if event.get("event_type") != "process_exec":
            return None
        if not event.get("pod_uid"):
            return None
        if self._is_whitelisted(event):
            return None
        binary = event.get("binary", "")
        if binary in ("/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"):
            return {
                "severity": "MEDIUM",
                "rule": "T1059",
                "description": "Shell execution inside pod",
                "pod_uid": event["pod_uid"],
                "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"),
                "binary": binary,
                "timestamp": event.get("timestamp"),
            }
        return None

    def _check_t1552(self, event: dict):
        if event.get("event_type") != "k8s_secret_access":
            return None
        return {
            "severity": "HIGH",
            "rule": "T1552",
            "description": "Secret access via Kubernetes API",
            "pod_uid": event.get("pod_uid"),
            "pod_name": event.get("pod_name"),
            "namespace": event.get("namespace"),
            "timestamp": event.get("timestamp"),
        }

    def _check_chains(self, event: dict) -> list:
        pod_uid = event.get("pod_uid")
        if not pod_uid or pod_uid not in self._event_window:
            return []
        events = self._event_window[pod_uid]
        has_t1059 = any(
            e.get("binary") in ("/bin/bash", "/bin/sh")
            for _, e in events
        )
        has_t1552 = any(
            e.get("event_type") == "k8s_secret_access"
            for _, e in events
        )
        if has_t1059 and has_t1552:
            return [{
                "severity": "CRITICAL",
                "rule": "T1059→T1552",
                "description": "Lateral movement chain: shell then credential access",
                "pod_uid": pod_uid,
                "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"),
                "timestamp": event.get("timestamp"),
            }]
        return []

    def snapshot(self):
        with self._lock:
            return nx.DiGraph(self.graph)
