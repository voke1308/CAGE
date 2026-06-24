import threading
import logging
from datetime import datetime, timedelta
import networkx as nx

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("causal-graph")

SHELL_WHITELIST_NAMESPACES = {"kube-system", "local-path-storage"}
SHELL_WHITELIST_POD_PREFIXES = ("legitimate-app", "debug-", "init-")

class CausalGraph:
    def __init__(self):
        self._lock = threading.RLock()
        self.graph = nx.DiGraph()
        self.alerts = []
        self._event_window = {}
        self._fired_chains = set()  # avoid duplicate chain alerts

    def add_event(self, event: dict) -> list:
        with self._lock:
            alerts = []

            t1059 = self._check_t1059(event)
            if t1059:
                alerts.append(t1059)
                self.alerts.append(t1059)

            t1552 = self._check_t1552(event)
            if t1552:
                alerts.append(t1552)
                self.alerts.append(t1552)

            pod_uid = event.get("pod_uid")
            if pod_uid and event.get("timestamp"):
                try:
                    ts_str = event["timestamp"].replace("Z", "+00:00")
                    ts = datetime.fromisoformat(ts_str)
                    if pod_uid not in self._event_window:
                        self._event_window[pod_uid] = []
                    self._event_window[pod_uid].append((ts, event))
                    self._event_window[pod_uid] = [
                        (t, e) for t, e in self._event_window[pod_uid]
                        if (ts - t) < timedelta(seconds=60)
                    ]
                except Exception:
                    pass

            chain = self._check_chains(event)
            if chain:
                alerts.extend(chain)
                self.alerts.extend(chain)

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
            alert = {
                "severity": "MEDIUM",
                "rule": "T1059",
                "description": "Shell execution inside pod",
                "pod_uid": event["pod_uid"],
                "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"),
                "binary": binary,
                "timestamp": event.get("timestamp"),
            }
            log.warning(f"[MEDIUM] T1059: Shell execution inside pod on "
                       f"{event.get('namespace')}/{event.get('pod_name')}")
            return alert
        return None

    def _check_t1552(self, event: dict):
        if event.get("event_type") != "k8s_secret_access":
            return None
        alert = {
            "severity": "HIGH",
            "rule": "T1552",
            "description": f"Secret access via K8s API (verb={event.get('verb')})",
            "pod_uid": event.get("pod_uid"),
            "pod_name": event.get("pod_name"),
            "namespace": event.get("namespace"),
            "secret_name": event.get("secret_name"),
            "user": event.get("user"),
            "timestamp": event.get("timestamp"),
        }
        log.warning(f"[HIGH] T1552: Secret access by "
                   f"{event.get('namespace')}/{event.get('pod_name')} "
                   f"verb={event.get('verb')} secret={event.get('secret_name')}")
        return alert

    def _check_chains(self, event: dict) -> list:
        pod_uid = event.get("pod_uid")
        if not pod_uid or pod_uid not in self._event_window:
            return []

        # Avoid firing duplicate chain alerts for same pod
        if pod_uid in self._fired_chains:
            return []

        events = self._event_window[pod_uid]
        has_t1059 = any(
            e.get("binary") in ("/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh")
            for _, e in events
        )
        has_t1552 = any(
            e.get("event_type") == "k8s_secret_access"
            for _, e in events
        )

        if has_t1059 and has_t1552:
            self._fired_chains.add(pod_uid)
            alert = {
                "severity": "CRITICAL",
                "rule": "T1059→T1552",
                "description": "Lateral movement chain: shell execution then credential access",
                "pod_uid": pod_uid,
                "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"),
                "timestamp": event.get("timestamp"),
            }
            log.warning(f"[CRITICAL] T1059→T1552 CHAIN DETECTED on "
                       f"{event.get('namespace')}/{event.get('pod_name')}")
            return [alert]
        return []

    def snapshot(self):
        with self._lock:
            return nx.DiGraph(self.graph)
