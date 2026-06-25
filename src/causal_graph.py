import threading
import logging
from datetime import datetime, timedelta
import networkx as nx

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("causal-graph")

SHELL_WHITELIST_NAMESPACES = {"kube-system", "local-path-storage"}
SHELL_WHITELIST_POD_PREFIXES = ("legitimate-app", "debug-", "init-", "victim")

class CausalGraph:
    def __init__(self):
        self._lock = threading.RLock()
        self.graph = nx.DiGraph()
        self.alerts = []
        self._event_window = {}
        self._fired_chains = set()

    def add_event(self, event: dict) -> list:
        with self._lock:
            alerts = []

            for check in (self._check_t1059, self._check_t1021, self._check_t1552):
                alert = check(event)
                if alert:
                    alerts.append(alert)
                    self.alerts.append(alert)

            # Add to graph
            pod_uid = event.get("pod_uid")
            if pod_uid:
                if not self.graph.has_node(pod_uid):
                    self.graph.add_node(pod_uid,
                        name=event.get("pod_name"),
                        namespace=event.get("namespace"))

            # Update sliding event window
            if pod_uid and event.get("timestamp"):
                try:
                    ts = datetime.fromisoformat(
                        event["timestamp"].replace("Z", "+00:00"))
                    self._event_window.setdefault(pod_uid, []).append((ts, event))
                    self._event_window[pod_uid] = [
                        (t, e) for t, e in self._event_window[pod_uid]
                        if (ts - t) < timedelta(seconds=120)
                    ]
                except Exception:
                    pass

            chain_alerts = self._check_chains(event)
            alerts.extend(chain_alerts)
            self.alerts.extend(chain_alerts)

            return alerts

    def _is_whitelisted(self, event):
        ns = event.get("namespace", "")
        pod = event.get("pod_name", "") or ""
        return ns in SHELL_WHITELIST_NAMESPACES or \
               any(pod.startswith(p) for p in SHELL_WHITELIST_POD_PREFIXES)

    def _check_t1059(self, event):
        if event.get("event_type") != "process_exec":
            return None
        if not event.get("pod_uid") or self._is_whitelisted(event):
            return None
        binary = event.get("binary", "")
        if binary in ("/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"):
            log.warning(f"[MEDIUM] T1059: Shell in {event.get('namespace')}/{event.get('pod_name')}")
            return {
                "severity": "MEDIUM", "rule": "T1059",
                "description": "Shell execution inside pod",
                "pod_uid": event["pod_uid"],
                "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"),
                "binary": binary,
                "timestamp": event.get("timestamp"),
            }

    def _check_t1021(self, event):
        if event.get("event_type") != "pod_exec":
            return None
        log.warning(f"[MEDIUM] T1021: Remote exec into {event.get('namespace')}/{event.get('pod_name')}")
        return {
            "severity": "MEDIUM", "rule": "T1021",
            "description": "Remote execution into pod via kubectl exec",
            "pod_uid": event.get("pod_uid"),
            "pod_name": event.get("pod_name"),
            "namespace": event.get("namespace"),
            "user": event.get("user"),
            "timestamp": event.get("timestamp"),
        }

    def _check_t1552(self, event):
        if event.get("event_type") != "k8s_secret_access":
            return None
        log.warning(f"[HIGH] T1552: Secret access by {event.get('namespace')}/{event.get('pod_name')}")
        return {
            "severity": "HIGH", "rule": "T1552",
            "description": f"Secret access via K8s API (verb={event.get('verb')})",
            "pod_uid": event.get("pod_uid"),
            "pod_name": event.get("pod_name"),
            "namespace": event.get("namespace"),
            "secret_name": event.get("secret_name"),
            "timestamp": event.get("timestamp"),
        }

    def _check_chains(self, event) -> list:
        pod_uid = event.get("pod_uid")
        if not pod_uid or pod_uid not in self._event_window:
            return []

        events = self._event_window[pod_uid]
        event_types = {e.get("event_type") for _, e in events}
        binaries = {e.get("binary") for _, e in events}

        has_t1059 = bool(binaries & {"/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"})
        has_t1021 = "pod_exec" in event_types
        has_t1552 = "k8s_secret_access" in event_types

        alerts = []

        # Two-hop chain: T1059 -> T1552
        chain_key_2 = (pod_uid, "T1059->T1552")
        if has_t1059 and has_t1552 and chain_key_2 not in self._fired_chains:
            self._fired_chains.add(chain_key_2)
            log.warning(f"[CRITICAL] T1059→T1552 CHAIN on {event.get('namespace')}/{event.get('pod_name')}")
            alerts.append({
                "severity": "CRITICAL", "rule": "T1059→T1552",
                "description": "Shell execution then credential access",
                "pod_uid": pod_uid,
                "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"),
                "timestamp": event.get("timestamp"),
            })

        # Three-hop chain: T1021 -> T1059 -> T1552
        chain_key_3 = (pod_uid, "T1021->T1059->T1552")
        if has_t1021 and has_t1059 and has_t1552 and chain_key_3 not in self._fired_chains:
            self._fired_chains.add(chain_key_3)
            log.warning(f"[CRITICAL] T1021→T1059→T1552 FULL CHAIN on {event.get('namespace')}/{event.get('pod_name')}")
            alerts.append({
                "severity": "CRITICAL", "rule": "T1021→T1059→T1552",
                "description": "Full lateral movement chain: remote exec + shell + credential access",
                "pod_uid": pod_uid,
                "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"),
                "timestamp": event.get("timestamp"),
            })

        return alerts

    def snapshot(self):
        with self._lock:
            return nx.DiGraph(self.graph)
