import threading
import logging
from datetime import datetime, timedelta
import networkx as nx

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("causal-graph")

SHELL_WHITELIST_NAMESPACES = {"kube-system", "local-path-storage"}
SHELL_WHITELIST_POD_PREFIXES = ("legitimate-app", "debug-", "init-", "victim")

# --- Container escape (T1611) ---
ESCAPE_BINARIES = {
    "/usr/bin/nsenter", "/bin/nsenter",
    "/usr/bin/unshare", "/bin/unshare",
    "/usr/sbin/chroot", "/bin/chroot", "/usr/bin/chroot",
    "/usr/bin/capsh", "/bin/capsh",
}
ESCAPE_ARG_INDICATORS = (
    "docker.sock", "containerd.sock", "/proc/1/root", "/proc/1/ns",
    "/var/lib/docker", "core_pattern", "release_agent",
)
DANGEROUS_CAPABILITIES = {
    "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE",
    "CAP_SYS_BOOT", "CAP_DAC_READ_SEARCH", "CAP_SYS_RAWIO",
}

# --- Privilege escalation (T1548) ---
PRIV_ESC_BINARIES = {
    "/usr/bin/sudo", "/bin/sudo",
    "/usr/bin/su", "/bin/su",
    "/usr/sbin/setcap", "/sbin/setcap", "/usr/bin/setcap",
}

# --- Resource abuse / DoS (T1499 fork-bomb, T1496 cryptomining) ---
CRYPTOMINING_INDICATORS = (
    "xmrig", "minerd", "cpuminer", "ethminer", "cgminer",
    "stratum+tcp", "nanominer", "teamredminer",
)
FORK_BOMB_EXEC_THRESHOLD = 25      # execs from the same pod...
FORK_BOMB_WINDOW_SECONDS = 10      # ...within this many seconds

# --- Network scan/lateral-movement burst detection (T1610) ---
CONNECTION_BURST_THRESHOLD = 5        # distinct destination pods...
CONNECTION_BURST_WINDOW_SECONDS = 10  # ...within this many seconds

# --- Shell / remote-exec correlation (T1059) ---
REMOTE_EXEC_CORRELATION_SECONDS = 10  # T1059 within this long after a T1021 is more suspicious

class CausalGraph:
    def __init__(self):
        self._lock = threading.RLock()
        self.graph = nx.DiGraph()
        self.alerts = []
        self._event_window = {}
        self._fired_chains = set()
        self._exec_burst = {}       # pod_uid -> [timestamps] for fork-bomb detection
        self._conn_burst = {}       # pod_uid -> [(timestamp, dst_pod_name)] for T1610 scan detection

    def add_event(self, event: dict) -> list:
        with self._lock:
            alerts = []

            for check in (self._check_t1059, self._check_t1021, self._check_t1552, self._check_t1610,
                          self._check_t1611_escape, self._check_t1548_privesc,
                          self._check_resource_abuse, self._check_privileged_pod,
                          self._check_rbac_abuse, self._check_rbac_discovery):
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

    def _recent_remote_exec(self, pod_uid, current_ts):
        """True if a T1021 (kubectl exec) event for this pod landed within the
        correlation window just before current_ts."""
        for t, e in self._event_window.get(pod_uid, []):
            if e.get("event_type") == "pod_exec" and \
               (current_ts - t) < timedelta(seconds=REMOTE_EXEC_CORRELATION_SECONDS):
                return True
        return False

    def _check_t1059(self, event):
        if event.get("event_type") != "process_exec":
            return None
        if not event.get("pod_uid") or self._is_whitelisted(event):
            return None
        binary = event.get("binary", "")
        if binary not in ("/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"):
            return None

        pod_uid = event["pod_uid"]
        try:
            ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        except Exception:
            ts = None

        correlated = bool(ts) and self._recent_remote_exec(pod_uid, ts)
        severity = "MEDIUM" if correlated else "LOW"

        log.warning(f"[{severity}] T1059: Shell in {event.get('namespace')}/{event.get('pod_name')}"
                    + (" (preceded by kubectl exec)" if correlated else " (no remote-exec correlation)"))
        return {
            "severity": severity, "rule": "T1059",
            "description": "Shell execution inside pod"
                            + (" following remote exec session" if correlated else ""),
            "pod_uid": pod_uid,
            "pod_name": event.get("pod_name"),
            "namespace": event.get("namespace"),
            "binary": binary,
            "correlated_with_t1021": correlated,
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

    def _check_t1610(self, event):
        """Network lateral movement: flag scan-like bursts (connections to several
        distinct pods in a short window), not a single ordinary pod-to-pod call."""
        if event.get("event_type") != "network_connect":
            return None
        if self._is_whitelisted(event):
            return None
        dst = event.get("dst_pod_name", "")
        src = event.get("pod_name", "")
        # Only flag cross-pod connections (not external IPs)
        if not dst or dst == src or not event.get("dst_pod_uid"):
            return None

        pod_uid = event.get("pod_uid")
        try:
            now = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        except Exception:
            return None

        self._conn_burst.setdefault(pod_uid, []).append((now, dst))
        self._conn_burst[pod_uid] = [
            (t, d) for t, d in self._conn_burst[pod_uid]
            if (now - t) < timedelta(seconds=CONNECTION_BURST_WINDOW_SECONDS)
        ]
        distinct_dsts = {d for _, d in self._conn_burst[pod_uid]}
        if len(distinct_dsts) < CONNECTION_BURST_THRESHOLD:
            return None

        log.warning(f"[MEDIUM] T1610: Network scan-like burst from {src}: "
                    f"{len(distinct_dsts)} distinct pods in {CONNECTION_BURST_WINDOW_SECONDS}s")
        return {
            "severity": "MEDIUM", "rule": "T1610",
            "description": f"Lateral movement scan: {len(distinct_dsts)} pods contacted "
                            f"in {CONNECTION_BURST_WINDOW_SECONDS}s",
            "pod_uid": pod_uid,
            "pod_name": src,
            "namespace": event.get("namespace"),
            "dst_pod_name": dst,
            "dst_pod_uid": event.get("dst_pod_uid"),
            "dst_port": event.get("dst_port"),
            "timestamp": event.get("timestamp"),
        }

    def _check_t1611_escape(self, event):
        """Container escape: escape-tool binaries, or args touching host runtime
        sockets / cgroup release_agent / proc-based host filesystem access, or
        exec requesting a dangerous kernel capability."""
        if event.get("event_type") == "capability_check":
            if event.get("capability") in DANGEROUS_CAPABILITIES and not self._is_whitelisted(event):
                log.warning(f"[HIGH] T1611: dangerous capability {event.get('capability')} "
                            f"requested by {event.get('namespace')}/{event.get('pod_name')}")
                return {
                    "severity": "HIGH", "rule": "T1611",
                    "description": f"Container escape indicator: process requested {event.get('capability')}",
                    "pod_uid": event.get("pod_uid"), "pod_name": event.get("pod_name"),
                    "namespace": event.get("namespace"), "timestamp": event.get("timestamp"),
                }
            return None

        if event.get("event_type") != "process_exec":
            return None
        if not event.get("pod_uid") or self._is_whitelisted(event):
            return None

        binary = event.get("binary", "")
        args = event.get("arguments", "") or ""
        hit_binary = binary in ESCAPE_BINARIES
        hit_arg = any(ind in args for ind in ESCAPE_ARG_INDICATORS)
        if not (hit_binary or hit_arg):
            return None

        log.warning(f"[HIGH] T1611: escape indicator '{binary} {args}' in "
                    f"{event.get('namespace')}/{event.get('pod_name')}")
        return {
            "severity": "HIGH", "rule": "T1611",
            "description": "Container escape indicator: namespace/host-runtime tooling or "
                            "host filesystem escape path used inside container",
            "pod_uid": event["pod_uid"], "pod_name": event.get("pod_name"),
            "namespace": event.get("namespace"), "binary": binary,
            "timestamp": event.get("timestamp"),
        }

    def _check_t1548_privesc(self, event):
        """Privilege escalation via sudo/su/setcap inside a container."""
        if event.get("event_type") != "process_exec":
            return None
        if not event.get("pod_uid") or self._is_whitelisted(event):
            return None
        binary = event.get("binary", "")
        if binary not in PRIV_ESC_BINARIES:
            return None
        log.warning(f"[HIGH] T1548: privilege escalation attempt '{binary}' in "
                    f"{event.get('namespace')}/{event.get('pod_name')}")
        return {
            "severity": "HIGH", "rule": "T1548",
            "description": f"Privilege escalation attempt inside container ({binary})",
            "pod_uid": event["pod_uid"], "pod_name": event.get("pod_name"),
            "namespace": event.get("namespace"), "binary": binary,
            "timestamp": event.get("timestamp"),
        }

    def _check_resource_abuse(self, event):
        """Resource abuse / DoS: known cryptominer binaries, or a fork-bomb-like
        burst of process_exec events from a single pod in a short window."""
        if event.get("event_type") != "process_exec":
            return None
        if not event.get("pod_uid") or self._is_whitelisted(event):
            return None

        binary = (event.get("binary") or "").lower()
        args = (event.get("arguments") or "").lower()
        if any(ind in binary or ind in args for ind in CRYPTOMINING_INDICATORS):
            log.warning(f"[HIGH] T1496: cryptomining indicator in "
                        f"{event.get('namespace')}/{event.get('pod_name')}")
            return {
                "severity": "HIGH", "rule": "T1496",
                "description": "Resource hijacking indicator: cryptomining process signature",
                "pod_uid": event["pod_uid"], "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"), "binary": event.get("binary"),
                "timestamp": event.get("timestamp"),
            }

        pod_uid = event["pod_uid"]
        ts_raw = event.get("timestamp")
        if not ts_raw:
            return None
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except Exception:
            return None

        window = self._exec_burst.setdefault(pod_uid, [])
        window.append(ts)
        cutoff = ts - timedelta(seconds=FORK_BOMB_WINDOW_SECONDS)
        self._exec_burst[pod_uid] = [t for t in window if t > cutoff]

        if len(self._exec_burst[pod_uid]) >= FORK_BOMB_EXEC_THRESHOLD:
            burst_key = (pod_uid, "T1499_BURST")
            if burst_key in self._fired_chains:
                return None
            self._fired_chains.add(burst_key)
            log.warning(f"[HIGH] T1499: fork-bomb-like exec burst in "
                        f"{event.get('namespace')}/{event.get('pod_name')}")
            return {
                "severity": "HIGH", "rule": "T1499",
                "description": f"Endpoint DoS indicator: {len(self._exec_burst[pod_uid])} "
                                f"process executions within {FORK_BOMB_WINDOW_SECONDS}s (possible fork bomb)",
                "pod_uid": pod_uid, "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"), "timestamp": event.get("timestamp"),
            }
        return None

    def _check_privileged_pod(self, event):
        """Privileged workload deployed (from K8s audit log pod-create inspection)."""
        if event.get("event_type") != "privileged_pod_created":
            return None
        log.warning(f"[HIGH] T1548: privileged pod created "
                    f"{event.get('namespace')}/{event.get('pod_name')} ({event.get('reason')})")
        return {
            "severity": "HIGH", "rule": "T1548-PRIV-POD",
            "description": f"Privileged workload deployed: {event.get('reason')}",
            "pod_uid": event.get("pod_uid"), "pod_name": event.get("pod_name"),
            "namespace": event.get("namespace"), "user": event.get("user"),
            "timestamp": event.get("timestamp"),
        }

    def _check_rbac_abuse(self, event):
        """RBAC abuse: binding to cluster-admin, wildcard Role/ClusterRole,
        or impersonation/token-request against another identity."""
        if event.get("event_type") != "rbac_abuse":
            return None
        log.warning(f"[CRITICAL] RBAC-ABUSE: {event.get('reason')} by {event.get('user')}")
        return {
            "severity": "CRITICAL", "rule": "T1548.005",
            "description": f"RBAC abuse: {event.get('reason')}",
            "pod_uid": event.get("pod_uid"), "pod_name": event.get("pod_name", "<cluster>"),
            "namespace": event.get("namespace", "cluster-wide"), "user": event.get("user"),
            "timestamp": event.get("timestamp"),
        }

    def _check_rbac_discovery(self, event):
        """Discovery: burst of get/list calls on RBAC objects by one identity."""
        if event.get("event_type") != "rbac_discovery":
            return None
        log.warning(f"[MEDIUM] T1613: RBAC/resource discovery burst by {event.get('user')}")
        return {
            "severity": "MEDIUM", "rule": "T1613",
            "description": f"Container and resource discovery: {event.get('count')} RBAC "
                            f"reads by {event.get('user')} in {event.get('window_seconds')}s",
            "pod_uid": event.get("pod_uid"), "pod_name": event.get("pod_name", "<cluster>"),
            "namespace": event.get("namespace", "cluster-wide"), "user": event.get("user"),
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
        # Same burst threshold as _check_t1610 — a single ordinary connection
        # must not be enough to satisfy this leg of the chain either.
        has_t1610 = len({d for _, d in self._conn_burst.get(pod_uid, [])}) >= CONNECTION_BURST_THRESHOLD

        alerts = []

        # Two-hop: T1059 → T1552
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

        # Three-hop: T1021 → T1059 → T1552
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

        # Four-hop: T1059 → T1610 → T1552 (new — network lateral movement)
        chain_key_4 = (pod_uid, "T1059->T1610->T1552")
        if has_t1059 and has_t1610 and has_t1552 and chain_key_4 not in self._fired_chains:
            self._fired_chains.add(chain_key_4)
            log.warning(f"[CRITICAL] T1059→T1610→T1552 NETWORK CHAIN on {event.get('namespace')}/{event.get('pod_name')}")
            alerts.append({
                "severity": "CRITICAL", "rule": "T1059→T1610→T1552",
                "description": "Shell → lateral network connection → secret access (eBPF network telemetry)",
                "pod_uid": pod_uid,
                "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"),
                "timestamp": event.get("timestamp"),
            })

        has_t1611 = bool(binaries & ESCAPE_BINARIES) or any(
            any(ind in (e.get("arguments") or "") for ind in ESCAPE_ARG_INDICATORS)
            for _, e in events
        )
        has_t1548 = bool(binaries & PRIV_ESC_BINARIES)

        # Escalation chain: shell -> privilege escalation -> container escape
        chain_key_5 = (pod_uid, "T1059->T1548->T1611")
        if has_t1059 and has_t1548 and has_t1611 and chain_key_5 not in self._fired_chains:
            self._fired_chains.add(chain_key_5)
            log.warning(f"[CRITICAL] T1059→T1548→T1611 ESCALATION CHAIN on "
                        f"{event.get('namespace')}/{event.get('pod_name')}")
            alerts.append({
                "severity": "CRITICAL", "rule": "T1059->T1548->T1611",
                "description": "Shell access, privilege escalation, then container escape attempt",
                "pod_uid": pod_uid, "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"), "timestamp": event.get("timestamp"),
            })

        # Breakout chain: container escape -> credential theft on the node
        chain_key_6 = (pod_uid, "T1611->T1552")
        if has_t1611 and has_t1552 and chain_key_6 not in self._fired_chains:
            self._fired_chains.add(chain_key_6)
            log.warning(f"[CRITICAL] T1611→T1552 BREAKOUT CHAIN on "
                        f"{event.get('namespace')}/{event.get('pod_name')}")
            alerts.append({
                "severity": "CRITICAL", "rule": "T1611->T1552",
                "description": "Container escape indicator followed by credential access",
                "pod_uid": pod_uid, "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"), "timestamp": event.get("timestamp"),
            })

        return alerts

    def snapshot(self):
        with self._lock:
            return nx.DiGraph(self.graph)
