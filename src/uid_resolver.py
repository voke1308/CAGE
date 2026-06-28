import threading
import logging
from kubernetes import client, config, watch

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("uid-resolver")

class PodUIDCache:
    """
    Live cache of pod identity mappings, updated via K8s watch.
    Thread-safe. Three lookup dimensions:
      (namespace, pod_name) -> uid
      pod_ip               -> uid
      (namespace, sa_name) -> set of uids
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._name_to_uid = {}   # (ns, name) -> uid
        self._ip_to_uid   = {}   # ip -> uid
        self._sa_to_uids  = {}   # (ns, sa) -> set(uid)
        self._uid_to_meta = {}   # uid -> {name, ns, ip, sa, node}

    # ── lookups ──────────────────────────────────────────────────────────────

    def resolve_by_name(self, namespace, pod_name):
        with self._lock:
            return self._name_to_uid.get((namespace, pod_name))

    def resolve_by_ip(self, ip):
        with self._lock:
            return self._ip_to_uid.get(ip)

    def resolve_by_sa(self, namespace, sa_name):
        with self._lock:
            return self._sa_to_uids.get((namespace, sa_name), set())

    def get_meta(self, uid):
        with self._lock:
            return self._uid_to_meta.get(uid)

    def get_meta_by_ip(self, ip: str):
        """Lookup pod metadata by pod IP address."""
        with self._lock:
            uid = self._ip_to_uid.get(ip)
            if uid:
                return self.get_meta(uid)
        return None

    def snapshot(self):
        with self._lock:
            return dict(self._uid_to_meta)

    # ── internal mutators ────────────────────────────────────────────────────

    def _add(self, pod):
        uid  = pod.metadata.uid
        name = pod.metadata.name
        ns   = pod.metadata.namespace
        ip   = pod.status.pod_ip if pod.status else None
        sa   = pod.spec.service_account_name if pod.spec else None
        node = pod.spec.node_name if pod.spec else None

        with self._lock:
            self._name_to_uid[(ns, name)] = uid
            if ip:
                self._ip_to_uid[ip] = uid
            if sa:
                self._sa_to_uids.setdefault((ns, sa), set()).add(uid)
            self._uid_to_meta[uid] = dict(name=name, ns=ns, ip=ip, sa=sa, node=node)

        log.info(f"[ADD] {ns}/{name} uid={uid} ip={ip} sa={sa}")

    def _remove(self, pod):
        uid  = pod.metadata.uid
        name = pod.metadata.name
        ns   = pod.metadata.namespace
        ip   = pod.status.pod_ip if pod.status else None
        sa   = pod.spec.service_account_name if pod.spec else None

        with self._lock:
            self._name_to_uid.pop((ns, name), None)
            if ip:
                self._ip_to_uid.pop(ip, None)
            if sa:
                uids = self._sa_to_uids.get((ns, sa), set())
                uids.discard(uid)
            self._uid_to_meta.pop(uid, None)

        log.info(f"[DEL] {ns}/{name} uid={uid}")

    # ── watcher (runs in background thread) ──────────────────────────────────

    def start_watch(self):
        t = threading.Thread(target=self._watch_loop, daemon=True)
        t.start()
        log.info("Pod UID cache watcher started")

    def _watch_loop(self):
        config.load_kube_config()
        v1 = client.CoreV1Api()
        w  = watch.Watch()

        while True:
            try:
                for event in w.stream(v1.list_pod_for_all_namespaces, timeout_seconds=0):
                    etype = event["type"]   # ADDED / MODIFIED / DELETED
                    pod   = event["object"]
                    if etype in ("ADDED", "MODIFIED"):
                        self._add(pod)
                    elif etype == "DELETED":
                        self._remove(pod)
            except Exception as e:
                log.warning(f"Watch error (will retry): {e}")


# ── quick smoke-test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import time

    cache = PodUIDCache()
    cache.start_watch()

    time.sleep(3)   # let initial list populate

    print("\n=== Pod UID Cache Snapshot ===")
    for uid, meta in cache.snapshot().items():
        print(f"  uid={uid[:8]}...  name={meta['ns']}/{meta['name']}  ip={meta['ip']}  node={meta['node']}")

    print(f"\nTotal pods cached: {len(cache.snapshot())}")

    # test a lookup
    snap = cache.snapshot()
    if snap:
        sample_uid = next(iter(snap))
        meta = cache.get_meta(sample_uid)
        print(f"\nLookup by UID test: {meta}")
        if meta['ip']:
            resolved = cache.resolve_by_ip(meta['ip'])
            print(f"Lookup by IP {meta['ip']} -> uid={resolved[:8]}...")


def build_docker_id_map(cache: PodUIDCache) -> dict:
    """
    Build a map of container_id_prefix (12 chars) -> pod_uid
    by querying pod container statuses from K8s API.
    Called once at startup and refreshed periodically.
    """
    config.load_kube_config()
    v1 = client.CoreV1Api()
    docker_map = {}

    pods = v1.list_pod_for_all_namespaces(watch=False)
    for pod in pods.items:
        uid = pod.metadata.uid
        if not pod.status or not pod.status.container_statuses:
            continue
        for cs in pod.status.container_statuses:
            if cs.container_id:
                # container_id looks like: docker://9335dcee926778...
                raw_id = cs.container_id.split("://")[-1]
                # Tetragon uses first 15 chars of the ID
                for prefix_len in (15, 12, 8):
                    docker_map[raw_id[:prefix_len]] = uid

    return docker_map
