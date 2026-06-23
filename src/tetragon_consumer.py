import subprocess
import json
import threading
import queue
import logging
from datetime import datetime
from src.uid_resolver import PodUIDCache, build_docker_id_map

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("tetragon-consumer")

class TetragonConsumer:
    def __init__(self, cache: PodUIDCache, out_queue: queue.Queue):
        self.cache = cache
        self.out_queue = out_queue
        self.event_count = 0
        self._docker_map = {}
        self._exec_container_map = {}  # exec-spawned container ID -> pod UID
        self._lock = threading.Lock()
        self._refresh_docker_map()

    def _refresh_docker_map(self):
        try:
            m = build_docker_id_map(self.cache)
            with self._lock:
                self._docker_map = m
            log.info(f"Docker→UID map: {len(m)} entries")
        except Exception as e:
            log.warning(f"Docker map refresh failed: {e}")

    def start(self):
        threading.Thread(target=self._refresh_loop, daemon=True).start()
        threading.Thread(target=self._consume_loop, daemon=True).start()

    def _refresh_loop(self):
        import time
        while True:
            time.sleep(30)
            self._refresh_docker_map()

    def _resolve_uid(self, proc: dict):
        """Returns (pod_uid, pod_name, namespace) or (None, None, None)"""
        
        # Strategy 1: Tetragon native pod field
        if "pod" in proc:
            pod = proc["pod"]
            uid = pod.get("uid")
            meta = self.cache.get_meta(uid) if uid else None
            if meta:
                return uid, meta["name"], meta["ns"]
            return uid, pod.get("name"), pod.get("namespace")

        docker = proc.get("docker", "")
        if not docker:
            return None, None, None

        with self._lock:
            # Strategy 2: known exec container map (built from runc args)
            uid = self._exec_container_map.get(docker[:32])
            if uid:
                meta = self.cache.get_meta(uid)
                if meta:
                    return uid, meta["name"], meta["ns"]

            # Strategy 3: docker map (known container IDs from K8s API)
            for prefix_len in [15, 12, 8]:
                uid = self._docker_map.get(docker[:prefix_len])
                if uid:
                    meta = self.cache.get_meta(uid)
                    if meta:
                        return uid, meta["name"], meta["ns"]

        return None, None, None

    def _learn_exec_container(self, proc: dict):
        """
        When runc exec runs, its arguments contain the full container ID.
        Map that ID back to the pod UID using known docker map entries.
        e.g. runc ... exec ... 4bd905b42b92a8d3d57b23f7faf8713c86314b63e44a1db969402403814333e3
        """
        binary = proc.get("binary", "")
        if "runc" not in binary:
            return

        args = proc.get("arguments", "")
        # The last token in runc exec args is the full container ID
        tokens = args.split()
        if not tokens:
            return

        full_container_id = tokens[-1]
        if len(full_container_id) < 32:
            return

        # Try to find which pod owns this container ID by prefix matching
        with self._lock:
            for prefix_len in [15, 12, 8]:
                uid = self._docker_map.get(full_container_id[:prefix_len])
                if uid:
                    # Map the full exec container ID to this pod UID
                    self._exec_container_map[full_container_id[:32]] = uid
                    meta = self.cache.get_meta(uid)
                    pod_name = meta["name"] if meta else "unknown"
                    log.info(f"[LEARNED] exec container {full_container_id[:12]}... -> {pod_name}")
                    return

    def _consume_loop(self):
        cmd = [
            "kubectl", "exec", "-n", "kube-system",
            "ds/tetragon", "-c", "tetragon", "--",
            "tetra", "getevents"
        ]
        log.info("Tetragon consumer started")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
            for line in iter(proc.stdout.readline, ''):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    self.event_count += 1

                    if "process_exec" in raw:
                        inner_proc = raw["process_exec"]["process"]
                        # Learn exec containers from runc events
                        self._learn_exec_container(inner_proc)

                        tagged = self._tag_event(raw)
                        if tagged:
                            self.out_queue.put(tagged)
                            if tagged.get("pod_uid"):
                                log.info(f"[QUEUED] {tagged['namespace']}/{tagged['pod_name']} | {tagged['binary']}")

                    if self.event_count % 200 == 0:
                        log.info(f"Processed {self.event_count} events")

                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    log.warning(f"Event error: {e}")
        except Exception as e:
            log.error(f"Stream error: {e}")

    def _tag_event(self, raw: dict):
        if "process_exec" not in raw:
            return None

        proc = raw["process_exec"]["process"]
        binary = proc.get("binary", "")

        # Skip runc/kernel internals
        if binary in ("/usr/bin/runc", "/proc/self/fd/6", "<kernel>"):
            return None

        pod_uid, pod_name, namespace = self._resolve_uid(proc)

        return {
            "timestamp": raw.get("time", datetime.now().isoformat()),
            "event_type": "process_exec",
            "node": raw.get("node_name", ""),
            "pod_uid": pod_uid,
            "pod_name": pod_name,
            "namespace": namespace,
            "binary": binary,
            "exec_id": proc.get("exec_id", ""),
            "parent_exec_id": proc.get("parent_exec_id", ""),
        }
