import subprocess
import json
import threading
import queue
import logging
import time
from kubernetes import client, config
from src.uid_resolver import PodUIDCache, build_docker_id_map

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("tetragon-consumer")

class TetragonConsumer:
    def __init__(self, cache: PodUIDCache, out_queue: queue.Queue):
        self.cache = cache
        self.out_queue = out_queue
        self._docker_map = {}
        self._docker_map_lock = threading.RLock()
        self._refresh_docker_map()
        # refresh docker map every 30s
        t = threading.Thread(target=self._refresh_loop, daemon=True)
        t.start()

    def _refresh_docker_map(self):
        try:
            new_map = build_docker_id_map(self.cache)
            with self._docker_map_lock:
                self._docker_map = new_map
            log.info(f"Docker→UID map refreshed: {len(new_map)} entries")
        except Exception as e:
            log.warning(f"Docker map refresh failed: {e}")

    def _refresh_loop(self):
        while True:
            time.sleep(30)
            self._refresh_docker_map()

    def _resolve_uid(self, event: dict) -> tuple:
        """Returns (uid, strategy_used)"""
        for key in ("process_exec", "process_exit", "process_kprobe"):
            proc = event.get(key, {}).get("process", {})
            pod = proc.get("pod", {})

            # Strategy 1: Tetragon already has pod.uid
            if pod.get("uid"):
                return pod["uid"], "tetragon"

            # Strategy 2: name+namespace lookup
            ns, name = pod.get("namespace"), pod.get("name")
            if ns and name:
                uid = self.cache.resolve_by_name(ns, name)
                if uid:
                    return uid, "name"

            # Strategy 3: docker container ID prefix
            docker_id = proc.get("docker", "")
            if docker_id:
                with self._docker_map_lock:
                    for prefix_len in (15, 12, 8):
                        uid = self._docker_map.get(docker_id[:prefix_len])
                        if uid:
                            return uid, f"docker({prefix_len})"

        return None, None

    def _tag_event(self, raw: dict) -> dict:
        uid, strategy = self._resolve_uid(raw)
        meta = self.cache.get_meta(uid) if uid else None
        event_type = next((k for k in raw if k.startswith("process_")), "unknown")
        proc_block = raw.get(event_type, {}).get("process", {})

        return {
            "timestamp":       raw.get("time"),
            "event_type":      event_type,
            "node":            raw.get("node_name"),
            "pod_uid":         uid,
            "pod_name":        meta["name"] if meta else proc_block.get("pod", {}).get("name"),
            "namespace":       meta["ns"]   if meta else proc_block.get("pod", {}).get("namespace"),
            "binary":          proc_block.get("binary"),
            "args":            proc_block.get("arguments"),
            "exec_id":         proc_block.get("exec_id"),
            "parent_exec_id":  proc_block.get("parent_exec_id"),
            "resolve_strategy": strategy,
        }

    def start(self):
        t = threading.Thread(target=self._stream_loop, daemon=True)
        t.start()
        log.info("Tetragon consumer started")

    def _stream_loop(self):
        cmd = ["kubectl", "exec", "-n", "kube-system",
               "ds/tetragon", "-c", "tetragon", "--", "tetra", "getevents"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self.out_queue.put(self._tag_event(json.loads(line)))
            except json.JSONDecodeError:
                pass


if __name__ == "__main__":
    cache = PodUIDCache()
    cache.start_watch()
    time.sleep(2)

    q = queue.Queue()
    consumer = TetragonConsumer(cache, q)
    consumer.start()

    log.info("Listening (Ctrl+C to stop)...")
    stats = {"resolved": 0, "unresolved": 0, "by_strategy": {}}

    try:
        while True:
            try:
                ev = q.get(timeout=1)
                if ev["pod_uid"]:
                    stats["resolved"] += 1
                    s = ev["resolve_strategy"]
                    stats["by_strategy"][s] = stats["by_strategy"].get(s, 0) + 1
                    print(f"[{s.upper():12}] {ev['namespace']}/{ev['pod_name']} | {ev['binary']}")
                else:
                    stats["unresolved"] += 1
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        total = stats["resolved"] + stats["unresolved"]
        pct = stats["resolved"]/total*100 if total else 0
        print(f"\n--- Stats ---")
        print(f"Resolution rate: {pct:.1f}% ({stats['resolved']}/{total})")
        print(f"By strategy: {stats['by_strategy']}")
