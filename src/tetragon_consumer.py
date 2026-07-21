import subprocess
import json
import threading
import queue
import time
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
        self._exec_container_map = {}
        self._lock = threading.Lock()
        self._retry_buffer = []
        self._retry_lock = threading.Lock()
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
        threading.Thread(target=self._retry_loop, daemon=True).start()

    def _refresh_loop(self):
        while True:
            time.sleep(3)
            self._refresh_docker_map()

    def _resolve_uid(self, proc: dict):
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
            uid = self._exec_container_map.get(docker[:32])
            if uid:
                meta = self.cache.get_meta(uid)
                if meta:
                    return uid, meta["name"], meta["ns"]

            for prefix_len in [15, 12, 8]:
                uid = self._docker_map.get(docker[:prefix_len])
                if uid:
                    meta = self.cache.get_meta(uid)
                    if meta:
                        return uid, meta["name"], meta["ns"]

        return None, None, None

    def _learn_exec_container(self, proc: dict):
        binary = proc.get("binary", "")
        if "runc" not in binary:
            return

        args = proc.get("arguments", "")
        tokens = args.split()
        if not tokens:
            return

        full_container_id = tokens[-1]
        if len(full_container_id) < 32:
            return

        with self._lock:
            for prefix_len in [15, 12, 8]:
                uid = self._docker_map.get(full_container_id[:prefix_len])
                if uid:
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
                        self._learn_exec_container(inner_proc)

                        tagged = self._tag_event(raw)
                        if tagged:
                            self.out_queue.put(tagged)
                            if tagged.get("pod_uid"):
                                log.info(f"[QUEUED] {tagged['namespace']}/{tagged['pod_name']} | {tagged['binary']}")

                    if "process_kprobe" in raw:
                        fn = raw["process_kprobe"].get("function_name")
                        if fn == "tcp_connect":
                            tagged = self._tag_network_event(raw)
                            if tagged:
                                self.out_queue.put(tagged)
                                log.info(f"[NET] {tagged['namespace']}/{tagged['pod_name']} -> {tagged['dst_ip']}:{tagged['dst_port']}")
                        elif fn == "cap_capable":
                            tagged = self._tag_capability_event(raw)
                            if tagged:
                                self.out_queue.put(tagged)
                                log.info(f"[CAP] {tagged['namespace']}/{tagged['pod_name']} requested {tagged['capability']}")

                    if self.event_count % 200 == 0:
                        log.info(f"Processed {self.event_count} events")

                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    log.warning(f"Event error: {e}")
        except Exception as e:
            log.error(f"Stream error: {e}")

    def _tag_network_event(self, raw: dict):
        pk = raw.get("process_kprobe", {})
        if pk.get("function_name") != "tcp_connect":
            return None

        sock = None
        for a in pk.get("args", []):
            if "sock_arg" in a:
                sock = a["sock_arg"]
                break
        if not sock:
            return None

        saddr = sock.get("saddr", "")
        daddr = sock.get("daddr", "")
        dport = sock.get("dport", 0)
        sport = sock.get("sport", 0)

        if not saddr.startswith("10.244."):
            return None

        if daddr.startswith("127.") or daddr.startswith("172.18.") or daddr.startswith("::"):
            return None

        src_meta = self.cache.get_meta_by_ip(saddr)
        if not src_meta:
            return None

        src_uid = self.cache.resolve_by_ip(saddr)
        if not src_uid:
            return None

        if src_meta.get("ns") in ("kube-system", "local-path-storage"):
            return None

        dst_uid = self.cache.resolve_by_ip(daddr)
        dst_meta = self.cache.get_meta(dst_uid) if dst_uid else None
        dst_pod_name = dst_meta["name"] if dst_meta else daddr

        return {
            "timestamp": raw.get("time", datetime.now().isoformat()),
            "event_type": "network_connect",
            "node": raw.get("node_name", ""),
            "pod_uid": src_uid,
            "pod_name": src_meta["name"],
            "namespace": src_meta["ns"],
            "src_ip": saddr,
            "src_port": sport,
            "dst_ip": daddr,
            "dst_port": dport,
            "dst_pod_name": dst_pod_name,
            "dst_pod_uid": dst_uid,
            "binary": pk.get("process", {}).get("binary", ""),
        }

    CAPABILITY_NAMES = {
        16: "CAP_SYS_MODULE",
        19: "CAP_SYS_PTRACE",
        21: "CAP_SYS_ADMIN",
        22: "CAP_SYS_BOOT",
    }

    def _tag_capability_event(self, raw: dict):
        pk = raw.get("process_kprobe", {})
        proc = pk.get("process", {})
        if not proc:
            return None

        cap_value = None
        for a in pk.get("args", []):
            if "int_arg" in a:
                cap_value = a["int_arg"]
                break
        if cap_value is None:
            return None

        cap_name = self.CAPABILITY_NAMES.get(cap_value)
        if not cap_name:
            return None

        pod_uid, pod_name, namespace = self._resolve_uid(proc)
        if not pod_uid:
            return None
        if namespace in ("kube-system", "local-path-storage"):
            return None

        return {
            "timestamp": raw.get("time", datetime.now().isoformat()),
            "event_type": "capability_check",
            "node": raw.get("node_name", ""),
            "pod_uid": pod_uid,
            "pod_name": pod_name,
            "namespace": namespace,
            "capability": cap_name,
            "binary": proc.get("binary", ""),
        }

    def _tag_event(self, raw: dict):
        if "process_exec" not in raw:
            return None

        proc = raw["process_exec"]["process"]
        binary = proc.get("binary", "")

        if binary in ("/usr/bin/runc", "/proc/self/fd/6", "<kernel>"):
            return None

        pod_uid, pod_name, namespace = self._resolve_uid(proc)

        if not pod_uid:
            has_container_ref = bool(proc.get("docker")) or "pod" in proc
            if has_container_ref:
                with self._retry_lock:
                    self._retry_buffer.append({
                        "proc": proc,
                        "raw_time": raw.get("time", datetime.now().isoformat()),
                        "binary": binary,
                        "exec_id": proc.get("exec_id", ""),
                        "parent_exec_id": proc.get("parent_exec_id", ""),
                        "first_seen": time.time(),
                    })
            return None

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

    def _retry_loop(self):
        while True:
            time.sleep(0.3)
            with self._retry_lock:
                pending = self._retry_buffer
                self._retry_buffer = []

            still_pending = []
            for entry in pending:
                pod_uid, pod_name, namespace = self._resolve_uid(entry["proc"])
                if pod_uid:
                    tagged = {
                        "timestamp": entry["raw_time"],
                        "event_type": "process_exec",
                        "node": "",
                        "pod_uid": pod_uid,
                        "pod_name": pod_name,
                        "namespace": namespace,
                        "binary": entry["binary"],
                        "exec_id": entry["exec_id"],
                        "parent_exec_id": entry["parent_exec_id"],
                    }
                    self.out_queue.put(tagged)
                    log.info(f"[RETRY-RESOLVED] {namespace}/{pod_name} | {entry['binary']}")
                elif time.time() - entry["first_seen"] < 2.0:
                    still_pending.append(entry)
                else:
                    log.warning(f"[DROPPED] Could not resolve pod_uid for {entry['binary']} after 2s retry window")

            with self._retry_lock:
                self._retry_buffer.extend(still_pending)
