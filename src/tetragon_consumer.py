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

    def start(self):
        t = threading.Thread(target=self._consume_loop, daemon=True)
        t.start()

    def _consume_loop(self):
        cmd = [
            "kubectl", "exec", "-n", "kube-system",
            "ds/tetragon", "-c", "tetragon", "--",
            "tetra", "getevents"
        ]
        log.info("Starting Tetragon consumer")
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            
            def refresh_docker_map():
                import time
                while True:
                    time.sleep(30)
                    try:
                        docker_map = build_docker_id_map(self.cache)
                        log.info(f"Docker→UID map refreshed: {len(docker_map)} entries")
                    except Exception as e:
                        log.warning(f"Failed to refresh docker map: {e}")
            
            t = threading.Thread(target=refresh_docker_map, daemon=True)
            t.start()
            log.info("Tetragon consumer started")
            
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    raw = json.loads(line)
                    self.event_count += 1
                    tagged = self._tag_event(raw)
                    if tagged:
                        self.out_queue.put(tagged)
                    if self.event_count % 100 == 0:
                        log.info(f"Processed {self.event_count} events")
                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    log.warning(f"Error processing event: {e}")
                    
        except Exception as e:
            log.error(f"Tetragon consumer error: {e}")

    def _tag_event(self, raw: dict) -> dict | None:
        if "process_exec" not in raw:
            return None
        
        proc = raw["process_exec"]["process"]
        binary = proc.get("binary", "")
        exec_id = proc.get("exec_id", "")
        
        pod_uid = None
        pod_name = None
        namespace = None
        strategy = "unresolved"
        
        if "pod" in proc:
            pod_uid = proc["pod"].get("uid")
            pod_name = proc["pod"].get("name")
            namespace = proc["pod"].get("namespace")
            strategy = "tetragon"
        else:
            docker = proc.get("docker", "")
            if docker:
                docker_map = build_docker_id_map(self.cache)
                for prefix_len in [15, 12, 8]:
                    prefix = docker[:prefix_len]
                    if prefix in docker_map:
                        # build_docker_id_map returns (pod_uid, pod_name, namespace, ...)
                        result = docker_map[prefix]
                        pod_uid = result[0]
                        pod_name = result[1]
                        namespace = result[2]
                        strategy = f"docker({prefix_len})"
                        break
        
        return {
            "timestamp": raw.get("time", datetime.now().isoformat()),
            "event_type": "process_exec",
            "node": raw.get("node_name", "unknown"),
            "pod_uid": pod_uid,
            "pod_name": pod_name,
            "namespace": namespace,
            "binary": binary,
            "exec_id": exec_id,
            "resolve_strategy": strategy,
        }
