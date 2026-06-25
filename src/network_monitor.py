import subprocess
import threading
import queue
import logging
import time
import socket
import struct

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("network-monitor")

def hex_to_ip(hex_str):
    addr = int(hex_str, 16)
    return socket.inet_ntoa(struct.pack("<I", addr))

def hex_to_port(hex_str):
    return int(hex_str, 16)

def read_proc_net_tcp(pod_name):
    """Read /proc/net/tcp from inside a pod via kubectl exec"""
    try:
        result = subprocess.run(
            ["kubectl", "exec", pod_name, "--", "cat", "/proc/net/tcp"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout
    except Exception:
        return ""

def parse_tcp_connections(raw):
    connections = []
    for line in raw.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[1]
        remote = parts[2]
        state = parts[3]
        # state 01 = ESTABLISHED
        if state != "01":
            continue
        local_ip, local_port = local.split(":")
        remote_ip, remote_port = remote.split(":")
        connections.append({
            "local_ip": hex_to_ip(local_ip),
            "local_port": hex_to_port(local_port),
            "remote_ip": hex_to_ip(remote_ip),
            "remote_port": hex_to_port(remote_port),
        })
    return connections

class NetworkMonitor:
    def __init__(self, cache, out_queue: queue.Queue, poll_interval=5):
        self.cache = cache
        self.out_queue = out_queue
        self.poll_interval = poll_interval
        self._seen = set()  # avoid duplicate events

    def start(self, pods_to_monitor=None):
        self._pods = pods_to_monitor or ["attacker"]
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        log.info(f"Network monitor started, watching pods: {self._pods}")

    def _loop(self):
        while True:
            for pod_name in self._pods:
                try:
                    self._check_pod(pod_name)
                except Exception as e:
                    log.warning(f"Error checking {pod_name}: {e}")
            time.sleep(self.poll_interval)

    def _check_pod(self, pod_name):
        raw = read_proc_net_tcp(pod_name)
        if not raw:
            return

        conns = parse_tcp_connections(raw)
        for conn in conns:
            remote_ip = conn["remote_ip"]
            
            # Skip loopback and kubernetes API server
            if remote_ip.startswith("127.") or remote_ip == "10.96.0.1":
                continue

            # Look up source pod UID
            src_uid = self.cache.resolve_by_name("default", pod_name)
            
            # Look up destination pod UID
            dst_uid = self.cache.resolve_by_ip(remote_ip)
            dst_meta = self.cache.get_meta(dst_uid) if dst_uid else None
            dst_name = dst_meta["name"] if dst_meta else remote_ip

            key = (pod_name, remote_ip, conn["remote_port"])
            if key in self._seen:
                continue
            self._seen.add(key)

            log.info(f"[NET] {pod_name} -> {dst_name} ({remote_ip}:{conn['remote_port']})")

            self.out_queue.put({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event_type": "network_connect",
                "src_pod": pod_name,
                "src_uid": src_uid,
                "dst_ip": remote_ip,
                "dst_port": conn["remote_port"],
                "dst_pod": dst_name,
                "dst_uid": dst_uid,
                "namespace": "default",
                "pod_uid": src_uid,
                "pod_name": pod_name,
            })

if __name__ == "__main__":
    from src.uid_resolver import PodUIDCache
    from kubernetes import config
    config.load_kube_config()

    cache = PodUIDCache()
    cache.start_watch()
    time.sleep(2)

    q = queue.Queue()
    monitor = NetworkMonitor(cache, q)
    monitor.start(pods_to_monitor=["attacker"])

    # Make attacker connect to victim
    VICTIM_IP = "10.244.2.4"
    log.info(f"Triggering connection from attacker to victim ({VICTIM_IP})...")
    subprocess.Popen(
        ["kubectl", "exec", "attacker", "--",
         "bash", "-c", f"cat /proc/version > /dev/tcp/{VICTIM_IP}/8080 2>/dev/null || true"],
    )

    log.info("Monitoring for 30s...")
    start = time.time()
    while time.time() - start < 30:
        try:
            ev = q.get(timeout=1)
            print(f"\n[T1021 DETECTED] {ev['src_pod']} -> {ev['dst_pod']} on port {ev['dst_port']}")
            print(f"  src_uid={ev['src_uid']}")
            print(f"  dst_uid={ev['dst_uid']}")
        except queue.Empty:
            pass
