import queue
import threading
import time
import logging
from src.tetragon_consumer import TetragonConsumer
from src.audit_log_consumer import AuditLogConsumer
from src.causal_graph import CausalGraph
from src.uid_resolver import PodUIDCache

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("correlator")

class Correlator:
    def __init__(self):
        self.cache = PodUIDCache()
        self.graph = CausalGraph()
        self.event_queue = queue.Queue()
        self.alert_list = []

    def start(self):
        self.cache.start_watch()
        time.sleep(2)

        TetragonConsumer(self.cache, self.event_queue).start()
        AuditLogConsumer(self.cache, self.event_queue).start()

        threading.Thread(target=self._loop, daemon=True).start()
        log.info("Correlator started — watching for T1059, T1552, chains")

    def _loop(self):
        while True:
            try:
                ev = self.event_queue.get(timeout=1)
                alerts = self.graph.add_event(ev)
                self.alert_list.extend(alerts)
            except queue.Empty:
                pass

    def get_alerts(self):
        return self.alert_list.copy()

if __name__ == "__main__":
    c = Correlator()
    c.start()

    log.info("Running (Ctrl+C to stop)...")
    try:
        while True:
            time.sleep(10)
            alerts = c.get_alerts()
            by_rule = {}
            for a in alerts:
                r = a["rule"]
                by_rule[r] = by_rule.get(r, 0) + 1
            if by_rule:
                log.info(f"Alert summary: {by_rule}")
    except KeyboardInterrupt:
        alerts = c.get_alerts()
        print(f"\n=== FINAL RESULTS ===")
        print(f"Total alerts: {len(alerts)}")
        by_rule = {}
        for a in alerts:
            by_rule[a["rule"]] = by_rule.get(a["rule"], 0) + 1
        print(f"By rule: {by_rule}")
        crits = [a for a in alerts if a["severity"] == "CRITICAL"]
        if crits:
            print(f"\nCRITICAL chain alerts:")
            for a in crits:
                print(f"  {a['rule']} on {a['namespace']}/{a['pod_name']} at {a['timestamp']}")
