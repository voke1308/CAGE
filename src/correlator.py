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
        tetragon = TetragonConsumer(self.cache, self.event_queue)
        tetragon.start()
        audit = AuditLogConsumer(self.cache, self.event_queue)
        audit.start()
        t = threading.Thread(target=self._correlation_loop, daemon=True)
        t.start()
        log.info("Correlator started")

    def _correlation_loop(self):
        while True:
            try:
                ev = self.event_queue.get(timeout=1)
                alerts = self.graph.add_event(ev)
                for alert in alerts:
                    self._fire_alert(alert)
            except queue.Empty:
                pass

    def _fire_alert(self, alert: dict):
        self.alert_list.append(alert)
        severity = alert.get("severity", "INFO")
        rule = alert.get("rule", "UNKNOWN")
        desc = alert.get("description", "")
        pod = f"{alert.get('namespace')}/{alert.get('pod_name')}"
        log.warning(f"[{severity}] {rule}: {desc} on {pod}")

    def get_alerts(self):
        return self.alert_list.copy()

if __name__ == "__main__":
    correlator = Correlator()
    correlator.start()
    log.info("Running correlator (Ctrl+C to stop)...")
    try:
        while True:
            alerts = correlator.get_alerts()
            if alerts:
                print(f"\n=== {len(alerts)} Alerts ===")
                for a in alerts[-5:]:
                    print(f"  [{a['severity']}] {a['rule']}: {a['description']}")
            time.sleep(5)
    except KeyboardInterrupt:
        total = len(alerts)
        print(f"\n--- Final Alert Count ---")
        print(f"Total: {total}")
        by_rule = {}
        for a in alerts:
            rule = a["rule"]
            by_rule[rule] = by_rule.get(rule, 0) + 1
        print(f"By rule: {by_rule}")
