import threading
import queue
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("audit-log-consumer")

class AuditLogConsumer:
    def __init__(self, cache, out_queue: queue.Queue):
        self.cache = cache
        self.out_queue = out_queue

    def start(self):
        log.info("Audit log consumer skipped (no audit policy in this cluster)")
