with open("src/server.py", "rb") as f:
    raw = f.read()

had_crlf = b"\r\n" in raw
content = raw.decode("utf-8").replace("\r\n", "\n")

old = '''if __name__ == '__main__':
    print("Starting CAGE correlator...")
    correlator.cache.start_watch()
    time.sleep(2)

    from src.tetragon_consumer import TetragonConsumer
    from src.audit_log_consumer import AuditLogConsumer
    from src.network_monitor import NetworkMonitor
    TetragonConsumer(correlator.cache, correlator.event_queue).start()
    AuditLogConsumer(correlator.cache, correlator.event_queue).start()
    NetworkMonitor(correlator.cache, correlator.event_queue).start()'''

new = '''if __name__ == '__main__':
    import os
    ABLATION_MODE = os.environ.get("ABLATION_MODE", "fused")  # tetragon_only | audit_only | fused
    print(f"Starting CAGE correlator... [ABLATION_MODE={ABLATION_MODE}]")
    correlator.cache.start_watch()
    time.sleep(2)

    from src.tetragon_consumer import TetragonConsumer
    from src.audit_log_consumer import AuditLogConsumer
    from src.network_monitor import NetworkMonitor

    if ABLATION_MODE in ("tetragon_only", "fused"):
        TetragonConsumer(correlator.cache, correlator.event_queue).start()
        print("  [ON]  TetragonConsumer")
    else:
        print("  [OFF] TetragonConsumer")

    if ABLATION_MODE in ("audit_only", "fused"):
        AuditLogConsumer(correlator.cache, correlator.event_queue).start()
        print("  [ON]  AuditLogConsumer")
    else:
        print("  [OFF] AuditLogConsumer")

    if ABLATION_MODE == "fused":
        NetworkMonitor(correlator.cache, correlator.event_queue).start()
        print("  [ON]  NetworkMonitor")
    else:
        print("  [OFF] NetworkMonitor")'''

if old not in content:
    print("ERROR: still not found.")
    lines = content.split("\n")
    for i, line in enumerate(lines):
        if "__main__" in line:
            for j in range(i, min(i + 12, len(lines))):
                print(repr(lines[j]))
            break
else:
    content = content.replace(old, new)
    if had_crlf:
        content = content.replace("\n", "\r\n")
    with open("src/server.py", "wb") as f:
        f.write(content.encode("utf-8"))
    print("SUCCESS: server.py updated with ABLATION_MODE toggle.")
