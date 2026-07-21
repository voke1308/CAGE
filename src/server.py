import json
import time
import re
import threading
import queue
from datetime import datetime
from flask import Flask, Response, jsonify, send_from_directory
from flask_cors import CORS
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.correlator import Correlator

app = Flask(__name__, static_folder='../dashboard')
CORS(app)

# Global correlator instance
correlator = Correlator()

# Broadcast queues — one per connected SSE client
event_subscribers = []
alert_subscribers = []
subscribers_lock = threading.Lock()

def broadcast_event(data):
    with subscribers_lock:
        dead = []
        for q in event_subscribers:
            try:
                q.put_nowait(data)
            except:
                dead.append(q)
        for q in dead:
            event_subscribers.remove(q)

def broadcast_alert(data):
    with subscribers_lock:
        dead = []
        for q in alert_subscribers:
            try:
                q.put_nowait(data)
            except:
                dead.append(q)
        for q in dead:
            alert_subscribers.remove(q)

def correlator_loop():
    """Drain correlator queue and broadcast to SSE clients"""
    while True:
        try:
            ev = correlator.event_queue.get(timeout=0.5)
            print(f"[DEQUEUE-B] {ev.get('event_type')} {ev.get('binary','')} pod={ev.get('pod_name')}", flush=True)
            # Add to graph
            alerts = correlator.graph.add_event(ev)
            correlator.alert_list.extend(alerts)

            # Broadcast event
            if ev.get('pod_uid') or ev.get('event_type') in ('k8s_secret_access', 'pod_exec'):
                broadcast_event(json.dumps({
                    'type': 'event',
                    'data': {
                        'timestamp': ev.get('timestamp', datetime.now().isoformat()),
                        'event_type': ev.get('event_type', ''),
                        'pod_name': ev.get('pod_name', ''),
                        'namespace': ev.get('namespace', ''),
                        'binary': ev.get('binary', ''),
                        'node': ev.get('node', ''),
                        'pod_uid': ev.get('pod_uid', ''),
                        'verb': ev.get('verb', ''),
                        'target_pod': ev.get('target_pod', ''),
                        'user': ev.get('user', ''),
                    }
                }))

            # Broadcast any new alerts
            for alert in alerts:
                broadcast_alert(json.dumps({
                    'type': 'alert',
                    'data': alert
                }))

        except queue.Empty:
            pass
        except Exception as e:
            pass

# ── REST endpoints ──

@app.route('/api/alerts')
def get_alerts():
    return jsonify(correlator.get_alerts())

@app.route('/api/pods')
def get_pods():
    snapshot = correlator.cache.snapshot()
    pods = []
    for uid, meta in snapshot.items():
        pods.append({
            'uid': uid,
            'name': meta.get('name'),
            'namespace': meta.get('ns'),
            'ip': meta.get('ip'),
            'node': meta.get('node'),
            'sa': meta.get('sa'),
        })
    return jsonify(pods)

@app.route('/api/graph')
def get_graph():
    alerts = correlator.get_alerts()
    pods = correlator.cache.snapshot()

    # Build nodes
    nodes = {}
    for uid, meta in pods.items():
        pod_alerts = [a for a in alerts if a.get('pod_uid') == uid]
        severity = 'clean'
        if any(a['severity'] == 'CRITICAL' for a in pod_alerts): severity = 'critical'
        elif any(a['severity'] == 'HIGH' for a in pod_alerts): severity = 'high'
        elif any(a['severity'] == 'MEDIUM' for a in pod_alerts): severity = 'medium'
        nodes[uid] = {
            'uid': uid,
            'name': meta.get('name'),
            'namespace': meta.get('ns'),
            'ip': meta.get('ip'),
            'node': meta.get('node'),
            'severity': severity,
            'alert_count': len(pod_alerts),
        }

    # Build edges from alerts
    edges = []
    seen_edges = set()
    
    api_uid = next((u for u, m in pods.items() if m.get('name','').startswith('kube-apiserver')), None)
    attacker_uid = next((u for u, m in pods.items() if m.get('name') == 'attacker'), None)
    rbac_targets = set()
    
    for alert in alerts:
        uid = alert.get('pod_uid')
        rule = alert.get('rule', '')

        if rule == 'T1548.005':
            # Cluster-level RBAC abuse — no pod_uid, so this must be handled
            # before the "if not uid: continue" guard below.
            reason = alert.get('description', '') or ''
            m = re.search(r'ServiceAccount:(\S+)', reason)
            target_name = m.group(1) if m else 'elevated-role'
            target_key = f'rbac:{target_name}'
            key = ('admin', target_key, 'T1548.005')
            if key not in seen_edges:
                seen_edges.add(key)
                rbac_targets.add((target_key, target_name))
                edges.append({'from': 'admin', 'to': target_key, 'type': 'T1548.005', 'color': '#ec4899', 'label': 'grants cluster-admin'})
            continue

        if not uid:
            continue
        
        if rule == 'T1552' and api_uid:
            key = (uid, api_uid, 'T1552')
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({'from': uid, 'to': api_uid, 'type': 'T1552', 'color': '#ef4444', 'label': 'secret access'})
        
        elif rule == 'T1021':
            # admin -> attacker (draw as external node -> attacker)
            target_pod = alert.get('pod_name')
            target_uid = next((u for u, m in pods.items() if m.get('name') == target_pod), None)
            if target_uid:
                # Add a virtual "admin" node if not present
                key = ('admin', target_uid, 'T1021')
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({'from': 'admin', 'to': target_uid, 'type': 'T1021', 'color': '#a855f7', 'label': 'kubectl exec'})
        
        elif rule == 'T1059' and uid:
            # Self-loop: shell spawn inside the pod — draw as tetragon -> pod
            tetragon_uid = next((u for u, m in pods.items()
                                  if m.get('name','').startswith('tetragon-')
                                  and not m.get('name','').startswith('tetragon-operator')), None)
            if tetragon_uid:
                key = (tetragon_uid, uid, 'T1059')
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({'from': tetragon_uid, 'to': uid, 'type': 'T1059', 'color': '#f59e0b', 'label': 'shell spawn'})

        elif rule == 'T1610' and uid:
            # attacker -> dst pod (lateral network move)
            dst_uid = alert.get('dst_pod_uid')
            if dst_uid and dst_uid in pods:
                key = (uid, dst_uid, 'T1610')
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({'from': uid, 'to': dst_uid, 'type': 'T1610', 'color': '#06b6d4', 'label': 'net connect'})

        elif rule in ('T1548', 'T1548-PRIV-POD') and uid:
            # Self-loop: privilege escalation inside the pod
            key = (uid, uid, 'T1548')
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({'from': uid, 'to': uid, 'type': 'T1548', 'color': '#f97316', 'label': 'priv-esc'})

        elif rule == 'T1611' and uid:
            # pod -> virtual host-system node (container breakout)
            key = (uid, 'host', 'T1611')
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({'from': uid, 'to': 'host', 'type': 'T1611', 'color': '#ef4444', 'label': 'container escape'})

        elif rule in ('T1496', 'T1499') and uid:
            # Self-loop: resource abuse inside the pod
            key = (uid, uid, rule)
            if key not in seen_edges:
                seen_edges.add(key)
                label = 'cryptomining' if rule == 'T1496' else 'fork bomb'
                edges.append({'from': uid, 'to': uid, 'type': rule, 'color': '#eab308', 'label': label})

    # Add virtual admin node to nodes list
    admin_node = {
        'uid': 'admin',
        'name': 'kubectl-admin',
        'namespace': 'external',
        'ip': '172.18.0.1',
        'node': 'host',
        'severity': 'clean',
        'alert_count': 0,
        'virtual': True,
    }
    host_node = {
        'uid': 'host',
        'name': 'Host System',
        'namespace': 'host',
        'ip': '',
        'node': '',
        'severity': 'critical',
        'alert_count': 0,
        'virtual': True,
    }
    node_list = list(nodes.values())
    if any(e.get('from') == 'admin' or e.get('to') == 'admin' for e in edges):
        node_list.append(admin_node)
    if any(e.get('to') == 'host' for e in edges):
        node_list.append(host_node)
    for target_key, target_name in rbac_targets:
        node_list.append({
            'uid': target_key,
            'name': target_name,
            'namespace': 'rbac',
            'ip': '',
            'node': '',
            'severity': 'critical',
            'alert_count': 0,
            'virtual': True,
        })

    return jsonify({'nodes': node_list, 'edges': edges})

@app.route('/api/stats')
def get_stats():
    alerts = correlator.get_alerts()
    by_rule = {}
    by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0}
    for a in alerts:
        by_rule[a['rule']] = by_rule.get(a['rule'], 0) + 1
        s = a.get('severity', '')
        if s in by_severity:
            by_severity[s] += 1
    return jsonify({
        'total_alerts': len(alerts),
        'by_rule': by_rule,
        'by_severity': by_severity,
        'pods_tracked': len(correlator.cache.snapshot()),
    })

# ── SSE streams ──

def sse_stream(subscriber_list):
    q = queue.Queue(maxsize=100)
    with subscribers_lock:
        subscriber_list.append(q)
    try:
        # Send keepalive
        yield 'data: {"type":"ping"}\n\n'
        while True:
            try:
                msg = q.get(timeout=15)
                yield f'data: {msg}\n\n'
            except queue.Empty:
                yield 'data: {"type":"ping"}\n\n'
    except GeneratorExit:
        with subscribers_lock:
            if q in subscriber_list:
                subscriber_list.remove(q)

@app.route('/stream/events')
def stream_events():
    return Response(
        sse_stream(event_subscribers),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        }
    )

@app.route('/stream/alerts')
def stream_alerts():
    return Response(
        sse_stream(alert_subscribers),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        }
    )

@app.route('/')
def index():
    return send_from_directory('../dashboard', 'index.html')

if __name__ == '__main__':
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
        print("  [OFF] NetworkMonitor")

    # Start correlator loop in background
    threading.Thread(target=correlator_loop, daemon=True).start()
    print("CAGE server running at http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, threaded=True)
