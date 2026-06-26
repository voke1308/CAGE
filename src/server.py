import json
import time
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
    for alert in alerts:
        uid = alert.get('pod_uid')
        rule = alert.get('rule', '')
        if not uid:
            continue
        if rule == 'T1552':
            # attacker -> kube-apiserver
            api_uid = next((u for u, m in pods.items() if m.get('name','').startswith('kube-apiserver')), None)
            if api_uid:
                key = (uid, api_uid, 'T1552')
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({'from': uid, 'to': api_uid, 'type': 'T1552', 'color': '#ef4444'})
        elif rule == 'T1021':
            target = alert.get('pod_name')
            target_uid = next((u for u, m in pods.items() if m.get('name') == target), None)
            if target_uid and uid != target_uid:
                key = (uid, target_uid, 'T1021')
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({'from': uid, 'to': target_uid, 'type': 'T1021', 'color': '#a855f7'})

    return jsonify({'nodes': list(nodes.values()), 'edges': edges})

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
    print("Starting CAGE correlator...")
    correlator.cache.start_watch()
    time.sleep(2)

    from src.tetragon_consumer import TetragonConsumer
    from src.audit_log_consumer import AuditLogConsumer
    TetragonConsumer(correlator.cache, correlator.event_queue).start()
    AuditLogConsumer(correlator.cache, correlator.event_queue).start()

    # Start correlator loop in background
    threading.Thread(target=correlator_loop, daemon=True).start()
    print("CAGE server running at http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, threaded=True)
