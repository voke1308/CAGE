# CAGE — Cross-Layer Attack Graph Engine

Kubernetes runtime security system that fuses eBPF telemetry, Kubernetes
audit logs, and pod identity to detect multi-step lateral-movement attacks
in real time — with a live SOC-style dashboard.

## What it does

Most tools watch one signal (syscalls, or network, or API calls). CAGE
watches three sources at once and correlates them by pod UID to catch
attack **chains**, not just isolated events.

**Detections (MITRE ATT&CK):**

| Technique | Alert | Severity | Source |
|---|---|---|---|
| T1059 | Shell spawned inside a pod | MEDIUM | Tetragon eBPF |
| T1021 | Remote exec (`kubectl exec`) | MEDIUM | K8s audit log |
| T1610 | Pod-to-pod network lateral movement | MEDIUM | Tetragon kprobe |
| T1552 | Secret access via K8s API | HIGH | K8s audit log |
| T1611 | Container escape (dangerous capability / escape binary) | HIGH | Tetragon eBPF |
| T1548 | Privilege escalation attempt inside a container | HIGH | Tetragon eBPF |
| T1548-PRIV-POD | Privileged pod created | HIGH | K8s audit log |
| T1548.005 | Cluster-admin / wildcard RBAC grant | CRITICAL | K8s audit log |
| T1496 | Cryptomining process signature | HIGH | Tetragon eBPF |
| T1499 | Fork-bomb-like exec burst (resource DoS) | HIGH | Tetragon eBPF |
| T1613 | RBAC / resource discovery burst | MEDIUM | K8s audit log |

**Correlated attack chains (CRITICAL):**
- T1059 → T1552 (shell → secret access)
- T1021 → T1059 → T1552 (remote exec → shell → secret access)
- T1059 → T1610 → T1552 (shell → network pivot → secret access)
- T1059 → T1548 → T1611 (shell → priv-esc → container escape)
- T1611 → T1552 (escape → secret access)

Chains are correlated per pod UID inside a 120-second sliding window.

## Architecture

```
Tetragon eBPF stream ──┐
                        ├─→ shared queue → CausalGraph → alerts → SSE → dashboard
K8s Audit Log stream ──┤
Network Monitor ───────┘
        ↑
   Pod UID Cache (K8s watch API — the correlation key across all sources)
```

## Codebase

```
src/
├── uid_resolver.py        — live pod identity cache (K8s watch API)
├── tetragon_consumer.py    — eBPF process_exec / kprobe event stream parser
├── audit_log_consumer.py   — K8s audit log tailer/parser
├── network_monitor.py      — pod-to-pod TCP connection tracking (T1610)
├── causal_graph.py         — detection rules + chain correlation engine
├── correlator.py           — orchestrator wiring sources → causal graph
└── server.py               — Flask API + SSE streaming backend

dashboard/
└── index.html               — live canvas-based attack graph, alert feed,
                                MITRE legend, severity sparkline, pod inventory

k8s/
├── tcp-connect-policy.yaml       — Tetragon TracingPolicy for T1610
└── capability-check-policy.yaml — Tetragon TracingPolicy for T1611/T1548

week4/                        — evaluation: ablation study, benign controls,
                                latency capture, scenario scripts, metrics, plots
run_ablation.py               — fires attacks against a running server for a
                                given ABLATION_MODE and logs fired/not-fired
plot_graph2.py                — attack-vs-benign alert rate bar chart
patch_server_v3.py            — one-off script that patched server.py's
                                __main__ block to read ABLATION_MODE
DEMO_GUIDE.md                  — full walkthrough for presenting the project
```

## Setup

1. Install Docker Desktop, enable WSL2 integration
2. Install `kind`, `kubectl`, `helm` inside Ubuntu/WSL2
3. `kind create cluster --config kind-config.yaml --name cage`
4. `helm install tetragon cilium/tetragon -n kube-system`
5. `pip install flask flask-cors kubernetes networkx matplotlib --break-system-packages`
6. Apply Tetragon policies: `kubectl apply -f k8s/tcp-connect-policy.yaml -f k8s/capability-check-policy.yaml`
7. Enable K8s audit logging using `audit-policy.yaml` (patch kube-apiserver — see `DEMO_GUIDE.md` Step 4)

## Run

```bash
python3 src/server.py       # starts correlator + Flask/SSE backend
# open http://localhost:5000 for the live dashboard
```

Standalone component tests:
```bash
python3 src/tetragon_consumer.py   # live tagged event stream
python3 src/uid_resolver.py        # pod UID cache smoke test
```

For the full attack-trigger walkthrough and how to explain the dashboard
during a demo, see `DEMO_GUIDE.md`.

## Evaluation

**Detection eval (5 trials, full chain T1021→T1059→T1552):** 100% detection
rate, 0 false positives, ~7s average detection latency (cold start), ~4.7s
steady state. Details in `DEMO_GUIDE.md`.

**Ablation study** (`week4/results_ablation.csv`) — isolates which telemetry
source each technique actually needs:

| Condition | T1059 | T1021 | T1552 | T1610 |
|---|---|---|---|---|
| Tetragon only | 9/10 | 0/10 | 0/10 | 10/10 |
| Audit log only | 0/10 | 10/10 | 10/10 | 0/10 |
| Fused (both) | 9/10 | 10/10 | 10/10 | 10/10 |

This is the core evidence for the cross-layer design: T1059 and T1610 are
invisible to the audit log, T1021 and T1552 are invisible to eBPF — no
single source covers the full chain.

**Benign controls** (`week4/results_benign.csv`) — 10 trials each of benign
shell use, benign exec, benign privileged behavior, and benign pod-to-pod
traffic. T1059/T1021/T1548 controls: 0/10 false positives. **T1610 control:
10/10 fired** — the current network-lateral-movement rule does not yet
distinguish benign pod-to-pod traffic from an attack pattern and is a known
false-positive source, tracked as an open item below.

## Known limitations

- Single-node `kind`/docker-desktop cluster, not a multi-node production setup.
- Audit log access requires directly patching the kube-apiserver manifest;
  in production this is normally set at cluster-creation time.
- T1610 (network) detection needs a BTF-enabled kernel (Linux 5.10+); WSL2's
  CO-RE struct-layout mismatch has, in some environments, blocked T1610
  entirely — confirmed working on kernel 6.6 here, but not portable as-is.
- T1610 currently has a high false-positive rate on benign pod-to-pod
  traffic (see benign controls above) — needs a tighter rule (e.g. namespace/
  IP allowlisting or connection-frequency thresholding) before it can be
  trusted standalone rather than only as a chain component.
- 120-second correlation window — an attack chain must complete inside that
  window to be linked. Configurable.

## Status

- [x] Environment: kind + Tetragon
- [x] Pod UID resolver + Tetragon consumer
- [x] Causal graph + MITRE correlation rules (11 techniques, 5 chains)
- [x] Live SOC dashboard (attack graph, alert feed, MITRE legend, sparkline)
- [x] Container escape / privilege escalation / resource abuse / RBAC abuse detection
- [x] Ablation study + benign controls + latency capture
- [ ] Fix T1610 false-positive rate on benign traffic
- [ ] Multi-node cluster validation
- [ ] Write-up / paper
