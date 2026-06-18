# CAGE — Cross-layer Attack Graph Engine

eBPF-based Kubernetes lateral movement detection system.

## Setup
1. Install Docker Desktop, enable WSL2 integration
2. Install kind, kubectl, helm inside Ubuntu/WSL2
3. `kind create cluster --config kind-config.yaml --name cage`
4. `helm install tetragon cilium/tetragon -n kube-system`
5. `pip install kubernetes networkx matplotlib --break-system-packages`

## Run
```bash
python3 src/tetragon_consumer.py   # live tagged event stream
python3 src/uid_resolver.py        # pod UID cache smoke test
```

## Week Status
- [x] Week 1: Environment (kind + Tetragon)
- [x] Week 2: Pod UID Resolver + Tetragon consumer
- [ ] Week 3: Causal graph + MITRE correlation rules
- [ ] Week 4: Eval + tuning
- [ ] Week 5: Paper
