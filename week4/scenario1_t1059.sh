#!/bin/bash

echo "[*] Scenario 1: T1059 - Shell Execution in Pod"
echo "[*] Attack: Spawn shell inside attacker pod"
echo "[*] Expected: T1059 alert fires"

# Log attack start
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[$TIMESTAMP] ATTACK_START: Shell spawn in attacker pod"

# Exec bash in attacker pod
kubectl exec -it attacker -- /bin/bash << 'SHELL'
echo "Shell spawned, running commands..."
ls /
pwd
whoami
sleep 1
exit
SHELL

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[$TIMESTAMP] ATTACK_END: Shell execution complete"
