#!/bin/bash
LOGFILE="$1"
OUTCSV="week4/results_personA_v2.csv"
PERSON="A"

for i in $(seq 1 10); do
  PODNAME="t1548-privesc-$i-$RANDOM"
  printf 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: %s\n  namespace: default\nspec:\n  containers:\n  - name: privesc\n    image: ubuntu:latest\n    command: ["sleep", "3600"]\n    securityContext:\n      privileged: true\n' "$PODNAME" > /tmp/t1548-pod.yaml

  echo "[Trial $i] Firing T1548 attack (pod=$PODNAME)..."
  POS=$(stat -c%s "$LOGFILE")
  T0=$(date +%s.%N)
  kubectl apply -f /tmp/t1548-pod.yaml > /dev/null

  MATCHED=0
  for attempt in $(seq 1 60); do
    sleep 0.5
    if tail -c +$((POS+1)) "$LOGFILE" | grep -q "T1548: privileged pod created default/${PODNAME}"; then
      T1=$(date +%s.%N)
      LATENCY=$(echo "$T1 - $T0" | bc)
      echo ">>> MATCHED after ${LATENCY}s"
      echo "${PERSON},T1548,${i},${T0},${T1},${LATENCY}" >> "$OUTCSV"
      MATCHED=1
      break
    fi
  done
  if [ "$MATCHED" -eq 0 ]; then
    echo ">>> TIMEOUT - no match for $PODNAME"
  fi

  kubectl delete pod "$PODNAME" -n default --wait=false > /dev/null 2>&1
  sleep 1
done
