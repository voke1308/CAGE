#!/usr/bin/env python3
"""
Run ablation trials against the CURRENTLY RUNNING server.
Usage: python3 run_ablation.py <condition_name> <logfile> <output_csv>

condition_name is just a label for the CSV rows (e.g. "tetragon_only") —
it does NOT set ABLATION_MODE itself. You must start the server with the
matching ABLATION_MODE env var BEFORE running this script. This script only
fires attacks and checks the log; it never touches the server process.
"""
import subprocess, time, sys, csv, os

TECHNIQUES = {
    "T1059": 'kubectl exec attacker -- bash -c "id && whoami"',
    "T1021": 'kubectl exec attacker -- echo "trial"',
    "T1552": 'kubectl exec attacker -- bash -c "TOKEN=\\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -s -k -H \\"Authorization: Bearer \\$TOKEN\\" https://kubernetes.default.svc/api/v1/namespaces/default/secrets/db-credentials"',
    "T1610": 'kubectl exec attacker -- bash -c "timeout 2 bash -c \\"echo > /dev/tcp/10.244.2.3/80\\""',
}

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 run_ablation.py <condition_name> <logfile> <output_csv>")
        print("  condition_name: tetragon_only | audit_only | fused  (label only)")
        sys.exit(1)

    condition, logfile, outfile = sys.argv[1:4]

    if not os.path.exists(logfile):
        print(f"ERROR: log file {logfile} does not exist. Is the server running and pointed at this log?")
        sys.exit(1)

    if not os.path.exists(outfile):
        with open(outfile, "w", newline="") as f:
            csv.writer(f).writerow(["condition", "technique", "trial", "fired"])

    print(f"=== Running ablation condition: {condition} ===")
    print(f"    Log: {logfile}")
    print(f"    Output: {outfile}")
    print(f"    IMPORTANT: confirm the server startup log already shows the correct")
    print(f"    [ON]/[OFF] pattern for '{condition}' before continuing.\n")
    input("Press ENTER once you've confirmed the server is in the right mode...")

    for technique, cmd in TECHNIQUES.items():
        print(f"\n--- {technique} ({condition}) ---")
        for trial in range(1, 11):
            pos = os.path.getsize(logfile)
            print(f"  [Trial {trial}] firing {technique}...")
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            fired = 0
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                with open(logfile, "r") as f:
                    f.seek(pos)
                    lines = f.readlines()
                    pos = f.tell()
                for line in lines:
                    if technique in line and any(k in line for k in ("WARNING", "CRITICAL", "HIGH", "MEDIUM")):
                        fired = 1
                        break
                if fired:
                    break
                time.sleep(0.2)

            print(f"    fired={fired}")
            with open(outfile, "a", newline="") as f:
                csv.writer(f).writerow([condition, technique, trial, fired])
            time.sleep(3)

    print(f"\n=== {condition} complete. Results appended to {outfile} ===")

if __name__ == "__main__":
    main()
