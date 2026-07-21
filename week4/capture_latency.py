#!/usr/bin/env python3
import subprocess, time, sys, csv, os
from datetime import datetime

def tail_new_lines(logfile, start_pos):
    with open(logfile, 'r') as f:
        f.seek(start_pos)
        lines = f.readlines()
        end_pos = f.tell()
    return lines, end_pos

def parse_ts(line):
    ts_str = line[:23]
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S,%f")
    except ValueError:
        return None

def main():
    if len(sys.argv) != 6:
        print("Usage: capture_latency.py <logfile> <technique_pattern> <output_csv> <person> <attack_cmd>")
        sys.exit(1)

    logfile, pattern, outfile, person, attack_cmd = sys.argv[1:6]

    if not os.path.exists(outfile):
        with open(outfile, 'w', newline='') as f:
            csv.writer(f).writerow(['person','technique','trial','t0','t1','latency_sec'])

    trial = 1
    while True:
        inp = input(f"\n[Trial {trial}] Press ENTER to fire {pattern} attack automatically (or type 'q' to stop): ")
        if inp.strip().lower() == 'q':
            break

        pos = os.path.getsize(logfile)
        t0_wall = time.time()
        t0_mono = time.monotonic()
        print(f">>> Firing attack now...")
        subprocess.run(attack_cmd, shell=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        exec_elapsed = time.monotonic() - t0_mono
        print(f">> subprocess.run returned after {exec_elapsed:.3f}s")
        print(">>> Attack sent. Waiting for matching alert in log...")

        t1_wall = None
        matched_line = None
        deadline_mono = time.monotonic() + 30
        while time.monotonic() < deadline_mono:
            lines, pos = tail_new_lines(logfile, pos)
            for line in lines:
                if pattern in line and ('WARNING' in line or 'CRITICAL' in line or 'HIGH' in line or 'MEDIUM' in line):
                    ts = parse_ts(line)
                    if ts:
                        t1_wall = ts.timestamp()
                        matched_line = line.strip()
                        break
            if matched_line:
                break
            time.sleep(0.05)

        if matched_line:
            mono_latency = round(time.monotonic() - t0_mono, 3)
            wall_latency = round(t1_wall - t0_wall, 3) if t1_wall else None
            print(f"MATCHED: {matched_line}")
            print(f">>> Latency (monotonic, reported): {mono_latency}s")
            if wall_latency is not None and abs(wall_latency - mono_latency) > 1.0:
                print(f"    (note: wall-clock diff was {wall_latency}s -- clock drift detected this trial, using monotonic value)")
            with open(outfile, 'a', newline='') as f:
                csv.writer(f).writerow([person, pattern, trial, t0_wall, t1_wall, mono_latency])
        else:
            print(">>> TIMEOUT - no match found in 30s. Not recorded. Check the log manually.")
        trial += 1

if __name__ == "__main__":
    main()
