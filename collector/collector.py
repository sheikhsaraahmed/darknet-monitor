import os
import time
import json
import datetime

LOG_SOURCES = [
    "/logs/http/http_honeypot.log",
    "/logs/ftp/ftp_honeypot.log",
]

COLLECTED_LOG = "/collected/all_attacks.log"

def collect():
    os.makedirs("/collected", exist_ok=True)
    seen = set()
    print("[COLLECTOR] Starting log collection...", flush=True)
    while True:
        for source in LOG_SOURCES:
            if not os.path.exists(source):
                continue
            with open(source, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line in seen:
                        continue
                    seen.add(line)
                    try:
                        entry = json.loads(line)
                        entry["source"] = source
                        with open(COLLECTED_LOG, "a") as out:
                            out.write(json.dumps(entry) + "\n")
                        print("[COLLECTED] " + str(entry), flush=True)
                    except json.JSONDecodeError:
                        pass
        time.sleep(5)

if __name__ == "__main__":
    collect()