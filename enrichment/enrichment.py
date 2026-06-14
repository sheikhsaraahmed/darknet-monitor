import os
import time
import json
import requests

COLLECTED_LOG = "/collected/all_attacks.log"
ENRICHED_LOG = "/enriched/enriched_attacks.log"
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

def check_abuseipdb(ip):
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=5
        )
        data = response.json()
        d = data.get("data", {})
        return {
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode", "unknown"),
            "isp": d.get("isp", "unknown"),
            "total_reports": d.get("totalReports", 0),
            "is_tor": d.get("isTor", False)
        }
    except Exception as e:
        print("[ENRICHMENT] AbuseIPDB error: " + str(e), flush=True)
        return {}

def enrich():
    os.makedirs("/enriched", exist_ok=True)
    seen = set()
    print("[ENRICHMENT] Starting enrichment service...", flush=True)
    while True:
        if not os.path.exists(COLLECTED_LOG):
            time.sleep(5)
            continue
        with open(COLLECTED_LOG, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line in seen:
                    continue
                seen.add(line)
                try:
                    entry = json.loads(line)
                    ip = entry.get("ip", "")
                    if ip and not ip.startswith("172.") and not ip.startswith("127."):
                        print("[ENRICHMENT] Looking up IP: " + ip, flush=True)
                        intel = check_abuseipdb(ip)
                        entry["intel"] = intel
                    else:
                        entry["intel"] = {"note": "private IP skipped"}
                    with open(ENRICHED_LOG, "a") as out:
                        out.write(json.dumps(entry) + "\n")
                    print("[ENRICHED] " + str(entry), flush=True)
                except json.JSONDecodeError:
                    pass
        time.sleep(5)

if __name__ == "__main__":
    enrich()