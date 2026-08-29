"""End-to-end honeypot test for Phase 15."""
import urllib.request
import json
import socket
import time

API = "http://localhost:8000"

def api_get(path: str) -> dict:
    r = urllib.request.urlopen(f"{API}{path}", timeout=15)
    return json.loads(r.read())

# 1. Start honeypot
print("1. Starting honeypot...")
result = api_get("/honeypot/start")
print(f"   Response: {json.dumps(result)}")

# 2. Make a probe connection
print("2. Connecting to honeypot on port 8899...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
s.connect(("127.0.0.1", 8899))
s.sendall(b"GET / HTTP/1.0\r\nHost: honeypot-test\r\n\r\n")
time.sleep(0.5)
s.close()
print("   Connection closed.")

# 3. Wait for triage pipeline to process
print("3. Waiting 12s for triage to complete...")
time.sleep(12)

# 4. Check honeypot status
print("4. Checking honeypot status...")
status = api_get("/honeypot/status")
print(f"   Status: {json.dumps(status, indent=2)}")

# 5. Check pending events
print("5. Checking pending events...")
pending = api_get("/events/pending")
count = pending.get("count", 0)
print(f"   Pending events: {count}")

if count > 0:
    ev = pending["events"][0]
    print(f"   Latest event:")
    print(f"     event_id: {ev.get('event_id')}")
    print(f"     prediction: {ev.get('prediction')}")
    print(f"     confidence: {ev.get('confidence')}")
    print(f"     source: {ev.get('source')}")
    print(f"     severity: {ev.get('severity')}")
    print(f"     recommended_action: {ev.get('recommended_action')}")
    print(f"     honeypot_meta: {ev.get('honeypot_meta')}")
    print(f"     agent_latency_seconds: {ev.get('agent_latency_seconds')}")
    print(f"     status: {ev.get('status')}")
    print(f"     ml_flagged: {ev.get('ml_flagged')}")
    print(f"     sig_flagged: {ev.get('sig_flagged')}")
else:
    print("   No pending events found!")

print("\nDone!")
