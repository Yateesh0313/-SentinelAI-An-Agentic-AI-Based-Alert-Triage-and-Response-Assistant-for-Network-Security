"""Test persistence: verify /events/history survives a backend restart."""
import requests

API = "http://localhost:8000"

print("=== Persistence Test: /events/history after restart ===")
r = requests.get(f"{API}/events/history")
data = r.json()
print(f"Count: {data['count']}")

for e in data["events"]:
    print(f"  {e['event_id']}: status={e['status']}, "
          f"severity={e.get('severity')}, "
          f"resolved_at={e.get('resolved_at')}, "
          f"resolved_by={e.get('resolved_by')}")

if data["count"] >= 2:
    print("\nPERSISTENCE TEST: PASS -- history survived restart!")
else:
    print("\nPERSISTENCE TEST: FAIL -- history lost on restart!")
