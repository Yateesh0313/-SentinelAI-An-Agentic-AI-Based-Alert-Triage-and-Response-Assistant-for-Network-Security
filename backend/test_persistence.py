"""Test persistence: verify /events/history survives a backend restart."""
import requests

API = "http://localhost:8000"

def main():
    print("=== Persistence Test: /events/history after restart ===")
    try:
        r = requests.get(f"{API}/events/history", timeout=5)
        data = r.json()
        print(f"Count: {data['count']}")

        for e in data.get("events", []):
            print(f"  {e['event_id']}: status={e['status']}, "
                  f"severity={e.get('severity')}, "
                  f"resolved_at={e.get('resolved_at')}, "
                  f"resolved_by={e.get('resolved_by')}")

        if data.get("count", 0) >= 2:
            print("\nPERSISTENCE TEST: PASS -- history survived restart!")
        else:
            print("\nPERSISTENCE TEST: FAIL -- history lost on restart!")
    except Exception as exc:
        print(f"\nPERSISTENCE TEST: Server offline or unreachable ({exc})")


if __name__ == "__main__":
    main()

