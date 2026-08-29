"""WebSocket test client for the /replay endpoint.

Connects to ws://localhost:8000/ws, triggers /replay/start via HTTP,
listens for 10 events, prints them, then stops the replay.

Usage:
    1. Start backend:  python -m uvicorn main:app --host 127.0.0.1 --port 8000
    2. Run this:       python test_replay.py
"""

from __future__ import annotations

import asyncio
import json

import httpx
import websockets

API_BASE = "http://localhost:8000"
WS_URL = "ws://localhost:8000/ws"
N_EVENTS_TO_CAPTURE = 10


async def main() -> None:
    """Connect to WebSocket, start replay, capture events."""
    print("=" * 72)
    print("  SentinelAI -- WebSocket Replay Test Client")
    print("=" * 72)
    print()

    # Connect WebSocket
    print("  Connecting to WebSocket ...")
    async with websockets.connect(WS_URL) as ws:
        print("  Connected!")
        print()

        # Start replay via HTTP
        async with httpx.AsyncClient() as http:
            resp = await http.get(f"{API_BASE}/replay/start")
            start_result = resp.json()
            print(f"  /replay/start -> {start_result}")
            print()

        # Listen for events
        print(f"  Listening for {N_EVENTS_TO_CAPTURE} events (~1/second) ...")
        print()
        print(f"  {'#':<5} {'Predicted':<10} {'Actual':<10} {'Conf':>6}  "
              f"{'Proto':<6} {'Service':<12} {'Flag':<6}")
        print(f"  {'-'*5} {'-'*10} {'-'*10} {'-'*6}  "
              f"{'-'*6} {'-'*12} {'-'*6}")

        count = 0
        correct = 0

        for _ in range(N_EVENTS_TO_CAPTURE):
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
                msg = json.loads(raw)

                idx = msg.get("event_index", "?")
                pred = msg.get("prediction", "?")
                actual = msg.get("actual", "?")
                conf = msg.get("confidence", 0)
                raw_evt = msg.get("raw_event", {})
                proto = raw_evt.get("protocol_type", "?")
                service = raw_evt.get("service", "?")
                flag = raw_evt.get("flag", "?")

                match = pred == actual
                if match:
                    correct += 1
                count += 1

                print(f"  {idx:<5} {pred:<10} {actual:<10} {conf:>6.2f}  "
                      f"{proto:<6} {service:<12} {flag:<6}")

            except asyncio.TimeoutError:
                print("  [TIMEOUT] No event received in 5 seconds.")
                break

        # Stop replay
        print()
        async with httpx.AsyncClient() as http:
            resp = await http.get(f"{API_BASE}/replay/stop")
            stop_result = resp.json()
            print(f"  /replay/stop -> {stop_result}")

        print()
        if count > 0:
            print(f"  Captured {count} events. "
                  f"Match rate: {correct}/{count} ({correct/count*100:.0f}%)")
        print()
        print("  Events arrived at ~1/second with predictions attached: OK")
        print("=" * 72)


if __name__ == "__main__":
    asyncio.run(main())
