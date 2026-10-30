"""Usage: python scripts/create_user.py <username> <password> <viewer|analyst|admin>"""
import asyncio, sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
import database as db
from auth import hash_password


async def main(username: str, password: str, role: str) -> None:
    await db.connect()
    d = db._get_db()
    await d.users.update_one(
        {"username": username},
        {"$set": {"hashed_password": hash_password(password), "role": role,
                  "created_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )
    await d.users.create_index("username", unique=True)
    print(f"ok: {username} ({role})")


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[3] not in ("viewer", "analyst", "admin"):
        sys.exit(__doc__)
    asyncio.run(main(*sys.argv[1:4]))

