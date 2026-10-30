import sqlite3
from pathlib import Path

root = Path(__file__).resolve().parent.parent
skip = {"venv", ".git", "__pycache__", ".pytest_cache"}
found = []
for p in root.rglob("*"):
    if not p.is_file() or (set(p.relative_to(root).parts) & skip):
        continue
    try:
        with open(p, "rb") as f:
            if f.read(15) == b"SQLite format 3":
                found.append(p)
    except OSError:
        pass

if not found:
    print("No SQLite database inside the project folder.")
for p in found:
    print("\nDATABASE:", p, "-", p.stat().st_size, "bytes")
    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    print("tables:", tables)
    if "users" in tables:
        cols = [r[1] for r in con.execute("pragma table_info(users)")]
        safe = [c for c in cols if any(k in c.lower() for k in ("id", "user", "role", "admin", "created"))
                and "hash" not in c.lower() and "secret" not in c.lower()]
        print("users columns shown:", safe)
        for row in con.execute(f"select {', '.join(safe)} from users order by 1"):
            print("  ", row)
    con.close()
