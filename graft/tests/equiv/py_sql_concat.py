#!/usr/bin/env python3
# family: sink.sql.concat | lang: python | verifies: concatenated quote reaches parser; bound stays data
import sqlite3
db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE t (name TEXT)")
attacker = "x'"
try:
    db.execute("SELECT name FROM t WHERE name = '%s'" % attacker)
    raise SystemExit("FAIL: unbalanced concatenated quote did not reach the parser")
except sqlite3.OperationalError:
    pass
db.execute("SELECT name FROM t WHERE name = ?", (attacker,))
print("py sql.concat OK: concatenated quote hits the parser as syntax; parameterized stays data")