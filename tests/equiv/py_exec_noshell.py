#!/usr/bin/env python3
# family: sink.exec.noshell | lang: python | verifies: argv form prints metachars literally
import subprocess
import sys

r = subprocess.run(
    [sys.executable, "-c", "import sys; sys.stdout.write(sys.argv[1])", "GRAFT_A && echo GRAFT_B"],
    capture_output=True,
    text=True,
)
assert r.returncode == 0 and r.stdout == "GRAFT_A && echo GRAFT_B", (r.returncode, r.stdout, r.stderr)
print("py exec.noshell OK: argv prints metachars literally — argument injection class")
