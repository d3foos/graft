#!/usr/bin/env python3
# family: sink.exec.shell | lang: python | verifies: shell=True interprets metachars via the OS shell
import subprocess
import sys

cmd = (
    f'"{sys.executable}" -c "import sys; sys.stdout.write(\'GRAFT_A\')"'
    f' && "{sys.executable}" -c "import sys; sys.stdout.write(\'GRAFT_B\')"'
)
r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
assert r.returncode == 0 and r.stdout == "GRAFT_AGRAFT_B", (r.returncode, r.stdout, r.stderr)
print("py exec.shell OK: shell=True interpreted && via OS shell")
