#!/usr/bin/env python3
# family: fs.path.join | lang: python | verifies: os.path.join RESETS on absolute second arg
import os
import posixpath

assert posixpath.join("/base", "/etc/passwd") == "/etc/passwd"
assert posixpath.join("/base", "x") == "/base/x"
assert os.path.join("/base", "/etc/passwd") == "/etc/passwd"
assert os.path.normpath(os.path.join("/base", "x")) == os.path.normpath("/base/x")
print("py path.join OK: absolute second arg replaces the base (reset trap live)")
