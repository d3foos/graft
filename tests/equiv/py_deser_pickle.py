#!/usr/bin/env python3
# family: sink.deser.native | lang: python | verifies: pickle.loads executes __reduce__
# Local echo marker only — proves the dispatch semantics, nothing else.
import contextlib, io, pickle
class G:
    def __reduce__(self):
        return (print, ("GRAFT_PICKLE_OK",))
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    pickle.loads(pickle.dumps(G()))
assert buf.getvalue().strip() == "GRAFT_PICKLE_OK", buf.getvalue()
print("py deser OK: pickle.loads dispatches __reduce__ (echo marker only)")