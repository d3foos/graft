#!/usr/bin/env python3
# family: sink.eval | lang: python | verifies: eval/compile execute
assert eval("7*7") == 49
code = compile("7*7", "<graft>", "eval")
assert eval(code) == 49
print("py eval OK: eval + compile execute")