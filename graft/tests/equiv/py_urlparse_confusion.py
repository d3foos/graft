#!/usr/bin/env python3
# family: sink.http.request | lang: python | verifies: userinfo host confusion in stdlib parser
import urllib.parse
u = urllib.parse.urlsplit("http://allowed.example@evil.example/x")
assert u.hostname == "evil.example", u
print("py URL confusion OK: urlsplit sees host 'evil' behind 'allowed@' — a guard parsing differently is the bug")