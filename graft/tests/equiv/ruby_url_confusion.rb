# family: sink.http.request | lang: ruby | verifies: URI userinfo host confusion
require "uri"
abort "FAIL" unless URI("http://allowed.example@evil.example/x").host == "evil.example"
puts "ruby URL confusion OK: URI sees host 'evil' behind 'allowed@'"