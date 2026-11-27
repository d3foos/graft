// family: sink.http.request | lang: node | verifies: URL parser sees userinfo host as the real host
const u = new URL('http://allowed.example@evil.example/x');
if (u.host !== 'evil.example') { console.error('FAIL:', u.host); process.exit(1); }
console.log("node URL confusion OK: 'http://allowed@evil/x' connects to evil — guard must check what the CLIENT sees");