// family: sink.eval | lang: node | verifies: eval + new Function execute
if (eval('7*7') !== 49) { console.error('FAIL: eval'); process.exit(1); }
if (new Function('return 7*7')() !== 49) { console.error('FAIL: new Function'); process.exit(1); }
console.log('node eval OK: eval and new Function execute');