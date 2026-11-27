// family: sink.exec.noshell | lang: node | verifies: spawn argv prints metachars literally
const { spawnSync } = require('child_process');
const r = spawnSync(process.execPath, ['-e', 'process.stdout.write(process.argv[1])', 'GRAFT_A && echo GRAFT_B'], { encoding: 'utf8' });
if (r.status !== 0 || r.stdout !== 'GRAFT_A && echo GRAFT_B') {
  console.error('FAIL: argv form unexpectedly interpreted metachars', r);
  process.exit(1);
}
console.log('node exec.noshell OK: argv prints metachars literally — argument injection class');
