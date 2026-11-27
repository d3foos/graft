// family: sink.exec.shell | lang: node | verifies: child_process.exec runs via the OS shell
const { exec } = require('child_process');
const cmd = '"' + process.execPath + '" -e "process.stdout.write(\'GRAFT_A\')" && "' + process.execPath + '" -e "process.stdout.write(\'GRAFT_B\')"';
exec(cmd, (err, stdout) => {
  if (err) { console.error('FAIL:', err); process.exit(1); }
  if (!stdout.includes('GRAFT_AGRAFT_B')) { console.error('FAIL: shell did not interpret &&'); process.exit(1); }
  console.log('node exec.shell OK: OS shell interpreted &&');
});
