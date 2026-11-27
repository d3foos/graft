// family: fs.path.join | lang: node | verifies: path.join does NOT reset; path.resolve DOES (rev-1 error fixed)
const path = require('path');
const joined = path.join('/base', '/etc/passwd');
const resolved = path.resolve('/base', '/etc/passwd');
if (joined !== path.normalize('/base/etc/passwd')) { console.error('FAIL: path.join unexpected:', joined); process.exit(1); }
if (resolved !== path.resolve('/etc/passwd')) { console.error('FAIL: path.resolve unexpected:', resolved); process.exit(1); }
if (path.posix.join('/base', '/etc/passwd') !== '/base/etc/passwd') { console.error('FAIL: path.posix.join'); process.exit(1); }
if (path.posix.resolve('/base', '/etc/passwd') !== '/etc/passwd') { console.error('FAIL: path.posix.resolve'); process.exit(1); }
console.log('node path OK: join keeps base (no reset); resolve resets — the Node reset primitive is resolve');
