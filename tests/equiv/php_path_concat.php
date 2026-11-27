<?php
// family: fs.path.join | lang: php | verifies: no join primitive; naive concat keeps prefix; realpath collapses
$joined = "/base" . "/" . "/etc/passwd";
if (strpos($joined, "/base/") !== 0) { fwrite(STDERR, "FAIL: concat shape unexpected\n"); exit(1); }
$rp = realpath("/usr/../etc/passwd");
if ($rp !== "/etc/passwd") { fwrite(STDERR, "FAIL: realpath did not collapse: $rp\n"); exit(1); }
echo "php path concat OK: naive concat keeps base prefix; realpath collapses dotdot (no reset concept)\n";