<?php
// family: sink.exec.noshell | lang: php | verifies: proc_open ARRAY form bypasses the shell
$cmd = [PHP_BINARY, '-r', 'echo $argv[1];', 'GRAFT_A && echo GRAFT_B'];
$proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
if (!is_resource($proc)) { fwrite(STDERR, "FAIL: proc_open failed\n"); exit(1); }
$out = stream_get_contents($pipes[1]);
fclose($pipes[1]);
proc_close($proc);
if ($out !== "GRAFT_A && echo GRAFT_B") {
    fwrite(STDERR, "FAIL: array-args proc_open unexpectedly interpreted metachars: $out\n");
    exit(1);
}
echo "php exec.noshell OK: proc_open(array) prints metachars literally — argument injection is the class here\n";
