<?php
// family: sink.exec.shell | lang: php | verifies: shell semantics live (metachars/command substitution)
$r = shell_exec('printf %s "$(echo GRAFT_A)GRAFT_B"');
if ($r === null || strpos($r, "GRAFT_AGRAFT_B") === false) {
    fwrite(STDERR, "FAIL: shell_exec did not interpret \$(...) via /bin/sh\n");
    exit(1);
}
echo "php exec.shell OK: /bin/sh interpreted \$(...) — metachars live on PHP 8.3\n";