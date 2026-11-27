<?php
// family: sink.eval | lang: php | verifies: eval live; create_function REMOVED php8; string assert DEAD php8
ob_start();
eval('echo "GRAFT_EVAL_OK";');
$v = ob_get_clean();
if ($v !== "GRAFT_EVAL_OK") { fwrite(STDERR, "FAIL: eval did not execute\n"); exit(1); }
if (function_exists('create_function')) {
    fwrite(STDERR, "FAIL: create_function exists — table gate wrong for this PHP\n");
    exit(1);
}
try {
    @assert('GRAFT_STRING_ASSERT_NOT_EVALUATED');
    echo "php eval gates OK: eval live; create_function absent; string assert inert (zend.assertions=" .
         ini_get('zend.assertions') . ")\n";
} catch (Throwable $e) {
    echo "php eval gates OK: eval live; create_function absent; string assert rejected by engine (" .
         get_class($e) . ") — dead sink either way\n";
}