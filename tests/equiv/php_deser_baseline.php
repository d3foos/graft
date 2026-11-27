<?php
// family: sink.deser.native | lang: php | verifies: unserialize instantiates named types; garbage errors
$o = @unserialize('O:8:"stdClass":0:{}');
if (!($o instanceof stdClass)) { fwrite(STDERR, "FAIL: baseline unserialize did not instantiate\n"); exit(1); }
$bad = @unserialize('O:8:"stdClass":1:{');
if ($bad !== false) { fwrite(STDERR, "FAIL: garbage blob unexpectedly parsed\n"); exit(1); }
echo "php deser OK: unserialize instantiates attacker-named type; garbage returns false\n";