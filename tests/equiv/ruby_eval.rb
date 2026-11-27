# family: sink.eval | lang: ruby | verifies: eval/instance_eval execute
abort "FAIL: eval" unless eval("7*7") == 49
o = Object.new
abort "FAIL: instance_eval" unless o.instance_eval { 7*7 } == 49
puts "ruby eval OK: eval + instance_eval execute"