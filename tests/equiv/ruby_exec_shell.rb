# family: sink.exec.shell | lang: ruby | verifies: backticks via /bin/sh interpret metachars
out = `printf GRAFT_A && printf GRAFT_B`
abort "FAIL: shell did not interpret &&" unless out == "GRAFT_AGRAFT_B"
puts "ruby exec.shell OK: backticks interpreted && via /bin/sh"