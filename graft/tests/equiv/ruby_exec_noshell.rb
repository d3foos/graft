# family: sink.exec.noshell | lang: ruby | verifies: array-arg system/Open3 prints metachars literally
require "open3"
require "rbconfig"
out, status = Open3.capture2(RbConfig.ruby, "-e", "print ARGV[0]", "GRAFT_A && echo GRAFT_B")
abort "FAIL: argv form interpreted metachars" unless out == "GRAFT_A && echo GRAFT_B" && status.success?
puts "ruby exec.noshell OK: array form prints metachars literally — argument injection class"
