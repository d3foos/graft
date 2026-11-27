# family: fs.path.join | lang: ruby | verifies: File.join does NOT reset (rev-1 error fixed)
abort "FAIL" unless File.join("/base", "/etc/passwd") == "/base/etc/passwd"
abort "FAIL" unless File.join("/base", "x") == "/base/x"
puts "ruby path OK: File.join keeps base — no reset; expand_path resolves against cwd, not the base"