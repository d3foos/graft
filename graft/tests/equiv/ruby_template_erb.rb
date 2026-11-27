# family: sink.template.render | lang: ruby | verifies: ERB evaluates template code in stdlib
require "erb"
out = ERB.new("<%= 7*7 %>").result
abort "FAIL: ERB did not evaluate" unless out.strip == "49"
puts "ruby template OK: ERB evaluates <%= %> — TEMPLATE_EVAL live in stdlib"