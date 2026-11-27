# family: sink.deser.native | lang: ruby | verifies: Marshal decodes attacker-shaped bytes
class Graft
  def initialize
    @x = "graft"
  end
  attr_reader :x
end
g = Marshal.load(Marshal.dump(Graft.new))
abort "FAIL: marshal roundtrip" unless g.is_a?(Graft) && g.x == "graft"
puts "ruby deser OK: Marshal decodes attacker-shaped bytes (gadgets need reachable classes — see hazards)"