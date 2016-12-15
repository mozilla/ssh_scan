require 'rspec'
require 'ssh_scan/rule_engine'

# ignore absurdities in rules, they have been created to test the rule engine
describe SSHScan::RuleEngine do
  context "match single rule" do
    it "eq should work for non numerics" do
      result = {:ssh_lib => "openssh"}
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_lib_eq", "openssh", result)).to be true
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_lib_eq", "libssh", result)).to be false
    end

    it "neq should work for non numerics" do
      result = {:ssh_lib => "openssh"}
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_lib_neq", "dropbear", result)).to be true
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_lib_neq", "openssh", result)).to be false
    end

    it "eq should work for numerics" do
      result = {:ssh_version => 2.0}
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_eq", 2.0, result)).to be true
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_eq", 1.99, result)).to be false
    end

    it "neq should work for numerics" do
      result = {:ssh_version => 2.0}
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_neq", 1.99, result)).to be true
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_neq", 2.0, result)).to be false
    end

    it "gt should work for numerics" do
      result = {:ssh_version => 2.0}
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_gt", 1.99, result)).to be true
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_gt", 2.0, result)).to be false
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_gt", 2.1, result)).to be false
    end

    it "gte should work for numerics" do
      result = {:ssh_version => 2.0}
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_gte", 1.99, result)).to be true
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_gte", 2.0, result)).to be true
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_gte", 2.1, result)).to be false
    end

    it "lt should work for numerics" do
      result = {:ssh_version => 2.0}
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_lt", 1.99, result)).to be false
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_lt", 2.0, result)).to be false
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_lt", 2.1, result)).to be true
    end

    it "lte should work for numerics" do
      result = {:ssh_version => 2.0}
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_lte", 2.1, result)).to be true
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_lte", 2.0, result)).to be true
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_version_lte", 1.99, result)).to be false
    end

    it "should not ignore attributes not in results" do
      result = {:ssh_version => 2.0}
      expect(SSHScan::RuleEngine.matchSingleRule("ssh_lib_eq", "openssh", result)).to be false
    end
  end

  # Note: inputs can be given in a hash as well
  context "parse conditional boolean expressions" do
    it "simple true/false" do
      expect(SSHScan::RuleEngine.parseBooleanRule("x", "x" => true)).to be true
      expect(SSHScan::RuleEngine.parseBooleanRule("x", "x" => false)).to be false
    end

    it "should work for NOT expressions" do
      expect(SSHScan::RuleEngine.parseBooleanRule("!x", "x" => true)).to be false
      expect(SSHScan::RuleEngine.parseBooleanRule("!x", "x" => false)).to be true
    end

    it "should work for AND expressions" do
      expect(SSHScan::RuleEngine.parseBooleanRule("x && y", "x" => true, "y" => true)).to be true
      expect(SSHScan::RuleEngine.parseBooleanRule("x && y", "x" => true, "y" => false)).to be false
      expect(SSHScan::RuleEngine.parseBooleanRule("x && y", "x" => false, "y" => true)).to be false
      expect(SSHScan::RuleEngine.parseBooleanRule("x && y", "x" => false, "y" => false)).to be false
    end

    it "should work for OR expressions" do
      expect(SSHScan::RuleEngine.parseBooleanRule("x || y", "x" => true, "y" => true)).to be true
      expect(SSHScan::RuleEngine.parseBooleanRule("x || y", "x" => true, "y" => false)).to be true
      expect(SSHScan::RuleEngine.parseBooleanRule("x || y", "x" => false, "y" => true)).to be true
      expect(SSHScan::RuleEngine.parseBooleanRule("x || y", "x" => false, "y" => false)).to be false
    end

    it "should work for compounded non bracketed AND, OR, NOT expressions" do
      expect(SSHScan::RuleEngine.parseBooleanRule("!x && y", "x" => false, "y" => true)).to be true
      expect(SSHScan::RuleEngine.parseBooleanRule("x || !y", "x" => false, "y" => false)).to be true
    end

    it "should work for compounded bracketed AND, OR, NOT expressions" do
      expect(SSHScan::RuleEngine.parseBooleanRule("x && (y || z)",
        "x" => false, "y" => true, "z" => false)).to be false
      expect(SSHScan::RuleEngine.parseBooleanRule("x && (y || z)",
        "x" => false, "y" => true, "z" => true)).to be false

      expect(SSHScan::RuleEngine.parseBooleanRule("!x || (y && (z || (!var)))",
        "x" => true, "y" => true, "z" => true, "var" => true)).to be true
 
      expect(SSHScan::RuleEngine.parseBooleanRule("x || !y", "x" => false, "y" => false)).to be true
      expect(SSHScan::RuleEngine.parseBooleanRule("!x || y", "x" => false, "y" => false)).to be true
      expect(SSHScan::RuleEngine.parseBooleanRule("x || y", "x" => false, "y" => false)).to be false
      expect(SSHScan::RuleEngine.parseBooleanRule("!x || !y", "x" => false, "y" => false)).to be true

      expect(SSHScan::RuleEngine.parseBooleanRule("x || !y", "x" => false, "y" => true)).to be false
      expect(SSHScan::RuleEngine.parseBooleanRule("!x || y", "x" => false, "y" => true)).to be true
      expect(SSHScan::RuleEngine.parseBooleanRule("x || y", "x" => false, "y" => true)).to be true
      expect(SSHScan::RuleEngine.parseBooleanRule("!x || !y", "x" => false, "y" => true)).to be true

      expect(SSHScan::RuleEngine.parseBooleanRule("x && !y", "x" => false, "y" => false)).to be false
      expect(SSHScan::RuleEngine.parseBooleanRule("!x && y", "x" => false, "y" => false)).to be false
      expect(SSHScan::RuleEngine.parseBooleanRule("x && y", "x" => false, "y" => false)).to be false
      expect(SSHScan::RuleEngine.parseBooleanRule("!x && !y", "x" => false, "y" => false)).to be true

      expect(SSHScan::RuleEngine.parseBooleanRule("x && !y", "x" => false, "y" => true)).to be false
      expect(SSHScan::RuleEngine.parseBooleanRule("!x && y", "x" => false, "y" => true)).to be true
      expect(SSHScan::RuleEngine.parseBooleanRule("x && y", "x" => false, "y" => true)).to be false
      expect(SSHScan::RuleEngine.parseBooleanRule("!x && !y", "x" => false, "y" => true)).to be false
    end
  end

  context "match simple rules + ruleset condition" do
    it "should be able to match complex conditions with OR, AND, NOT" do
      result1 = {:ssh_version => 2.0, :ssh_lib => "openssh"}
      result2 = {:ssh_version => 1.99, :ssh_lib => "dropbear"}
      result3 = {:ssh_version => 2.1, :ssh_lib => "dropbear"}
      rules = {
        "a" => ["ssh_version_gt", 1.99],
        "b" => ["ssh_lib_eq", "openssh"],
        "c" => ["ssh_lib_eq", "dropbear"],
        "d" => ["ssh_version_lt", 1.99]
      }
      ruleset = "(a && b) || (c && !d)" # !d means ssh_version_gte 1.99
      expect(SSHScan::RuleEngine.matchRuleset(rules, ruleset, result1)).to be true
      expect(SSHScan::RuleEngine.matchRuleset(rules, ruleset, result2)).to be true
      expect(SSHScan::RuleEngine.matchRuleset(rules, ruleset, result3)).to be true
      ruleset = "b && ((d))"
      expect(SSHScan::RuleEngine.matchRuleset(rules, ruleset, result1)).to be false
      expect(SSHScan::RuleEngine.matchRuleset(rules, ruleset, result2)).to be false
      expect(SSHScan::RuleEngine.matchRuleset(rules, ruleset, result3)).to be false
      result = {:ssh_version => 1.98, :ssh_lib => "openssh"}
      expect(SSHScan::RuleEngine.matchRuleset(rules, ruleset, result)).to be true
    end
  end
end
