module SSHScan
  class RuleEngine
    # Simple one rule matching.
    def self.matchSingleRule(key, value, result)
      conditional = key.split("_")[-1]
      attribute = key.chomp("_" + conditional).to_sym
      rvalue = result[attribute]
      if rvalue
        answer = case conditional
          when "eq" then (rvalue == value)
          when "neq" then (rvalue != value)
        end
        return answer if answer
      end
      if rvalue.is_a? Numeric
        answer = case conditional
          when "gt" then (rvalue > value)
          when "lt" then (rvalue < value)
          when "gte" then (rvalue >= value)
          when "lte" then (rvalue <= value)
        end
        return answer if answer
      end
      return false
    end

    # Match a simple ruleset condition using the stack based parser.
    def self.matchRuleset(rules, ruleset, result)
      mem = {}
      rules.each do |rule_name, values|
        mem[rule_name] = matchSingleRule(values[0], values[1], result)
      end
      return parseBooleanRule(ruleset, mem)
    end

    # Check if o is boolean or not. Apparently is_a?(Boolean) is not a thing.
    def self.checkBool(o)
      !!o == o
    end

    # Reduce boolean expression parser stack once.
    # Examples of stacks and what reduction does -
    # ( T && ( F && T   =>    ( T && ( F
    # ( T || ( F || T   =>    ( T || ( T
    # ( T && ! F        =>    ( T && T
    def self.reduceStack!(stack)
      if (stack[-2] == '!') && checkBool(stack[-1])
        new_tokenval = !stack[-1]
        2.times { stack.pop }
        stack << new_tokenval
      elsif (stack[-2] == '&&') && checkBool(stack[-3]) && checkBool(stack[-1])
        new_tokenval = stack[-1] && stack[-3]
        3.times { stack.pop }
        stack << new_tokenval
      elsif (stack[-2] == '||') && checkBool(stack[-3]) && checkBool(stack[-1])
        new_tokenval = stack[-1] || stack[-3]
        3.times { stack.pop }
        stack << new_tokenval
      else
        # if we cannot reduce, say so
        return false
      end
      # if we exited from the if, we have reduced something, so say so
      return true
    end

    # Parse a boolean expression with parentheses, uses stack.
    def self.parseBooleanRule(rule, inputs)
      tokens = rule.delete(' ').gsub('(', ' ( ').gsub(')', ' ) ')
                   .gsub('&&', ' && ').gsub('||', ' || ').gsub('!', ' ! ').split
      stack = []
      tokens.each do |token|
        case token
          when /^[a-zA-Z0-9]*$/
            tokenval = if inputs.include?(token) then inputs[token]
                       elsif inputs.include?(token.to_sym) then inputs[token.to_sym]
              end
            return nil if tokenval.nil?
            stack << tokenval
          when "(", "&&", "||", "!"
            stack << token
          when ")"
            if stack[-2] == "("
              new_val = stack[-1]
              2.times { stack.pop }
              stack << new_val
            else
              return nil
            end
        end
        loop do
          break unless reduceStack!(stack)
        end
      end
      return stack[0] if stack.length == 1
      return nil
    end
  end
end
