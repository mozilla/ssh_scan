module SSHScan
  # A very crude means of translating # of compliance recommendations into a a grade
  # Basic formula is 100 - (# of recommendations * 10)
  class Grader
    GRADE_MAP = {
      91..100 => "A",
      81..90 => "B",
      71..80 => "C",
      61..70 => "D",
      0..60 => "F",
    }

    def initialize(result)
      @result = result
    end

    def grade
      score = 100

      if @result.compliance_recommendations.each do |recommendation|
          score -= 10
        end
      end

      GRADE_MAP.each do |score_range,grade|
        if score_range.include?(score)
          return grade
        end
      end
    end
  end
end