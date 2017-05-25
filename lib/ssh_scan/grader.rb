module SSHScan
  class Grader
    # Inspired by http-observatory grading scheme
    # https://github.com/mozilla/http-observatory/blob/master/httpobs/scanner/grader/grade.py
    GRADE_SCHEME = {
      100..96 => "A+",
      95..90 => "A",
      89..85 => "A-",
      84..80 => "B+",
      79..70 => "B",
      69..65 => "B-",
      64..60 => "C+",
      59..50 => "C",
      49..45 => "C-",
      44..40 => "D+",
      39..30 => "D",
      29..25 => "D-",
      24..0 => "F"
    }

    def initialize(result, policy)
      @result = result
    end

    def grade
      if results['compliance']
        if results['compliance'][:recommendations]
          
        end
      else
        return "unknown"
      end
    end 
  end
end
