module SSHScan
  module OS
    class Windows
      def common
        "windows"
      end

      def cpe
        "o:microsoft:windows"
      end
    end
  end
end
