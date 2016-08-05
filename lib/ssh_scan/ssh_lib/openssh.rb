module SSHScan
  module SSHLib
    class OpenSSH
      def common
        "openssh"
      end

      def cpe
        "a:openssh:openssh"
      end
    end
  end
end
