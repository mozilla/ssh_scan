module SSHScan
  module SSHLib
    class OpenSSH
      class Version
        def initialize(version_string)
          @version_string = version_string
        end

        def to_s
          @version_string
        end
      end

      def initialize(banner = nil)
        @banner = banner
      end

      def version()
        return nil if @banner.nil?
        match = @banner.match(/OpenSSH_(\d+[\.\d+]+(p)?(\d+)?)/)
        return nil if match.nil?
        return OpenSSH::Version.new(match[1])
      end

      def common
        "openssh"
      end

      def cpe
        "a:openssh:openssh" << (":" + version.to_s) unless version.nil?
      end
    end
  end
end
