module SSHScan
  module SSHLib
    class IpSsh
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
        match = @banner.match(/IPSSH-(\d+[\.\d+]+(p)?(\d+)?)/)
        return nil if match.nil?
        return IpSsh::Version.new(match[1])
      end

      def common
        "ipssh"
      end

      def cpe
        "a:ipssh:ipssh" << (":" + version.to_s) unless version.nil?
      end
    end
  end
end
