module SSHScan
  module SSHLib
    class Mpssh
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
        match = @banner.match(/mpSSH_(\d+[\.\d+]+(p)?(\d+)?)/i)
        return nil if match.nil?
        return Mpssh::Version.new(match[1])
      end

      def common
        "mpssh"
      end

      def cpe
        "a:mpssh:mpssh" << (":" + version.to_s) unless version.nil?
      end
    end
  end
end
