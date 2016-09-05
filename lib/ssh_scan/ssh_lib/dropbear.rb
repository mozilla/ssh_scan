module SSHScan
  module SSHLib
    class Dropbear
      class Version
        def initialize(version_string)
          if version_string == nil
            @version_string = "unknown"
          else
            @version_string = version_string
          end
        end
        def to_s
          @version_string
        end
      end

      def initialize(banner)
        @banner = banner
        @version = Dropbear::Version.new(dropbear_version_guess)
      end

      def dropbear_version_guess
        return nil if @banner.nil?
        match = @banner.match(/SSH-2.0-dropbear_(\d+.\d+(?:.\d)?(?:test(:?\d)?)?)/)
        return nil if match.nil?
        return match[1]
      end

      def common
        "dropbear"
      end

      def cpe
        "o:dropbear:dropbear:#{@version.to_s}"
      end

      def version
        @version
      end
    end
  end
end

