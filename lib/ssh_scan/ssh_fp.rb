require 'resolv'

module SSHScan
  class SshFp
    
    ALGO_MAP = {
      0 => "reserved", # Reference: https://tools.ietf.org/html/rfc4255#section-2.4
      1 => "rsa",      # Reference: https://tools.ietf.org/html/rfc4255#section-2.4
      2 => "dss",      # Reference: https://tools.ietf.org/html/rfc4255#section-2.4
      3 => "ecdsa",    # Reference: https://tools.ietf.org/html/rfc6594#section-5.3.1
      4 => "ed25519"   # Reference: https://tools.ietf.org/html/rfc7479
    }

    
    FPTYPE_MAP = {
      0 => "reserved",  # Reference: https://tools.ietf.org/html/rfc4255#section-2.4
      1 => "sha1",      # Reference: https://tools.ietf.org/html/rfc4255#section-2.4
      2 => "sha256"     # Reference: https://tools.ietf.org/html/rfc6594#section-5.1.2
    }


    def query(fqdn)
      sshfp_records = []

      # try up to 3 times to resolve ssh_fp's
      5.times do

        # Reference: https://stackoverflow.com/questions/28867626/how-to-use-resolvdnsresourcegeneric
        # Note: this includes some fixes too, I'll post a direct link back to the SO article.
        Resolv::DNS.open do |dns|
           all_records = dns.getresources(fqdn, Resolv::DNS::Resource::IN::ANY ) rescue nil
           all_records.each do |rr|
              if rr.is_a? Resolv::DNS::Resource::Generic then
                 classname = rr.class.name.split('::').last
                 if classname == "Type44_Class1"
                   data = rr.data.bytes
                   algo = data[0].to_s
                   fptype = data[1].to_s
                   fp = data[2..-1]
                   hex = fp.map{|b| b.to_s(16).rjust(2,'0') }.join(':')
                   sshfp_records << {"fptype" => FPTYPE_MAP[fptype.to_i], "algo" => ALGO_MAP[algo.to_i], "hex" => hex}
                 end
              end
           end
        end

        if sshfp_records.any?
          return sshfp_records.sort_by { |k| k["hex"] }
        end

        sleep 0.5
      end 

      return sshfp_records
    end
  end
end