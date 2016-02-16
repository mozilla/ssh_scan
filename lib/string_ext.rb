# Extend string to include some helpful stuff
class String
  def unhexify
    [self].pack("H*")
  end
end
