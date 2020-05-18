$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))
require 'puppet_x/tlsinfo/x509_tools'

Puppet::Functions.create_function(:'tlsinfo::lookup') do
  dispatch :lookup do
    param 'String', :key
    optional_param 'Boolean', :private
  end

  def lookup(key, private = false)
    lookupkey = Puppet_X::TlsInfo.normalize(key)
    if private
      begin
        call_function('lookup', "#{lookupkey}_private", Puppet::Pops::Types::PStringType::NON_EMPTY, 'first', nil)
      rescue => detail
        raise Puppet::Error, "Can not find #{lookupkey}_private in Hiera: #{detail}", detail.backtrace
      end
    else
      begin
        call_function('lookup', "#{lookupkey}_certificate", Puppet::Pops::Types::PStringType::NON_EMPTY, 'first', nil)
      rescue => detail
        raise Puppet::Error, "Can not find #{lookupkey}_certificate in Hiera: #{detail}", detail.backtrace
      end
    end
  end
end
