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
            call_function('lookup', "#{lookupkey}_private", Puppet::Pops::Types::PStringType::NON_EMPTY, 'first', nil)
        else
            call_function('lookup', "#{lookupkey}_certificate", Puppet::Pops::Types::PStringType::NON_EMPTY, 'first', nil)
        end
    end
  end