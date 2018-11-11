$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))
require 'puppet_x/tlsinfo/x509_tools'

Puppet::Functions.create_function(:'tlsinfo::normalize') do
    dispatch :normalize do
        param 'String', :name
    end

    def normalize(name)
        Puppet_X::TlsInfo.normalize(commonname)
    end
end