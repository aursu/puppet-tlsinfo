$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))
require 'puppet_x/tlsinfo/x509_tools'

Puppet::Functions.create_function(:'tlsinfo::keypath') do

    dispatch :keypath do
        param 'String', :cert
        optional_param 'Stdlib::Unixpath', :basepath
    end

    def keypath(cert, basepath = '/etc/pki/tls/private')
        base = Puppet_X::TlsInfo.basename(cert)
        "#{basepath}/#{base}.key"
    end
  end
