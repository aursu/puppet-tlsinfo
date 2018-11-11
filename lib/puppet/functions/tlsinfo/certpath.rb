$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'puppet_x/tlsinfo/tlsinfo'

Puppet::Functions.create_function(:'tlsinfo::certpath') do

    dispatch :certpath do
        param 'String', :cert
        optional_param 'Stdlib::Unixpath', :basepath
    end

    def certpath(cert, basepath = '/etc/pki/tls/certs')
        base = Puppet_X::TlsInfo.basename(cert)
        "#{basepath}/#{base}.pem"
    end
  end
