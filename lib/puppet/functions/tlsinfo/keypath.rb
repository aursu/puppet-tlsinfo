$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'puppet/util/tlsinfo'

Puppet::Functions.create_function(:'tlsinfo::keypath') do
    extend Puppet::Util::TlsInfo

    dispatch :keypath do
        param 'String', :cert
        optional_param 'Stdlib::Unixpath', :basepath
    end

    def keypath(cert, basepath = '/etc/pki/tls/private')
        base = basename(cert)
        "#{basepath}/#{base}.key"
    end
  end
