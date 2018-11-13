$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))
require 'puppet_x/tlsinfo/x509_tools'

Puppet::Functions.create_function(:'tlsinfo::certpath') do

    dispatch :certpath do
        param 'String', :cert
        optional_param 'Stdlib::Unixpath', :basepath
    end

    def certpath(cert, basepath = nil)
        unless basepath
            basepath = closure_scope['tlsinfo::params::certbase']
        end
        base = Puppet_X::TlsInfo.basename(cert)
        "#{basepath}/#{base}.pem"
    end
  end
