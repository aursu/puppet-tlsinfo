require 'openssl'

Puppet::Functions.create_function(:'tlsinfo::certpath') do
    dispatch :certpath do
        param 'String', :cert
        optional_param 'Stdlib::Unixpath', :basepath
    end

    def read_x509_cert(value)
        raw = value.is_a?(Puppet::Pops::Types::PBinaryType::Binary) ? value.binary_buffer : value
        OpenSSL::X509::Certificate.new(raw)
    rescue OpenSSL::X509::CertificateError => e
        Puppet.warning(_('Can not create X509 Certificate object (%{message})') % { message: e.message })
        nil
    end

    def basename(cert)
        certobj = read_x509_cert(cert)

        basicconstraints, = cert.extensions.select { |e| e.oid == 'basicConstraints' }.map { |e| e.to_h }
        cn, = cert.subject.to_a.select { |name, _data, _type| name == 'CN' }
        _name, data, _type = cn

        if basicconstraints && basicconstraints['value'].include?('CA:TRUE')
            # basename is Certificate subject hash
            cert.subject.hash.to_s(16)
        else
            data.sub('*', 'wildcard')
        end
    end

    def certpath(cert, basepath = '/etc/pki/tls/certs')
        base = basename(cert)
        "#{basepath}/#{base}.pem"
    end
  end
