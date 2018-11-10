require 'openssl'

module Puppet::Util::TlsInfo

    def read_x509_cert(value)
        raw = value.is_a?(Puppet::Pops::Types::PBinaryType::Binary) ? value.binary_buffer : value
        OpenSSL::X509::Certificate.new(raw)
    rescue OpenSSL::X509::CertificateError => e
        Puppet.warning(_('Can not create X509 Certificate object (%{message})') % { message: e.message })
        nil
    end

end