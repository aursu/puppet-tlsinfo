require 'openssl'
require 'securerandom'

module Puppet_X
  module TlsInfo
    def self.read_rsa_key(value, password = nil)
      raw = value.is_a?(Puppet::Pops::Types::PBinaryType::Binary) ? value.binary_buffer : value
      password = SecureRandom.urlsafe_base64(10) unless password
      OpenSSL::PKey::RSA.new(raw, password)
    rescue OpenSSL::PKey::RSAError => e
      Puppet.warning _('Can not create RSA PKey object (%{message})') % { message: e.message }
      nil
    end

    def self.rsa_key_size(key)
      key.params['n'].num_bits
    end

    def self.rsa_key_modulus(key)
      key.params['n'].to_s(16)
    end

    # openssl rsa -des3 -in <key> -passout pass:<@resource[:password]>
    def self.rsa_to_pem(key, password = nil)
      return key.to_pem unless password
      cipher = OpenSSL::Cipher.new('DES3')
      key.to_pem(cipher, password)
    end

    def self.read_x509_cert(value)
      # raw = value.is_a?(Puppet::Pops::Types::PBinaryType::Binary) ? value.binary_buffer : value
      # OpenSSL::X509::Certificate.new(raw)
      OpenSSL::X509::Certificate.new(value)
    rescue OpenSSL::X509::CertificateError => e
      Puppet.warning(_('Can not create X509 Certificate object (%{message})') % { message: e.message })
      nil
    end

    def self.basename(cert)
      certobj = read_x509_cert(cert)

      basicconstraints, = certobj.extensions.select { |e| e.oid == 'basicConstraints' }.map { |e| e.to_h }
      cn, = certobj.subject.to_a.select { |name, _data, _type| name == 'CN' }
      _name, data, _type = cn

      if basicconstraints && basicconstraints['value'].include?('CA:TRUE')
        # basename is Certificate subject hash
        i = certobj.subject.hash
        [i].pack('L').unpack('L').first.to_s(16)
      else
        data.sub('*', 'wildcard')
      end
    end

    def self.normalize(name)
      name.sub('*', 'wildcard').tr('.-', '_').tr("'", '_').tr(' ', '_')
    end

    def self.cert_names(cert)
      cn, = cert.subject.to_a.select { |name, _data, _type| name == 'CN' }
      _name, dns1, _type = cn

      altname, = cert.extensions.select { |e| e.oid == 'subjectAltName' }.map { |e| e.to_h }
      return [dns1] unless altname
      ([dns1] + altname['value'].split(',')
        .map { |san| san.strip.split(':') }
        .select { |m, _san| m == 'DNS' }
        .map { |_m, san| san }).uniq
    end

    def self.cert_hash(cert)
      cert.subject.hash.to_s(16)
    end

    def self.cert_hash_old(cert)
      cert.subject.hash_old.to_s(16)
    end

    def self.cert_issuer(cert)
      cert.issuer.to_s
    end

    def self.cert_issuer_hash(cert)
      cert.issuer.hash.to_s(16)
    end

    def self.x509_cert_modulus(cert)
      cert.public_key.params['n'].to_s(16)
    end

    def self.cert_serial(cert)
      cert.serial.to_s(16)
    end

    def self.cert_not_before(cert)
      cert.not_before
    end

    def self.cert_not_before_valid(cert)
      cert.not_before < Time.now
    end

    def self.cert_not_before_message(cert)
      cert.not_before.strftime('notBefore=%b %_d %T %Y %Z')
    end

    def self.cert_not_after(cert)
      cert.not_after
    end

    def self.cert_not_after_valid(cert)
      cert.not_after > Time.now
    end

    def self.cert_not_after_message(cert)
      cert.not_after.strftime('notAfter=%b %_d %T %Y %Z')
    end

    def self.cert_valid(cert)
      cert_not_before_valid(cert) && cert_not_after_valid(cert)
    end

    def self.read_x509_chain(path)
      return nil unless File.exist?(path)
      cert = File.read(path)

      certobj = read_x509_cert(cert)
      return nil if cert.nil?

      store = OpenSSL::X509::Store.new
      store.add_file(path)
      store.verify(certobj)

      store.chain
    end
  end
end
