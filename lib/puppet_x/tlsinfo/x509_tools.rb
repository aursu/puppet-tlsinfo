require 'openssl'
require 'securerandom'

# rubocop:disable Style/Documentation, Style/ClassAndModuleChildren, Style/ClassAndModuleCamelCase
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

    def self.read_ec_key(value, password = nil)
      raw = value.is_a?(Puppet::Pops::Types::PBinaryType::Binary) ? value.binary_buffer : value
      password = SecureRandom.urlsafe_base64(10) unless password

      OpenSSL::PKey::EC.new(raw, password)
    rescue OpenSSL::PKey::ECError => e
      Puppet.warning _('Can not create ECDSA/ECDH PKey object (%{message})') % { message: e.message }
      nil
    end

    def self.read_key(value, password = nil)
      read_rsa_key(value, password) || read_ec_key(value, password)
    end

    def self.rsa_key_size(key)
      key.params['n'].num_bits
    end

    def self.rsa_key_modulus(key)
      key.params['n'].to_s(16)
    end

    def self.ec_key_pubkey(key)
      return key.public_to_der if key.respond_to?(:public_to_der)
  
      pub = OpenSSL::PKey::EC.new(key)
      pub.private_key = nil

      pub.to_der
    end

    # openssl rsa -des3 -in <key> -passout pass:<@resource[:password]>
    def self.key_to_pem(key, password = nil)
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
      # cn  and data could be nil in case if Common Name is absent
      cn, = certobj.subject.to_a.select { |name, _data, _type| name == 'CN' }
      _name, data, _type = cn

      # check also if data is empty string
      if basicconstraints && basicconstraints['value'].include?('CA:TRUE') || data.nil? || data.empty?
        # basename is Certificate subject hash
        i = certobj.subject.hash
        '%08x' % [i].pack('L').unpack('L').first
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
      return [dns1].compact unless altname
      ([dns1] + altname['value'].split(',')
        .map { |san| san.strip.split(':') }
        .select { |m, _san| m == 'DNS' }
        .map { |_m, san| san }).uniq.compact
    end

    def self.cert_hash(cert)
      '%08x' % cert.subject.hash
    end

    def self.cert_hash_old(cert)
      '%08x' % cert.subject.hash_old
    end

    def self.cert_issuer(cert)
      cert.issuer.to_s
    end

    def self.cert_issuer_hash(cert)
      '%08x' % cert.issuer.hash
    end

    def self.x509_cert_modulus(cert)
      cert.public_key.params['n'].to_s(16)
    end

    def self.x509_cert_pubkey(cert, der=false)
      return cert.public_key.to_der if der
      cert.public_key
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
      return nil if certobj.nil?

      store = OpenSSL::X509::Store.new
      store.add_file(path)
      store.verify(certobj)

      store.chain
    end
  end
end
