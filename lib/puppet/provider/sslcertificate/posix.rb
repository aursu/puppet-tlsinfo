require 'openssl'

Puppet::Type.type(:sslcertificate).provide :posix do
  desc 'Uses POSIX functionality to manage certificate file.'

  attr_reader :store

  def remove_file
    Puppet::FileSystem.unlink(@resource[:path])
  end

  def make_x509_store(*chain)
    store = OpenSSL::X509::Store.new
    chain.flatten.each do |c|
      begin
        store.add_cert(c) if c.is_a?(OpenSSL::X509::Certificate)
      rescue OpenSSL::X509::StoreError
        # in case of duplicate certificate
        next
      end
    end
    store
  end

  # validate certificate chain
  def validate
    rootca = false
    rootca = true if resource.rootca?

    @store = make_x509_store(resource.cacertobj, resource.cachain(rootca)) if store.nil?

    cabundle = nil
    if Facter.value(:osfamily).casecmp('redhat').zero?
      cabundle = '/etc/pki/tls/certs/ca-bundle.crt'
    elsif Facter.value(:osfamily).casecmp('debian').zero?
      cabundle = '/etc/ssl/certs/ca-certificates.crt'
    end

    # Add root certificates if exists
    store.add_file(cabundle) if cabundle && File.exist?(cabundle)

    status = store.verify(resource.certobj)

    # certificate is valid
    return true if status

    if store.chain.count > 1
      # certificate match to provided intermediate CA (Root CA is not available)
      return true unless cabundle && File.exist?(cabundle)

      # if cabundle exists then intermediate CA is not valid or chain is not
      # complete if X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT error occured
      # see https://www.openssl.org/docs/manmaster/man1/verify.html
      if store.error == 2
        casubject = resource.cacertobj.map { |c| c.subject.to_s }.join(', ')
        warning _('Provided Intermediate CA certificate (subject: %{casubject}) is not trusted by any root certificate from CA bundle %{path}') %
                {
                  casubject: casubject,
                  path: cabundle,
                }
      end

      return true unless resource.strict?
    end

    # no CA available - no chain verification
    return false unless resource.cacertobj

    raise Puppet::Error, _('Certificate %{path} is not valid due to error %{errcode}: %{errmsg}') %
                         {
                           path: resource[:path],
                           errcode: store.error,
                           errmsg: store.error_string,
                         }
  end

  def chain(rootca = nil)
    validate unless store
    return nil unless store && store.chain

    # default behavior - to not include Root CA
    rootca = false if rootca.nil?

    return store.chain if rootca
    store.chain.reject { |c| c.subject == c.issuer }
  end

  def chainpem(rootca = nil)
    return nil unless chain(rootca)
    chain(rootca).map { |c| c.to_pem }.join
  end
end
