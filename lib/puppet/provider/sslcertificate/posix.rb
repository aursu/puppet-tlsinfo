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
    return false unless resource.cacertobj || rooresource.rootca?tca

    @store = make_x509_store(resource.cacertobj, resource.cachain(resource.rootca?)) if store.nil?

    cabundle = nil
    if Facter.value(:osfamily).casecmp('redhat') == 0
      cabundle = '/etc/pki/tls/certs/ca-bundle.crt'
    elsif Facter.value(:osfamily).casecmp('debian') == 0
      cabundle = '/etc/ssl/certs/ca-certificates.crt'
    end

    # Add root certificates if exists
    store.add_file(cabundle) if cabundle && File.exist?(cabundle)

    status = store.verify(resource.certobj)
    return true if status

    # certificate match to provided intermediate CA
    if store.chain.count > 1
      return true unless cabundle && File.exist?(cabundle)

      # if cabundle exixts then intermediate CA is not valid
      casubject = resource.cacertobj.map { |c| c.subject.to_s }.join(', ')
      warning _('Provided Intermediate CA certificate (subject: %{casubject}) are not trusted by any root certificate from CA bundle %{path}') %
              {
                casubject: casubject,
                path: cabundle
              }
      return true unless resource.strict?
    end
    fail Puppet::Error, _('Certificate %{path} is not valid due to invalid CA (issuer: %{issuer})') %
                        {
                          path: resource[:path],
                          issuer: resource.certobj.issuer.to_s
                        }
  end

  def chain(rootca)
    validate unless store
    return nil unless store && store.chain

    # rootca flag could be disabled on parameters level
    return store.chain if rootca && resource.rootca?
    store.chain.reject { |c| c.subject == c.issuer }
  end

  def chainpem(rootca)
    return nil unless chain(rootca)
    chain(rootca).map { |c| c.to_pem }.join
  end
end
