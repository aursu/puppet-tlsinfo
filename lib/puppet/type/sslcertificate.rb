$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', '..'))
require 'puppet_x/tlsinfo/x509_tools'
require 'puppet/util/checksums'

Puppet::Type.newtype(:sslcertificate) do
  def self.title_patterns
    # strip trailing slashes from path but allow the root directory, including
    # for example "/" or "C:/"
    [[%r{^(/|.+:/|.*[^/])/*\Z}m, [[:path]]]]
  end

  ensurable do
    newvalue(:absent) do
      provider.remove_file
    end

    newvalue(:present) do
    end

    defaultto :present

    def retrieve
      return :present if (stat = resource.stat) && stat.ftype.to_s == 'file'
      :absent
    end
  end

  newparam(:subject_hash) do
    desc 'Certificate subject hash (read only)'

    munge { resource.cert_hash }
    defaultto { resource.cert_hash }
  end

  newparam(:subject_hash_old) do
    desc 'Certificate subject hash (read only)'

    munge { resource.cert_hash_old }
    defaultto { resource.cert_hash_old }
  end

  newparam(:path) do
    desc 'The path to the private key to manage.  Must be fully qualified.'

    isnamevar

    validate do |value|
      unless Puppet::Util.absolute_path?(value)
        fail Puppet::Error, _("File paths must be fully qualified, not '%{path}'") % { path: value }
      end
    end

    munge do |value|
      resource.fixpath(value)
    end
  end

  newparam(:pkey) do
    desc 'The path to the private key to use. Must be fully qualified.'

    attr_reader :sslkey

    validate do |value|
      unless Puppet::Util.absolute_path?(value)
        fail Puppet::Error, _("Pkey parameter must be fully qualified path to private key, not '%{path}'") % { path: value }
      end
      unless @resource.catalog.resource(:sslkey, value)
        fail Puppet::Error, _('You must define resource Sslkey[%{path}]') % { path: value }
      end
    end

    munge do |value|
      keypath = resource.fixpath(value)
      @sslkey = @resource.catalog.resource(:sslkey, keypath)
      keypath
    end

    def keyobj
      return sslkey.keyobj if sslkey
      nil
    end
  end

  newparam(:cacert) do
    desc 'The path to the private key to use. Must be fully qualified.'

    attr_reader :sslcert

    validate do |value|
      if !!value == value # rubocop:disable Style/DoubleNegation : Could not find a better way to check if a boolean
        # cacert => true means CA Intermediate certificate already MUST be defined in caralog
        # cacert => false means we do not manage CA Intermediate certificate (therefore validation passed)
        if value && resource.lookupcatalog(resource.cert_issuer_hash).nil?
          fail Puppet::Error, _('You must define Sslcertificate resource with subject %{subject}') %
                              { subject: resource.cert_issuer }
        end
      else
        # cacert => String is reference to Sslcertificate resource title or system path
        value = [value] if value.is_a?(String)
        fail Puppet::Error, _('Sslcertificate[cacert] must be either Boolean or String or Array of strings') unless value.is_a?(Array)
        value.each do |cert|
          if resource.lookupcatalog(cert).nil?
            fail Puppet::Error, _('You must define resource Sslcertificate with title or path %{name}') % { name: cert }
          end
        end
      end
    end

    munge do |value|
      @sslcert = []
      if !!value == value # rubocop:disable Style/DoubleNegation : Could not find a better way to check if a boolean
        # if it is true
        if value
          # resolve certificate resource in catalog using Issuer hash
          cert = resource.lookupcatalog(resource.cert_issuer_hash)
          @sslcert += [cert]
          # return array of certificate paths
          [cert[:path]]
        else
          nil
        end
      else
        value = [value] if value.is_a?(String)
        value.map do |certpath|
          cert = resource.lookupcatalog(certpath)
          @sslcert += [cert]
          cert[:path]
        end
      end
    end

    def certobj
      return nil unless sslcert
      sslcert.map { |c| c.certobj }
    end

    def certchain
      return nil unless sslcert
      sslcert.map { |c| c.certchain }.flatten.uniq
    end
  end

  newparam(:replace, boolean: true, parent: Puppet::Parameter::Boolean) do
    desc "Whether to replace a certificate file that already exists on the local
      system but whose content doesn't match what the `content` attribute
      specifies. Setting this to false allows sslkey resources to initialize private
      key file without overwriting future changes.  Note that this only affects
      content; Puppet will still manage ownership and permissions. Defaults to
      `true`."
    defaultto :true
  end

  newparam(:chain, boolean: true, parent: Puppet::Parameter::Boolean) do
    desc 'Whether to place Intermediate certificate into certificate file or not'
    defaultto :true
  end

  newparam(:identity) do
    desc "Identtity which certificate should represent (eg domain name). Certificate
    Common Name or any of DNS name must match identity field"

    validate do |value|
      if value.is_a?(String)
        fail Puppet::Error, _('Domain name must be non-empty string') if value.empty?
      elsif value.is_a?(Array)
        value.each do |entity|
          fail Puppet::Error, _('Domain name inside list must be a string') unless entity.is_a?(String)
          fail Puppet::Error, _('Domain name inside list must be a non-empty string') if entity.empty?
        end
      else
        fail Puppet::Error, _('Parameter Sslcertificate[identity] must be string or list of strings')
      end
    end

    munge do |value|
      Array(value).uniq
    end
  end

  newproperty(:content) do
    include Puppet::Util::Checksums

    attr_reader :actual_content, :certobj, :chain

    validate do |value|
      fail Puppet::Error, 'Certificate must be not empty' if value.nil? || value.empty?

      cert = Puppet_X::TlsInfo.read_x509_cert(value)
      fail Puppet::Error, _('Can not read certificate content') if cert.nil?
      fail Puppet::Error, _('Certificate is not yet valid (Not Before is %{time})') % { time: cert.not_before.asctime } if cert.not_before > Time.now
      fail Puppet::Error, _('Certificate has expired (Not After is %{time})') % { time: cert.not_after.asctime } if cert.not_after < Time.now

      # TODO: add notification and tagging for tagmail
    end

    munge do |value|
      @certobj = Puppet_X::TlsInfo.read_x509_cert(value)
      @actual_content = certobj.to_pem
      '{sha256}' + sha256(modulus)
    end

    def retrieve
      # Private key file must be not empty.
      return nil unless (stat = resource.stat)
      return nil if stat.zero?
      begin
        @chain = Puppet_X::TlsInfo.read_x509_chain(resource[:path])
        return nil if chain.nil?

        cert = chain[0]
        '{sha256}' + sha256(Puppet_X::TlsInfo.x509_cert_modulus(cert))
      rescue => detail
        raise Puppet::Error, "Could not read #{stat.ftype} #{resource.title}: #{detail}", detail.backtrace
      end
    end

    def insync?(is)
      return true unless resource.should_be_present?
      return false if is.nil?
      return true unless resource.replace?

      # chain handling
      if resource.chain?
        return false if resource.cacertobj && chain.count == 1
        return false if (c = resource.cachain) && chain.count < (1 + c.count)
      elsif chain.count > 1
        # not in sync if should not be chain but it is
        return false
      end

      super(is)
    end

    def sync
      return_event = resource.stat ? :content_changed : :content_created
      mode_int = 0o0644
      File.open(@resource[:path], 'wb', mode_int) { |f| write(f) }
      # configuration synced here - no need to sync it elsewhere
      return_event
    end

    def write(file)
      # write chain if requested
      content = if resource.chain? && (c = provider.chainpem)
                  c
                else
                  actual_content
                end

      checksum = sha256_stream do |sum|
        sum << content
        file.print content
      end
      "{sha256}#{checksum}"
    end

    def modulus
      return nil if certobj.nil?
      Puppet_X::TlsInfo.rsa_key_modulus(certobj)
    end
  end

  autorequire(:file) do
    req = []
    path = Pathname.new(self[:path])
    unless path.root?
      # Start at our parent, to avoid autorequiring ourself
      parents = path.parent.enum_for(:ascend)
      if (found = parents.find { |p| catalog.resource(:file, p.to_s) })
        req << found.to_s
      end
    end

    req
  end

  autorequire(:sslkey) do
    self[:pkey]
  end

  autorequire(:sslcertificate) do
    self[:cacert]
  end

  validate do
    if certobj
      # check if certificate and private key match
      if (p = @parameters[:pkey]) && !certobj.check_private_key(p.keyobj)
        self.fail _('Certificate public key does not match private key %{path}') % { path: self[:pkey] }
      end

      # check if specified identitiesand certificate subject names are match
      if self[:identity]
        names = cert_names
        unless (names & self[:identity]) == names
          self.fail _('Certificate names (%{names}) do not match provided identities (%{identity})') %
                    {
                      names: names,
                      identity: self[:identity]
                    }
        end
      end

      # provider validates CA issuer(s)
      provider.validate if provider.respond_to?(:validate)
    elsif should_be_present?
      self.fail _('Sslcertificate[content] property is mandatory for certificate')
    end
  end

  def initialize(hash)
    super
    self[:ensure] = :present if self[:ensure].nil? && self[:content]
  end

  def fixpath(value)
    path =  if value.include?('/')
              File.join(File.split(value))
            else
              value
            end
    return File.expand_path(path) if Puppet::Util.absolute_path?(path)
    path
  end

  def stat(path = nil)
    path = self[:path] unless path
    Puppet::FileSystem.stat(path)
  rescue Errno::ENOENT
    nil
  rescue Errno::ENOTDIR
    nil
  rescue Errno::EACCES
    warning _('Could not stat; permission denied')
    nil
  rescue Errno::EINVAL
    warning _('Could not stat; invalid pathname')
    nil
  end

  def lookupcatalog(key)
    return nil unless catalog
    # path, subject_hash and title are all key values
    catalog.resources.find { |r| r.is_a?(Puppet::Type.type(:sslcertificate)) && [r[:subject_hash], r[:subject_hash_old], r[:path], r.title].include?(key) }
  end

  # return OpenSSL::X509::Certificate representation of content property
  def certobj
    return nil unless content
    content.certobj
  end

  # return Array[OpenSSL::X509::Certificate] - certificate chain for current certificate
  def certchain
    provider.chain
  end

  # return OpenSSL::X509::Certificate representation of Intermediate certificate
  def cacertobj
    return nil unless cacert
    cacert.certobj
  end

  # return Array[OpenSSL::X509::Certificate] - certificate chain of Intermediate certificate
  # duplicate certificates are possible
  def cachain
    return nil unless cacert
    cacert.certchain
  end

  def cert_names
    Puppet_X::TlsInfo.cert_names(certobj)
  end

  def cert_issuer
    Puppet_X::TlsInfo.cert_issuer(certobj)
  end

  def cert_issuer_hash
    Puppet_X::TlsInfo.cert_issuer_hash(certobj)
  end

  def cert_hash
    Puppet_X::TlsInfo.cert_hash(certobj)
  end

  def cert_hash_old
    Puppet_X::TlsInfo.cert_hash_old(certobj)
  end

  def should_be_present?
    self[:ensure] == :present
  end

  private

  # return :content property
  def content
    @parameters[:content]
  end

  # return :cacert property
  def cacert
    @parameters[:cacert]
  end
end
