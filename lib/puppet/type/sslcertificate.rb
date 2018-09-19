require 'puppet/util/symbolic_file_mode'
require 'puppet/util/checksums'
require 'openssl'

Puppet::Type.newtype(:sslcertificate) do
  include Puppet::Util::SymbolicFileMode

  newparam(:name) do
    desc 'Certificate name (key value)'
    isnamevar
  end

  ensurable do
    newvalue(:absent) do
      Puppet::FileSystem.unlink(@resource[:path])
    end

    newvalue(:present) do
      # Make sure we're not managing the content some other way
      if (property = @resource.property(:content))
        property.sync
      else
        @resource.write
        @resource.should(:mode)
      end
    end

    defaultto :present

    def insync?(current)
      unless current == :absent || resource.replace?
        return true
      end

      super(current)
    end

    def retrieve
      return :present if (stat = @resource.stat) && stat.ftype.to_s == 'file'
      :absent
    end

    def sync
      should = self.should
      current = retrieve

      unless current == :absent || current == should
        @resource.remove_file
      end

      if should == :absent
        return :file_removed
      end

      super
    end
  end

  newparam(:basepath) do
    desc 'The path to which we store certificate by default'

    defaultto '/etc/pki/tls/certs'

    validate do |value|
      unless Puppet::Util.absolute_path?(value)
        fail Puppet::Error, _("basepath must be fully qualified, not '%{path}'") % { path: value }
      end
    end

    munge do |value|
      resource.fixpath(value)
    end
  end

  newparam(:path) do
    desc 'The path to the private key to manage.  Must be fully qualified.'

    validate do |value|
      unless Puppet::Util.absolute_path?(value)
        fail Puppet::Error, _("File paths must be fully qualified, not '%{path}'") % { path: value }
      end
    end

    munge do |value|
      resource.fixpath(value)
    end

    defaultto { @resource[:basepath] + '/' + resource.certbasename }
  end

  newparam(:pkey) do
    desc 'The path to the private key to use. Must be fully qualified.'

    attr_reader :sslkey

    validate do |value|
      unless Puppet::Util.absolute_path?(value)
        fail Puppet::Error, _("File paths must be fully qualified, not '%{path}'") % { path: value }
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
      value = [value] if value.is_a?(String)
      value.each do |certpath|
        unless resource.lookupcatalog(certpath)
          fail Puppet::Error, _('You must define resource Sslcertificate[%{name}]') % { name: certpath }
        end
      end
    end

    munge do |value|
      value = [value] if value.is_a?(String)
      @sslcert = []
      value.map do |certpath|
        cert = resource.lookupcatalog(certpath)
        @sslcert += [cert]
        cert[:path]
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
          fail Puppet::Error, _('Domain name must be non-empty string') unless entity.is_a?(String) and !entity.empty?
        end
      else
        fail Puppet::Error, _('Parameter Sslcertificate[identity] must be string or array of strings')
      end
    end

    munge do |value|
      if value.is_a?(String)
        [value]
      else
        value
      end
    end
  end

  # copied from https://github.com/puppetlabs/puppet/blob/master/lib/puppet/type/file/mode.rb
  newproperty(:mode) do
    include Puppet::Util::SymbolicFileMode

    validate do |value|
      unless value.is_a?(String)
        fail Puppet::Error, "The file mode specification must be a string, not '#{value.class.name}'"
      end
      unless value.nil? || valid_symbolic_mode?(value)
        fail Puppet::Error, "The file mode specification is invalid: #{value.inspect}"
      end
    end

    munge do |value|
      return nil if value.nil?

      unless valid_symbolic_mode?(value)
        fail Puppet::Error, "The file mode specification is invalid: #{value.inspect}"
      end

      normalize_symbolic_mode(value)
    end

    def property_matches?(current, desired)
      return false unless current
      current_bits = normalize_symbolic_mode(current)
      desired_bits = desired_mode_from_current(desired, current).to_s(8)
      current_bits == desired_bits
    end

    def desired_mode_from_current(desired, current)
      current = current.to_i(8) if current.is_a? String
      symbolic_mode_to_int(desired, current)
    end

    def sync
      current = @resource.stat ? @resource.stat.mode : 0644
      set(desired_mode_from_current(@should[0], current).to_s(8))
    end
  end

  # copied from https://github.com/puppetlabs/puppet/blob/master/lib/puppet/type/file/checksum.rb
  newparam(:checksum) do
    include Puppet::Util::Checksums

    desc "The checksum type to use when determining whether to replace a file's contents.

      The default checksum type is md5."

    newvalues 'md5', 'md5lite', 'sha224', 'sha256', 'sha256lite', 'sha384', 'sha512'

    defaultto do
      Puppet[:digest_algorithm].to_sym
    end

    validate do |value|
      if Puppet::Util::Platform.fips_enabled? && [:md5, :md5lite].include?(value)
        fail ArgumentError, _('MD5 is not supported in FIPS mode')
      end
    end

    def sum(content)
      content = content.is_a?(Puppet::Pops::Types::PBinaryType::Binary) ? content.binary_buffer : content
      type = digest_algorithm
      "{#{type}}" + send(type, content)
    end

    def sum_file(path)
      type = digest_algorithm
      method = type.to_s + '_file'
      "{#{type}}" + send(method, path).to_s
    end

    def sum_stream(&block)
      type = digest_algorithm
      method = type.to_s + '_stream'
      checksum = send(method, &block)
      "{#{type}}#{checksum}"
    end

    private

    # Return the appropriate digest algorithm with fallbacks in case puppet defaults have not
    # been initialized.
    def digest_algorithm
      value || Puppet[:digest_algorithm].to_sym
    end
  end

  newproperty(:content) do
    include Puppet::Util::Checksums

    attr_reader :actual_content, :certobj, :chain

    validate do |value|
      fail Puppet::Error, 'Certificate must be not empty' if value.nil? || value.empty?
      if value.is_a?(String) && checksum?(value)
        fail Puppet::Error, 'Certificate must be provided via :content property' unless actual_content
      else
        cert = read_x509_cert(value)
        fail Puppet::Error, _('Can not read certificate content') if cert.nil?
        fail Puppet::Error, _('Certificate is not yet valid (Not Before is %{time})') % { time: cert.not_before.asctime } if cert.not_before > Time.now
        fail Puppet::Error, _('Certificate has expired (Not After is %{time})') % { time: cert.not_after.asctime } if cert.not_after < Time.now
      end
    end

    munge do |value|
      if value.is_a?(String) && checksum?(value)
        value
      else
        @certobj = read_x509_cert(value)
        @actual_content = cert_to_pem(certobj)

        resource.parameter(:checksum).sum(modulus)
      end
    end

    def length
      return 0 unless actual_content
      actual_content.length
    end

    def empty?
      return true unless actual_content
      actual_content.empty?
    end

    def insync?(current)
      # in sync if ensure is :absent
      return true unless resource.should_be_present?

      # not in sync if ensure is :present but file not exist
      return false if current == :absent

      # in sync if parameter replace is false (we do not replace content)
      return true unless resource.replace?

      # chain handling
      if resource.chain?
        return false if resource.cacertobj && chain.count == 1
        return false if (c = resource.cachain) && chain.count < (1 + c.count)
      elsif chain.count > 1
        # not in sync if should not be chain but it is
        return false
      end

      super(current)
    end

    def retrieve
      # Private key file must be not empty.
      return :absent unless (stat = resource.stat) && !stat.zero?
      begin
        @chain = read_x509_chain(resource[:path])
        return :absent if chain.nil?

        cert = chain[0]
        resource.parameter(:checksum).sum(x509_cert_modulus(cert))
      rescue => detail
        raise Puppet::Error, "Could not read #{stat.ftype} #{resource.title}: #{detail}", detail.backtrace
      end
    end

    # Make sure we're also managing the checksum property.
    def should=(value)
      # treat the value as a bytestring
      value = value.b if value.is_a?(String)
      @resource.newattr(:checksum) unless @resource.parameter(:checksum)
      super
    end

    # Just write our content out to disk.
    def sync
      return_event = resource.stat ? :file_changed : :file_created
      resource.write
      return_event
    end

    def write(file)
      resource.parameter(:checksum).sum_stream do |sum|
        each_chunk_from do |chunk|
          sum << chunk
          file.print chunk
        end
      end
    end

    def modulus
      return nil unless certobj
      x509_cert_modulus(certobj)
    end

    private

    def read_x509_cert(value)
      raw = value.is_a?(Puppet::Pops::Types::PBinaryType::Binary) ? value.binary_buffer : value
      # get :password property (if provided) or define it as random password
      OpenSSL::X509::Certificate.new(raw)
    rescue OpenSSL::X509::CertificateError => e
      warning _('Can not create X509 Certificate object (%{message})') % { message: e.message }
      nil
    end

    def read_x509_chain(path)
      return nil unless File.exist?(path)
      raw = File.read(path)

      cert = read_x509_cert(raw)
      return nil if cert.nil?

      store = OpenSSL::X509::Store.new
      store.add_file(path)
      store.verify(cert)

      store.chain
    end

    def cert_to_pem(cert)
      cert.to_pem
    end

    def x509_cert_modulus(cert)
      cert.public_key.params['n'].to_s(16)
    end

    # the content is munged so if it's a checksum source_or_content is nil
    # unless the checksum indirectly comes from source
    def each_chunk_from
      if resource.chain? && (c = provider.chainpem) && c.is_a?(String)
        yield c
      elsif actual_content.is_a?(String)
        yield actual_content
      elsif actual_content.nil?
        yield ''
      end
    end
  end

  newproperty(:owner) do
    include Puppet::Util::Warnings

    desc <<-DOC
      The user to whom the private key file should belong.  Argument can be
      a user name or a user ID.
    DOC

    def insync?(current)
      # We don't want to validate/munge users until we actually start to
      # evaluate this property, because they might be added during the catalog
      # apply.
      @should.map! do |val|
        provider.name2uid(val) || fail(Puppet::Error, _('Could not find user %{user}') % { user: val })
      end

      return true if @should.include?(current)

      unless Puppet.features.root?
        warnonce 'Cannot manage ownership unless running as root'
        return true
      end

      false
    end

    # We want to print names, not numbers
    def is_to_s(currentvalue)
      super(provider.uid2name(currentvalue) || currentvalue)
    end

    def should_to_s(newvalue)
      super(provider.uid2name(newvalue) || newvalue)
    end
  end

  newproperty(:group) do
    desc <<-DOC
      Which group should own the private key file. Argument can be either a
      group name or a group ID.
    DOC

    validate do |group|
      fail(Puppet::Error, "Invalid group name '#{group.inspect}'") unless group && group != ''
    end

    def insync?(current)
      # We don't want to validate/munge groups until we actually start to
      # evaluate this property, because they might be added during the catalog
      # apply.
      @should.map! do |val|
        provider.name2gid(val) || fail(Puppet::Error, _('Could not find group %{group}') % { group: val })
      end

      @should.include?(current)
    end

    # We want to print names, not numbers
    def is_to_s(currentvalue)
      super(provider.gid2name(currentvalue) || currentvalue)
    end

    def should_to_s(newvalue)
      super(provider.gid2name(newvalue) || newvalue)
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
      # Now that we know the checksum, update content (in case it was created before checksum was known).
      @parameters[:content].value = @parameters[:checksum].sum(content.modulus)

      if (p = @parameters[:pkey]) && !certobj.check_private_key(p.keyobj)
        self.fail _('Certificate public key does not match private key %{path}') % { path: self[:pkey] }
      end

      if self[:identity]
        names = certnames
        unless (names & self[:identity]) == names
          self.fail _('Certificate names (%{names}) do not match provided identity (%{identity})') %
                    {
                      names: names,
                      identity: self[:identity]
                    }
        end
      end

      provider.validate if provider.respond_to?(:validate)
    elsif should_be_present?
      self.fail _('Sslcertificate[content] property is mandatory for certificate')
    end
  end

  def initialize(hash)
    super

    if !self[:ensure] && self[:content]
      self[:ensure] = :present
    end

    @stat = :needs_stat
  end

  # Does the file currently exist?  Just checks for whether
  # we have a stat
  def exist?
    stat ? true : false
  end

  def should_be_present?
    self[:ensure] == :present
  end

  def stat
    return @stat unless @stat == :needs_stat

    @stat = begin
      Puppet::FileSystem.send(:stat, self[:path])
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
  end

  # Write out the private key file. To write content, we use property :content
  # write method
  def write
    mode = should(:mode) # might be nil
    mode_int = mode ? symbolic_mode_to_int(mode, Puppet::Util::DEFAULT_POSIX_MODE) : nil

    if (c = property(:content)) && !c.empty?
      Puppet::Util.replace_file(self[:path], mode_int) do |file|
        file.binmode

        content_checksum = c.write(file)
        file.flush

        begin
          file.fsync
        rescue NotImplementedError # rubocop:disable Lint/HandleExceptions
          # fsync may not be implemented by Ruby on all platforms, but
          # there is absolutely no recovery path if we detect that.  So, we just
          # ignore the return code.
          #
          # However, don't be fooled: that is accepting that we are running in
          # an unsafe fashion.  If you are porting to a new platform don't stub
          # that out.
        end

        fail_if_checksum_is_wrong(file.path, content_checksum)
      end
    else
      umask = mode ? 000 : 022
      Puppet::Util.withumask(umask) { File.open(self[:path], 'wb', mode_int) { |f| c.write(f) if c } }
    end

    # make sure all of the modes are actually correct
    property_fix
  end

  # @return [Boolean] if the file was removed (which is always true currently)
  # @api private
  def remove_file
    Puppet::FileSystem.unlink(self[:path])
    stat_needed
    true
  end

  def lookupcatalog(path)
    return nil unless catalog
    catalog.resources.find { |r| r.is_a?(Puppet::Type.type(:sslcertificate)) && [r.should(:path), r.title].include?(path) }
  end

  # return OpenSSL::X509::Certificate representation of content property
  def certobj
    return nil unless content
    content.certobj
  end

  # return Array[OpenSSL::X509::Certificate] - certificate chain for current resource
  def certchain
    provider.chain
  end

  # return OpenSSL::X509::Certificate representation of Intermediate certificate
  def cacertobj
    return nil unless @parameters[:cacert]
    @parameters[:cacert].certobj
  end

  # return Array[OpenSSL::X509::Certificate] - certificate chain of Intermediate certificate
  # duplicate certificates are possible
  def cachain
    return nil unless @parameters[:cacert]
    @parameters[:cacert].certchain
  end

  def certbasename(cert = nil)
    cert = certobj if cert.nil?

    basicconstraints, = cert.extensions.select { |e| e.oid == 'basicConstraints' }.map { |e| e.to_h }
    cn, = cert.subject.to_a.select { |name, _data, _type| name == 'CN' }
    _name, data, _type = cn

    base = if basicconstraints && basicconstraints['value'].include?('CA:TRUE')
             # basename is Certificate subject hash
             cert.subject.hash.to_s(16)
           else
             data.sub('*', 'wildcard')
           end
    "#{base}.pem"
  end

  def certnames(cert = nil)
    cert = certobj if cert.nil?

    cn, = cert.subject.to_a.select { |name, _data, _type| name == 'CN' }
    _name, dns1, _type = cn

    altname, = cert.extensions.select { |e| e.oid == 'subjectAltName' }.map { |e| e.to_h }
    return [dns1] unless altname
    ([dns1] + altname['value'].split(',')
      .map { |san| san.strip.split(':') }
      .select { |m, _san| m == 'DNS' }
      .map { |_m, san| san }).uniq
  end

  def fixpath(value)
    if value.start_with?('//') && File.basename(value) == '/'
      # This is a UNC path pointing to a share, so don't add a trailing slash
      File.expand_path(value)
    else
      File.join(File.split(File.expand_path(value)))
    end
  end

  private

  # return :content property
  def content
    @parameters[:content]
  end

  # Make sure the file we wrote out is what we think it is.
  def fail_if_checksum_is_wrong(path, content_checksum)
    newsum = parameter(:checksum).sum_file(path)
    return if [:absent, nil, content_checksum].include?(newsum)

    self.fail _("File written to disk did not match checksum; discarding changes
        (%{content_checksum} vs %{newsum})") % { content_checksum: content_checksum, newsum: newsum }
  end

  def stat_needed
    @stat = :needs_stat
  end

  # There are some cases where all of the work does not get done on
  # file creation/modification, so we have to do some extra checking.
  def property_fix
    properties.each do |thing|
      next unless [:mode, :owner, :group].include?(thing.name)

      # Make sure we get a new stat object
      @stat = :needs_stat
      currentvalue = thing.retrieve
      thing.sync unless thing.safe_insync?(currentvalue)
    end
  end
end
