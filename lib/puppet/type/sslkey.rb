$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', '..'))
require 'puppet_x/tlsinfo/x509_tools'
require 'puppet/util/checksums'

Puppet::Type.newtype(:sslkey) do
  def self.title_patterns
    # strip trailing slashes from path but allow the root directory, including
    # for example "/" or "C:/"
    [[%r{^(/|.+:/|.*[^/])/*\Z}m, [[:path]]]]
  end

  # password must be a property defined before content property
  newproperty(:password) do
    desc 'Encrypted private key password'

    validate do |value|
      fail ArgumentError, _('Passwords must be a string or :undef') unless value.is_a?(String) || value.nil?
    end

    munge do |value|
      return nil if value.empty?
      value
    end

    # password is always in sync (we do not handle it as real property)
    def insync?(current) # rubocop:disable Lint/UnusedMethodArgument
      true
    end

    # we do not show desired value as it is sensitive data
    def should_to_s(value) # rubocop:disable Lint/UnusedMethodArgument
      super('[redacted]')
    end
  end

  ensurable do
    newvalue(:absent) do
      provider.remove_file
    end

    newvalue(:present) do
      content_sync
    end

    defaultto :present

    def retrieve
      return :present if (stat = resource.stat) && stat.ftype.to_s == 'file'
      :absent
    end

    def content_sync
      property = @resource.property(:content)
      current = property.retrieve
      # set provider to sync configuration
      property.sync unless property.safe_insync?(current)
    end
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

  newparam(:replace, boolean: true, parent: Puppet::Parameter::Boolean) do
    desc "Whether to replace a private key file that already exists on the local
      system but whose content doesn't match what the `content` attribute
      specifies. Setting this to false allows sslkey resources to initialize private
      key file without overwriting future changes.  Note that this only affects
      content; Puppet will still manage ownership and permissions. Defaults to
      `true`."
    defaultto :true
  end

  newproperty(:content) do
    include Puppet::Util::Checksums

    attr_reader :actual_content, :keyobj

    validate do |value|
      fail Puppet::Error, 'Private key must be a string' unless value.is_a?(String)
      fail Puppet::Error, 'Private must not be empty' if value.empty?

      key = Puppet_X::TlsInfo.read_rsa_key(value, @resource[:password])
      fail Puppet::Error, _('Can not read private key content') if key.nil?
      fail Puppet::Error, _('Provided key is not a private key') unless key.private?
      if (size = Puppet_X::TlsInfo.rsa_key_size(key)) < 2048
        fail Puppet::Error, _("Provided key is too weak (key size is #{size}")
      end
    end

    munge do |value|
      @keyobj = Puppet_X::TlsInfo.read_rsa_key(value, @resource[:password])
      @actual_content = Puppet_X::TlsInfo.rsa_to_pem(keyobj, @resource[:password])
      '{sha256}' + sha256(modulus)
    end

    def retrieve
      # Private key file must be not empty.
      return nil unless (stat = resource.stat)
      return nil if stat.zero?
      begin
        raw = File.read(resource[:path])
        key = Puppet_X::TlsInfo.read_rsa_key(raw, @resource[:password])
        return nil if key.nil?
        '{sha256}' + sha256(Puppet_X::TlsInfo.rsa_key_modulus(key))
      rescue => detail
        raise Puppet::Error, "Could not read #{stat.ftype} #{resource.title}: #{detail}", detail.backtrace
      end
    end

    def insync?(is)
      return true unless resource.should_be_present?
      return false if is.nil?
      return true unless resource.replace?
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
      checksum = sha256_stream do |sum|
        sum << actual_content
        file.print actual_content
      end
      "{sha256}#{checksum}"
    end

    def modulus
      return nil if keyobj.nil?
      Puppet_X::TlsInfo.rsa_key_modulus(keyobj)
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

  validate do
    if should_be_present?
      fail Puppet::Error, _(':content property is mandatory for Sslkey resource') unless keyobj
    end
    provider.validate if provider.respond_to?(:validate)
  end

  def initialize(hash)
    super

    # If they've specified a source, we get our 'should' values
    # from it.
    self[:ensure] = :present if self[:ensure].nil? && self[:content]
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
  end

  def content
    @parameters[:content]
  end

  def keyobj
    return content.keyobj if content
    nil
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

  def should_be_present?
    self[:ensure] == :present
  end
end
