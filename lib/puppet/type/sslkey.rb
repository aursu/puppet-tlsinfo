require 'puppet/util/symbolic_file_mode'
require 'puppet/util/checksums'

Puppet::Type.newtype(:sslkey) do
  def self.title_patterns
    # strip trailing slashes from path but allow the root directory, including
    # for example "/" or "C:/"
    [[%r{^(/|.+:/|.*[^/])/*\Z}m, [[:path]]]]
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

    def insync?(currentvalue)
      unless currentvalue == :absent || resource.replace?
        return true
      end

      super(currentvalue)
    end

    def retrieve
      return :present if @resource.stat
      :absent
    end

    def sync
      @resource.remove_existing(self.should)
      if self.should == :absent
        return :file_removed
      end

      super
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
      if value.start_with?('//') && ::File.basename(value) == '/'
        # This is a UNC path pointing to a share, so don't add a trailing slash
        ::File.expand_path(value)
      else
        ::File.join(::File.split(::File.expand_path(value)))
      end
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

    newvalues 'md5', 'md5lite', 'sha224', 'sha256', 'sha256lite', 'sha384', 'sha512', 'mtime', 'ctime', 'none'

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

    attr_reader :actual_content

    munge do |value|
      if value == :absent || (value.is_a?(String) && checksum?(value))
        value
      else
        @actual_content = value.is_a?(Puppet::Pops::Types::PBinaryType::Binary) ? value.binary_buffer : value
        resource.parameter(:checksum).sum(@actual_content)
      end
    end

    def length
      actual_content&.length || 0
    end

    def content
      self.should
    end

    def insync?(current)
      # in sync if ensure => absent
      return true unless resource.should_be_file?

      # not in sync if ensure => present but file not exist
      return false if current == :absent

      # in sync if parameter replace is false (we do not replace content)
      return true unless resource.replace?

      super(current)
    end

    def property_matches?(current, desired)
      # The inherited equality is always accepted, so use it if valid.
      return true if super(current, desired)

      checksum_type = resource.parameter(:checksum).value
      date_matches?(checksum_type, current, desired)
    end

    def retrieve
      return :absent unless (stat = resource.stat)
      begin
        resource.parameter(:checksum).sum_file(resource[:path])
      rescue => detail
        raise Puppet::Error, "Could not read #{stat.ftype} #{resource.title}: #{detail}", detail.backtrace
      end
    end

    def date_matches?(checksum_type, current, desired)
      time_types = [:mtime, :ctime]
      return false unless time_types.include?(checksum_type)
      return false unless current && desired

      begin
        if checksum?(current) || checksum?(desired)
          fail if !time_types.include?(sumtype(current).to_sym) || !time_types.include?(sumtype(desired).to_sym)
          current = sumdata(current)
          desired = sumdata(desired)
        end
        DateTime.parse(current) >= DateTime.parse(desired)
      rescue => detail
        self.fail Puppet::Error, "Resource with checksum_type #{checksum_type} didn't contain a date in #{current} or #{desired}", detail.backtrace
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

    private

    # the content is munged so if it's a checksum source_or_content is nil
    # unless the checksum indirectly comes from source
    def each_chunk_from
      if actual_content.is_a?(String)
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
        fail "Could not find user #{val}" unless provider.name2uid(val)
      end

      return true if @should.include?(current)

      unless Puppet.features.root?
        warnonce 'Cannot manage ownership unless running as root'
        return true
      end

      false
    end

    # We want to print names, not numbers
    def is_to_s(current) # rubocop:disable Naming/PredicateName
      super(provider.uid2name(current) || current)
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
        fail "Could not find group #{val}" unless provider.name2gid(val)
      end

      @should.include?(current)
    end

    # We want to print names, not numbers
    def is_to_s(currentvalue) # rubocop:disable Naming/PredicateName
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

  validate do
    [:none, :ctime, :mtime].each do |checksum_type|
      self.fail _("You cannot specify content when using checksum '%{checksum_type}'") % { checksum_type: checksum_type } if self[:checksum] == checksum_type && !self[:content].nil?
    end

    if @parameters[:content]&.actual_content
      # Now that we know the checksum, update content (in case it was created before checksum was known).
      @parameters[:content].value = @parameters[:checksum].sum(@parameters[:content].actual_content)
    end

    provider.validate if provider.respond_to?(:validate)
  end

  def initialize(hash)
    super

    # If they've specified a source, we get our 'should' values
    # from it.
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

  def should_be_file?
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
    c = property(:content)

    mode = should(:mode) # might be nil
    mode_int = mode ? symbolic_mode_to_int(mode, Puppet::Util::DEFAULT_POSIX_MODE) : nil

    if write_temporary_file?
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

        fail_if_checksum_is_wrong(file.path, content_checksum) if validate_checksum?
      end
    else
      umask = mode ? 000 : 022
      Puppet::Util.withumask(umask) { ::File.open(self[:path], 'wb', mode_int) { |f| c.write(f) if c } } # rubocop:disable Style/SafeNavigation
    end

    # make sure all of the modes are actually correct
    property_fix
  end

  private

  # Should we validate the checksum of the file we're writing?
  def validate_checksum?
    self[:checksum] !~ %r{time}
  end

  # Make sure the file we wrote out is what we think it is.
  def fail_if_checksum_is_wrong(path, content_checksum)
    newsum = parameter(:checksum).sum_file(path)
    return if [:absent, nil, content_checksum].include?(newsum)

    self.fail _("File written to disk did not match checksum; discarding changes
        (%{content_checksum} vs %{newsum})") % { content_checksum: content_checksum, newsum: newsum }
  end

  def write_temporary_file?
    (c = property(:content)) && c.length
  end

  # @return [String] The type of the current file, cast to a string.
  def read_current_type
    return stat.ftype.to_s if stat
    nil
  end

  def remove_existing(should)
    wanted_type = should.to_s
    current_type = (read_current_type == 'file') ? 'present' : nil

    return false if (current_type.nil? || current_type == wanted_type)

    remove_file
  end

  # @return [Boolean] if the file was removed (which is always true currently)
  # @api private
  def remove_file
    Puppet::FileSystem.unlink(self[:path])
    stat_needed
    true
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
