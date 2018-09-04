Puppet::Type.type(:sslkey).provide :posix do
  desc 'Uses POSIX functionality to manage file ownership and permissions.'

  confine :feature => :posix # rubocop:disable Style/HashSyntax

  include Puppet::Util::POSIX
  include Puppet::Util::Warnings

  require 'etc'

  attr_accessor :password

  def uid2name(id)
    return id.to_s if id.is_a?(Symbol) || id.is_a?(String)
    return nil if id > Puppet[:maximum_uid].to_i

    begin
      user = Etc.getpwuid(id)
    rescue TypeError, ArgumentError
      return nil
    end

    return nil if user.uid == ''
    user.name
  end

  # Determine if the user is valid, and if so, return the UID
  def name2uid(value)
    Integer(value)
  rescue
    uid(value) || false
  end

  def gid2name(id)
    return id.to_s if id.is_a?(Symbol) || id.is_a?(String)
    return nil if id > Puppet[:maximum_uid].to_i

    begin
      group = Etc.getgrgid(id)
    rescue TypeError, ArgumentError
      return nil
    end

    return nil if group.gid == ''
    group.name
  end

  def name2gid(value)
    Integer(value)
  rescue
    gid(value) || false
  end

  def owner
    unless (stat = resource.stat)
      return :absent
    end

    currentvalue = stat.uid

    # On OS X, files that are owned by -2 get returned as really
    # large UIDs instead of negative ones.  This isn't a Ruby bug,
    # it's an OS X bug, since it shows up in perl, too.
    if currentvalue > Puppet[:maximum_uid].to_i
      warning _('Apparently using negative UID (%{currentvalue}) on a platform that does not consistently handle them') % { currentvalue: currentvalue }
      currentvalue = :silly
    end

    currentvalue
  end

  def owner=(should)
    File.send(:chown, should, nil, resource[:path])
  rescue => detail
    raise Puppet::Error, _("Failed to set owner to '%{should}': %{detail}") % { should: should, detail: detail }, detail.backtrace
  end

  def group
    return :absent unless (stat = resource.stat)

    currentvalue = stat.gid

    # On OS X, files that are owned by -2 get returned as really
    # large GIDs instead of negative ones.  This isn't a Ruby bug,
    # it's an OS X bug, since it shows up in perl, too.
    if currentvalue > Puppet[:maximum_uid].to_i
      warning _('Apparently using negative GID (%{currentvalue}) on a platform that does not consistently handle them') % { currentvalue: currentvalue }
      currentvalue = :silly
    end

    currentvalue
  end

  def group=(should)
    File.send(:chown, nil, should, resource[:path])
  rescue => detail
    raise Puppet::Error, _("Failed to set group to '%{should}': %{detail}") % { should: should, detail: detail }, detail.backtrace
  end

  def mode
    if (stat = resource.stat)
      (stat.mode & 0o7777).to_s(8).rjust(4, '0')
    else
      :absent
    end
  end

  def mode=(value)
    File.chmod(value.to_i(8), resource[:path])
  rescue => detail
    error = Puppet::Error.new(_('failed to set mode %{mode} on %{path}: %{message}') % { mode: mode, path: resource[:path], message: detail.message })
    error.set_backtrace detail.backtrace
    raise error
  end
end
