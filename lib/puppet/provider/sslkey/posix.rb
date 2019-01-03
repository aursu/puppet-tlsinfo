Puppet::Type.type(:sslkey).provide :posix do
  desc 'Uses POSIX functionality to manage key file.'

  confine :feature => :posix # rubocop:disable Style/HashSyntax

  def remove_file
    Puppet::FileSystem.unlink(@resource[:path])
  end
end
