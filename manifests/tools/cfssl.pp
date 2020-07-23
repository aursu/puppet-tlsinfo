# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include tlsinfo::tools::cfssl
class tlsinfo::tools::cfssl (
    Optional[Pattern[/^1\.[4-9][1-9]?\./]]
            $version          = $tlsinfo::cfssl_version,
    String  $download_source  = $tlsinfo::params::cfssl_download_source,
    Stdlib::Absolutepath
            $tmpdir           = $tlsinfo::params::download_tmpdir,
) inherits tlsinfo::params
{
  $cfssl_tools      = $tlsinfo::params::cfssl_tools
  # we allow user to not care about cfssl version and keep it default
  # (specified in params)
  # $download_version - either user specified or default
  if $version {
    $download_version = $version
  }
  else {
    $download_version = $tlsinfo::params::cfssl_version
  }

  # in URL base folder resides CFSSL binaries and checksum file
  # eg https://github.com/cloudflare/cfssl/releases/download/v1.4.1
  $download_url_base = "${download_source}/v${download_version}"

  # checksum file name
  # eg cfssl_1.4.1_checksums.txt
  $checksum_name = "cfssl_${download_version}_checksums.txt"
  $checksum_download_path = "${tmpdir}/${checksum_name}"

  # download checksm file into temporary directory
  exec { 'cfssl-checksum':
    command => "curl -L ${download_url_base}/${checksum_name} -o ${checksum_name}",
    creates => $checksum_download_path,
    path    => '/usr/bin:/bin',
    cwd     => $tmpdir,
  }

  $cfssl_tools.each |$bin| {
    # download binary if checksum not match
    # cfssl_1.4.1_linux_amd64
    $download_name = "${bin}_${download_version}_linux_amd64"
    $binary_path = "/usr/local/bin/${bin}"

    exec { "${bin}-download":
      command => "curl -L ${download_url_base}/${download_name} -o ${download_name}",
      unless  => "grep -w ${download_name} ${checksum_name} | sha256sum -c",
      require => Exec['cfssl-checksum'],
      path    => '/usr/bin:/bin',
      cwd     => $tmpdir,
    }

    # install binary into specified location (by default is
    # /usr/local/bin)
    file { $bin:
      ensure    => file,
      path      => $binary_path,
      source    => "file://${tmpdir}/${download_name}",
      mode      => '0755',
      owner     => 'root',
      group     => 'root',
      subscribe => Exec["${bin}-download"],
    }
  }
}
