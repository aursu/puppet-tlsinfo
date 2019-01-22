
# tlsinfo

#### Table of Contents

1. [Description](#description)
2. [Setup - The basics of getting started with tlsinfo](#setup)
    * [Beginning with tlsinfo](#beginning-with-tlsinfo)
    * [sslkey](#sslkey)
    * [Sslcertificate](#sslcertificate)
3. [Usage - Configuration options and additional functionality](#usage)
4. [Limitations - OS compatibility, etc.](#limitations)
5. [Development - Guide for contributing to the module](#development)

## Description

tlsinfo module rpovide ability to manage x509 certificates and private keys on web node with proper validation checking (over dates, CA issuers, common names etc)

## Setup

### Beginning with tlsinfo

Module provides two custom types:

```puppet
sslkey { '/etc/pki/tls/private/www.domain.com.key':
  ensure   => present,
  password => 'SecureSecret',
  path     => '/etc/pki/tls/private/www.domain.com.key',
  replace  => true,
  content  => lookup('www_domain_com_private', String, 'first'),
}
```
and

```puppet
sslcertificate { 'www.domain.com':
  ensure => present,
  path   => '/etc/pki/tls/certs/www.domain.com.pem',
  pkey   => '/etc/pki/tls/private/www.domain.com.key',
  cacert => true,
}
```

### Sslkey

#### sslkey title

Must be full path to private key because `Sslcertificate[pkey]` has requirement to be absolute path.

#### sslkey::ensure

Default value is `present`

If defined as `absent` - private key file will be removed by `unlink()`

#### sslkey::passowrd

Encrypted private key password. Must be a `String` or `nil` (`undef`). Can not be empty string.

#### sslkey::path

Absolute path to Private key file. It is namevar parameter (set to `title` value if not specified). Required parameter.

#### sslkey::replace

Boolean. Default value is `true`. 

If `true` than `content` value will replace existing private key file. Otherwise - noop.

#### sslkey::content

String. Required parameter

Must not be empty. Should be valid RSA private key in DER or PEM encoding form. Key size must be greate or equal 2048 bits

### Sslcertificate

SSL certificate provided via `content` parameter will be checked over `pkey` private key.

#### sslcertificate title

By default it should be full path to certificate file (eg `/etc/pki/tls/certs/4f06f81d.pem`) but not neccesarry.

Could be any string.

`Sslcertificate` type applies title pattern to get name variable parameter `path`. Therefore `path` if not defined will be set to `title` value (trimming last hashes `/`) 

#### sslcertificate::ensure

Default value is `present`

If defined as `absent` - certificate file will be removed by `unlink()`

#### sslcertificate::subject_hash (readonly)

Represent certificate subject hash `openssl x509 -subject_hash`

#### sslcertificate::subject_hash_old (readonly)

Represent certificate subject old hash `openssl x509 -subject_hash_old`

#### sslcertificate::path

Absolute path to certificate file. It is namevar parameter (set to `title` value if not specified). Required parameter.

#### sslcertificate::pkey

Absolute path to Private key file. Required parameter.

Puppet catalog should consist `Sslkey` resource with `title` that match `pkey` parameter.

#### sslcertificate::cacert

Default value: `undef`

Possible values are:

* `true` (Intermediate CA should be defined in Puppet catalog as `Sslcertificate` resource),
* `false` (we don't care about Intermediate CA),
* String. Any of certificate path, `Sslcertificate` resource title, certificate subject hash (`openssl x509 -subject_hash`) or old hash (`openssl x509 -subject_hash_old`). Should be defined in Puppet catalog as `Sslcertificate` resource
* Array of strings (list of CA certificates)

#### sslcertificate::replace

Boolean. Default value is `true`. 

If `true` than `content` value will replace existing certificate file. Otherwise - noop.

#### sslcertificate::chain

Boolean. Default is `true`

If `true` than Intermediate CA certificate will be placed into PEM file.

#### sslcertificate::strict

Boolean. Default is `true`

If `true` and `cacert` specified than cert chain will be checked over root certificate bundle (catalog compilation will fail if CA certificate is not valid)

#### sslcertificate::identity

Certificate identities. Could be String or list of strings

Each identity will be checked over Common Name or Alternative Names (DNS). If any of them missed - resource compilation will fail.

#### sslcertificate::content

Certificate PEM data. Required parameter. Can not be empty

It should be valid x509 certificate with valid term of validity

## Usage

It is required to include tlsinfo module into current scope to make parmeters `tlsinfo::certbase` and `tlsinfo::keybase` available

```puppet
include tlsinfo
```

Example:

```puppet
  tlsinfo::certificate { 'LetsEncryptAuthorityX3':
    cert => file('profile/certs/LetsEncryptAuthorityX3.crt'),
  }

  $server_name = 'registry.domain.com'
  tlsinfo::certpair { $server_name:
    identity => true,
  }

  # get certificate data from Hiera
  $certdata = tlsinfo::lookup($server_name)

  $ssl_cert_path = tlsinfo::certpath($certdata)
  $ssl_key_path = tlsinfo::keypath($certdata)
  
  class { 'profile::registry::nginx':
    server_name      => $server_name,
    ...
    ...
    ssl              => true,
    ssl_cert         => $ssl_cert_path,
    ssl_key          => $ssl_key_path,
    require          => Tlsinfo::Certpair[$server_name],
  }
```

In this example defined type `Tlsinfo::Certificate` will create certificate `/etc/pki/tls/certs/4f06f81d.pem` (`4f06f81d` is a certificate subject hash). 

`Tlsinfo::Certpair` will look for `registry_domain_com_certificate` and `registry_domain_com_private` keys through Hiera and create certpair `/etc/pki/tls/certs/registry.domain.com.pem` and `/etc/pki/tls/private/registry.domain.com.key`. It will check certificate-key validity before. Also certificate file `/etc/pki/tls/certs/registry.domain.com.pem` will consists Intermediate CA certificate on the bottom if such Intermediate CA certificate exists in Puppet catalog (defined via Tlsinfo::Certificate)

Path to certificate could be got via function `tlsinfo::certpath` and path to private key - via `tlsinfo::keypath`

## Reference

## Limitations

Module uses Ruby library 'openssl'

For unknown reasons this module has unpredicted behavior like:

1) returns old hash instead of new (for certificate Subject and Issuer fields)
2) returns negative (signed) values for Subject and Issuer hashes (eg `-ece330c` instead of `f131ccf4`)

Therefore it is better to use module functions for default path calculation (`tlsinfo::certpath` and `tlsinfo::keypath`)

## Development

## Release Notes/Contributors/Etc. **Optional**
