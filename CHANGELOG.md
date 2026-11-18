# Changelog

All notable changes to this project will be documented in this file.

## Release 0.3.6

**Features**

**Bugfixes**

* Updated dependencies' versions

**Known Issues**

## Release 0.3.7

**Features**

**Bugfixes**

* Updated plan to match latest puppet module changes

**Known Issues**

## Release 0.4.0

**Features**

* PDK upgrade to 3.0.0

**Bugfixes**

* Updated dependencies

**Known Issues**

## Release 0.5.0

**Features**

* Use bsys for certbase and keybase

**Bugfixes**

**Known Issues**

## Release 0.6.0

**Features**

* Added some types to operate CFSSL configuration

**Bugfixes**

**Known Issues**

## Release 0.6.1

**Features**

**Bugfixes**

* Bugfix: in `Tlsinfo::Signing` fix for `default` keyword

**Known Issues**

## Release 0.7.0

**Features**

* Added Bolt plan `tlsinfo::cfssl`

**Bugfixes**

**Known Issues**

## Release 0.8.0

**Features**

* Added `tlsinfo::cfssl::ca_config` to manage CA configuration for CFSSL

**Bugfixes**

**Known Issues**

## Release 0.9.0

**Features**

* Added `tlsinfo::cfssl::crt_req` to manage CSR requests

**Bugfixes**

**Known Issues**

## Release 0.10.0

**Features**

* Added `tlsinfo::cfssl::gencert` to generate certificates

**Bugfixes**

**Known Issues**

## Release 0.10.1

**Features**

* Added `hostname` parameter into `tlsinfo::cfssl::gencert` resource

**Bugfixes**

**Known Issues**

## Release 0.11.0

**Features**

**Bugfixes**

* Fixed support for stdlib < 9.0.0

**Known Issues**

## Release 0.12.3

**Features**

* Added support for ECDSA/ECDH private keys

**Bugfixes**

* Fixed compatibility with Ruby 2.x

**Known Issues**

## Release 0.13.0

**Features**

* New `sslkey` property `mode`, default `0600`. A new key file is created
  with that mode, and an existing key file with another mode is corrected.

**Bugfixes**

* Private keys were written world-readable (`0644`, hardcoded). Where
  `/etc/ssl/private` is `0710 root:ssl-cert` (Debian/Ubuntu), every member of
  `ssl-cert` - typically `postgres` - could read them. Existing keys become
  `0600` on the next agent run.
* The `replace` documentation promised that ownership and permissions stay
  managed; permissions now are (through `mode`), ownership is not managed.

**Known Issues**
