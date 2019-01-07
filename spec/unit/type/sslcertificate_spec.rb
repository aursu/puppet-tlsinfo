#! /usr/bin/env ruby
require 'spec_helper'
require 'openssl'

describe Puppet::Type.type(:sslcertificate) do
  let(:catalog) { Puppet::Resource::Catalog.new }
  let(:www_domain_com_private) do
    <<-RSAKEYDATA
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxWcWaD9E6OeNoGLKUeXrs1pQGCJ11CLfzm2Pip9iXz7D67Hj
RiRjDzGENYgMV+2wP5MyvkRhk/DAjJyPN3QnLF8rI7/xe6v+jA+nZatUzbyUe396
jA/UCMZKTl/iLXtMyuWf1kAcJlhj8aETel3w5QbuCfW8jgycXsBOPTuzJjTtOJcd
AuDL56ruwd8GwrRyn/jQFCsWAs4n6pyf5/GXNKN8X356uaAGda74r2BuTTGiwPxo
Nw3K1c5NlbsDtDCerMw8WqW/3N4n1/BrApvgQcxhEnxikHeSxbLUKWaDwbw5NmPH
b9YY7Ao0gqWwjDI+8l0Y60Ri0TzbYNWQHeTOnQIDAQABAoIBAQCKU6ab/lnnavsP
fKqRoS/9Sjf98Yfn01hJavS/CtkALRdVPh4otK7FoskmSeN8ag6rPha8xWYrKPWE
kuC41yfsK/Qq5QHuy6NfukhvMhQG5zKVJ8tUAnNugqTnLsFrZY92Tlom5F3VcPL4
Cwt/H/0CQEzlpdEvKR8aNl+dAQyUpB1Z2yeNRZ0vSvGIHqkIeTsWzfV88eDUZ7Zl
6r1pMz88hvtLuJeNYalU2BuQd13wLnin7gQlLWQGTLvk+OelToV4SSwN9qKi6gLY
5PCaBgf8TxHgG2eU8i4UNilmQBVUWN5r/KeujOLAOEnvYyOK9PW/yQnNacic4jzJ
lO/aUD9xAoGBAPfOwaQwMRcM35JoLNUmaH2OxnLGoisvnA+awzXMBomucwTXo+QL
hYHkMNRB+LCSZu5Sm4Siq9Y3F832lLU5ywYwhgBernBecMHTgtwoKhjDh1SlvPvQ
ln6cBG5Jof5tsv1UQbd21kWJ7cwdeiJyfF/duqkMakMxZQoWkX7huDH/AoGBAMvt
vorFMJLSxDiLpFF03JrfbCLd3xaJvnc5Y56TbiN9Gg8HTuXCUiKwkVadxmGqOOrv
iMHCLG8xNGEQdk6qnV55NHBYFc95XLXCj8yI16spf8S+BANd3vdGIbwp91byVmnE
alTD+OJFnq5pbEqSP8Gqb/I1kfT0OVahpBh2tIdjAoGBAOvmk0ht6A19X8fMDAHN
UmNUa24P0YkzBWmFdpfb5c1jmHLfpVEN9sY0KJenRcsxU3NEiG+3O8XtJGgZeG8c
2TzHLIllmMG35bdeVpCmW4y/djEKpeFCLEHS3BTxW5kNbPrkHrs8EbaZGxrYZNAu
FGBef7c17mKQvxLfcRpMXkCZAoGBAI17GCL2w8hZacFBQHMy/IqGT2OxQsFEN1xH
+JFf/52ngZjDnT1SH+HpViwdsjC4BF0aamri6CkMniZpYWsae6u7s2Ht+tPCg0um
/FUO63HYjMhWfDpJuhMcGPOOugccgk9G8e51OArj+j9O7M6fwJQAR0JnYCft+Ine
Axbl5EG5AoGAE58RfiCgyJBoeNhqzBdRf4XQLfdP/Hg4zLQN42m7XftCDPVekjzS
7E9jhP+4gnir5elreAbuajASTWI7srLPPShSdrs+XW7kFgmzFIJBb2R3atu3izzf
ITb/vUggVX9R9toJZHlBg2sZSMyGISJTHOT4d4zPFoAf3U+YGGa9lZI=
-----END RSA PRIVATE KEY-----
RSAKEYDATA
  end
  let(:keypath) { '/etc/pki/tls/private/www.domain.com.key' }
  let(:wildcard_domain_com_private) do
    <<-RSAKEYDATA
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwk2hrEE0Cd7Lqb7RwZXh5D28eU1QVm+l3G5ZwM9UwxOjkWe6
LNkKarbcV5OC4nJ0TymNRAjNxjisTN0Y/SCYULZrZzFpLBq9JFiB8XRtcLuDoXzQ
nSmlr9hBYu0a5dcyYtSHaMRX+70tluzesm2luFEGMFd5EiddohVNwiWBhJgEeOzA
7QAJZuB+w/+GJjEJw/smTMoZXQiYA+oCkjy8Hqna6yrKdsdb34l9Sv3qG6QPRZIp
PmI1EZPnMqSL7FOdUA3ltzK0EBguJxqwzUGnX8qdSbcOlD02+Id1Yo8JpDOhbZIn
GFlSAl93N3eiVTq2IFTOxcCxdM/mxISWgzM/KQIDAQABAoIBACwQCs/TYYezfKAb
49lwse9eiLVBcSyI2SYp6DSvT9uFQpyg1zmAZrpYiZNaol3T8shY9e4tyOxgwcIU
iawtjh0PoT+flugnkCkD4UPuUTs1at5ePbjGTwqXkgxrFKR2rrh21dZOYF14QzRs
tvvjnac0yKCB1bTmNHejOSUD+GEm6sx60HVaoEDU7dLE6+YNUyHuCBOb8LaqvWoU
ZRI54v9vhfoNYzSDjrV5YUswMmbNmb6AXQbGoFzjXVN2MehhqmaLxQgLSi1Kkdm+
502PM3RjDrpBB/6YGULum9Bs4gy/BK0rGpUnIm0I+6ABJjfyni6Th2MyNWvNk0sO
IQ1PwZkCgYEA7kPS5H+rfxG3tiy5R1rK/kPU+HrxrV1QD2twNG5JY/7DQFHvu+f2
8uey6lGI+V1HBt9kXWeNc0Wz3g0KuI3Z7kAq4gmo7WwbvuPs++vPWbJikTx5jXh/
8KqlX+DpT38DlVOWWRkQVd9aSTdYFwQOCETjH7mNsKznDGeXNOrW2Q8CgYEA0MQc
XBjOFnOGKr61Bp+x0KwfQR44q548aGepvX2BOU2kTBf79O22I0q5WNjXVmOfEIcT
ubuws9FkUjOhYZHh6rnuLvwuwSco7LmSNuNVJBpdJD9nbRCTa4b4MDAFzP72xDNX
wbp+JiD2oVuBp53HDG/lMjjI64ZeNMi7bS4aNEcCgYBxmdbgaVrMQBdWfaZtNgXZ
C2BshLncDcSRRYl/BiJp0dsoPKjP775XfE9a1zs2odmuli5VNn1Du7URpyg4bDG/
HcsUcMShRs1Hy4Z/aqQ3QQ0r8CiIYi6mAcbNmv/Cjm2X8f2aR4/5UX/Lrt6KQr2q
BaZAxwiedyHGUVHPwjRj0wKBgFTlW08Me0pgAlCBqyYdbPcZ97/IZW1M9O3UMg+v
6Qv/ie+z1S8+N9JUQdlinPcxne7fr2LZc7s8TJqtClSeOYv1vml2/iBoJ1lVAaO2
gNokqnniGtIcaobQpT8bWFCL4pfY9Tf/+erRftoRV0FthROGsWLh+rrksoyukKGO
nPNjAoGBAOH5u3M4sS2UlPkqwVtQ3XPPTXVT9m0xp6cfyNsPQCpwAOHqpUgaCrsx
mOI9qJG1PiwVgbOhW3Q3mYHEh/7NDywAlieE9kPO03HExCfDIwhEOPQeZ7uXxOKR
UJB6MzKFZqSp3kQGh0PaO4YaEDPuGy5+HjXB9N0pwcKD6Ep/PF5l
-----END RSA PRIVATE KEY-----
RSAKEYDATA
  end
  let(:keypath_wildcard) { '/etc/pki/tls/private/wildcard.domain.com.key' }
  let(:www_domain_com_certificate) do
    <<-CERTIFICATE
-----BEGIN CERTIFICATE-----
MIIE6DCCA9CgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCREUx
DzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtmdXJ0MRswGQYDVQQKDBJD
b21wYW55IENBIExpbWl0ZWQxNzA1BgNVBAMMLkNvbXBhbnkgUlNBIERvbWFpbiBW
YWxpZGF0aW9uIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTkwMTA2MjMyMjI2WhcNMjAw
MTA2MjMyMjI2WjBSMSEwHwYDVQQLDBhEb21haW4gQ29udHJvbCBWYWxpZGF0ZWQx
FDASBgNVBAsMC0ludGVybmFsU1NMMRcwFQYDVQQDDA53d3cuZG9tYWluLmNvbTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMVnFmg/ROjnjaBiylHl67Na
UBgiddQi385tj4qfYl8+w+ux40YkYw8xhDWIDFftsD+TMr5EYZPwwIycjzd0Jyxf
KyO/8Xur/owPp2WrVM28lHt/eowP1AjGSk5f4i17TMrln9ZAHCZYY/GhE3pd8OUG
7gn1vI4MnF7ATj07syY07TiXHQLgy+eq7sHfBsK0cp/40BQrFgLOJ+qcn+fxlzSj
fF9+ermgBnWu+K9gbk0xosD8aDcNytXOTZW7A7QwnqzMPFqlv9zeJ9fwawKb4EHM
YRJ8YpB3ksWy1Clmg8G8OTZjx2/WGOwKNIKlsIwyPvJdGOtEYtE822DVkB3kzp0C
AwEAAaOCAZAwggGMMB8GA1UdIwQYMBaAFOLqvc4bAIg+s4RRrnUElIsLUwhOMB0G
A1UdDgQWBBQxhbHtBDD0tQDUB0RJ3xTO2utRATAOBgNVHQ8BAf8EBAMCBaAwDAYD
VR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEwYDVR0g
BAwwCjAIBgZngQwBAgEwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5jb21w
YW55Y2EuY29tL0NvbXBhbnlSU0FEb21haW5WYWxpZGF0aW9uU2VjdXJlU2VydmVy
Q0EuY3JsMIGIBggrBgEFBQcBAQR8MHowUQYIKwYBBQUHMAKGRWh0dHA6Ly9jcnQu
Y29tcGFueWNhLmNvbS9Db21wYW55UlNBRG9tYWluVmFsaWRhdGlvblNlY3VyZVNl
cnZlckNBLmNydDAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AuY29tcGFueWNhLmNv
bTAVBgNVHREEDjAMggpkb21haW4uY29tMA0GCSqGSIb3DQEBCwUAA4IBAQBXpjtc
0n7ff+aWhCxu65g5OtfvhwZ9QIJ0qW/nmoX3mH7vBIVm8rJyTGx0foUs1ATUN5b2
SOJOyvJBDwO5ysc5MK6ixhZn/UNxsDgYD/L8q6HGUNViuUBAFH+zWlW6jR3wJY86
EkaXS9eXoem4Nb8xHiJmWVORAzywk5VgCE9gkd9IACxCxAOJZtWmsMUFnjSAQL+3
eFRq/sYrbs2/4n7WkMHJt06JZmHdBx5kT8dESiod0Eoayms9rfQ2uIQPdvl+Psiw
Psb6Qs3Mw/ruzPoK/C4WFEjMPpy2Qlh5HEemqZnywxiJ++J/9qMMaoe4r3HdAOQt
0ulH8BPP1c9hKGKK
-----END CERTIFICATE-----
CERTIFICATE
  end
  let(:certpath) { '/etc/pki/tls/certs/www.domain.com.pem' }
  let(:www_domain_com_certificate_modulus) do
    'C56716683F44E8E78DA062CA51E5EBB35A50182275D422DFCE6D8F8A9F625F3EC3EBB1E3'\
    '4624630F318435880C57EDB03F9332BE446193F0C08C9C8F3774272C5F2B23BFF17BABFE'\
    '8C0FA765AB54CDBC947B7F7A8C0FD408C64A4E5FE22D7B4CCAE59FD6401C265863F1A113'\
    '7A5DF0E506EE09F5BC8E0C9C5EC04E3D3BB32634ED38971D02E0CBE7AAEEC1DF06C2B472'\
    '9FF8D0142B1602CE27EA9C9FE7F19734A37C5F7E7AB9A00675AEF8AF606E4D31A2C0FC68'\
    '370DCAD5CE4D95BB03B4309EACCC3C5AA5BFDCDE27D7F06B029BE041CC61127C62907792'\
    'C5B2D4296683C1BC393663C76FD618EC0A3482A5B08C323EF25D18EB4462D13CDB60D590'\
    '1DE4CE9D'
  end
  let(:www_domain_com_intermediate) do
    <<-CERTIFICATE
-----BEGIN CERTIFICATE-----
MIIE8TCCA9mgAwIBAgIBATANBgkqhkiG9w0BAQsFADB9MQswCQYDVQQGEwJERTEP
MA0GA1UECAwGSGVzc2VuMRIwEAYDVQQHDAlGcmFua2Z1cnQxGzAZBgNVBAoMEkNv
bXBhbnkgQ0EgTGltaXRlZDEsMCoGA1UEAwwjQ29tcGFueSBSU0EgQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkwHhcNMTkwMTA2MjE0MzUxWhcNMjAwMTA2MjE0MzUxWjCB
iDELMAkGA1UEBhMCREUxDzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtm
dXJ0MRswGQYDVQQKDBJDb21wYW55IENBIExpbWl0ZWQxNzA1BgNVBAMMLkNvbXBh
bnkgUlNBIERvbWFpbiBWYWxpZGF0aW9uIFNlY3VyZSBTZXJ2ZXIgQ0EwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1KboZmOrID0NVOBz62DqhAWFM9nLQ
GGRrdz/dSK6hZWpHvaamxMIdlGKFVxv9NNRhhs6iCeSPd17ENgcZK1jEm4Ne7VZm
2QHLiMd3IXXqway88eMrIn9TNRV7SWYgusgnLGy3D4h2z3jK6SScSueN4uoOzV6q
vcHKGInFgTCSOeFaH+dH1iKs0P6JLyRNUtKQf2ZUw770RvQZlS3gGVSGiBU9tqgr
LWu9+QtVaN0FYNjwC7rUXKGOfSz4kdce3hOxfLDRWJOlUNRsPNW27Iws7cV/uVLL
sbGrbj1RU6n1kyt/sXWNjEL58r6DfQK8Qh3FKv8EVNy9s/DmQ3E+W8DPAgMBAAGj
ggFuMIIBajAfBgNVHSMEGDAWgBRD22vglhqyVabtkH+x1FzbBCzsETAdBgNVHQ4E
FgQU4uq9zhsAiD6zhFGudQSUiwtTCE4wDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB
/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBsGA1Ud
IAQUMBIwBgYEVR0gADAIBgZngQwBAgEwTgYDVR0fBEcwRTBDoEGgP4Y9aHR0cDov
L2NybC5jb21wYW55Y2EuY29tL0NvbXBhbnlSU0FDZXJ0aWZpY2F0aW9uQXV0aG9y
aXR5LmNybDB4BggrBgEFBQcBAQRsMGowQQYIKwYBBQUHMAKGNWh0dHA6Ly9jcnQu
Y29tcGFueWNhLmNvbS9Db21wYW55UlNBRG9tYWluRG90Q29tQ0EuY3J0MCUGCCsG
AQUFBzABhhlodHRwOi8vb2NzcC5jb21wYW55Y2EuY29tMA0GCSqGSIb3DQEBCwUA
A4IBAQCTNcUhijCxTLiKO4EjWecC95NVAHYYjWMd9XJ6wi++D91zGoc/nr9PdOkR
HKL8NWVGm4u7DcKoXMwS2mXn/Oi9/5QzxmlrRpRxkRmJnDikh6+EfMWdg98qOA4X
CkENKu/DJL/jerP/+Ply0fNCN1A7RKRuVs6p7BAH55iayotmZ7aBTdnpeW33N8wR
bNLVYUPvPPcxSOvL9klwvuN/TX90NAMsBYF/B9Z78fChdeXnao4GA32WnPH3K5lF
YbsA4uENjiuzhXm3tRowzTRYun6LTOg0SKPTLKsnIa8nWM8zui7SHrT853i2YH8E
QhUEQsjnS6lCImFQVI0oxGx3En22
-----END CERTIFICATE-----
CERTIFICATE
  end
  let(:capath) { '/etc/pki/tls/certs/f1453246.pem' }
  let(:www_domain_com_intermediate_parent) do
    <<-CERTIFICATE
-----BEGIN CERTIFICATE-----
MIIEZjCCA06gAwIBAgIBATANBgkqhkiG9w0BAQsFADB7MQswCQYDVQQGEwJERTEY
MBYGA1UECgwPRG9tYWluRG90Q29tIEFCMSowKAYDVQQLDCFEb21haW5Eb3RDb20g
RXh0ZXJuYWwgVFRQIE5ldHdvcmsxJjAkBgNVBAMMHURvbWFpbkRvdENvbSBFeHRl
cm5hbCBDQSBSb290MB4XDTE5MDEwNjIwNTgzN1oXDTIwMDEwNjIwNTgzN1owfTEL
MAkGA1UEBhMCREUxDzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtmdXJ0
MRswGQYDVQQKDBJDb21wYW55IENBIExpbWl0ZWQxLDAqBgNVBAMMI0NvbXBhbnkg
UlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAoA/moPZrHp4rdJFxFTezDWa4xR9p+VAW2PYKGAcWsNy6UA7h
9Ua4w3o+YznWOKsy+LqdE37canWq+4L6F6Q+oNtygxqhccBttzTBh/P6nOOCffOI
mRZPFuLfHhlowQDLyCmbkbzIg4rSWjSzfDKOfeRQsfHf2dK876+5DAP2M3xSV1U9
7oXN+kaWCFqAokhYXLu5QWGxCK+QZeWgtkhi6b05UbhgJ+77JhIMWOwAVnTeo0GI
bNaMVI+Jpzg81riM8nsGsjSmJ0CYEaOXb3w2lgoIJDPh/e0n5XzZglNMeiQmzFLp
exaf0WxRQa8I8OJBWv4HH3Tkpbgmo7bP5r6cawIDAQABo4HyMIHvMB8GA1UdIwQY
MBaAFP9OEBEe8AnZPk4x3PMOBndYdQ3eMB0GA1UdDgQWBBRD22vglhqyVabtkH+x
1FzbBCzsETAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zARBgNVHSAE
CjAIMAYGBFUdIAAwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybC5kb21haW4u
Y29tL0RvbWFpbkRvdENvbUV4dGVybmFsQ0FSb290LmNybDAyBggrBgEFBQcBAQQm
MCQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLmRvbWFpbi5jb20wDQYJKoZIhvcN
AQELBQADggEBAMCAcCb+7RzHJvNgAgH8P5KSWWeFJPVOXPllKoNFjqK6QrmijJnH
UQkoD4G8wOSey7YkfSEJe2uc7uGWxqSjvOqhpcePSUSh5kzodFDXaQicCn+2xWYS
xZpfQgXygextLMWfFu1w3ImqYtvRZjwTv+03hF6+7zUxBKLQCbm90NRDFoINHXT0
ZMf2eDCwH/FUsZs1oaerTzNCSVipki89TIiohj/3T2cM1vOtJqMCN2+ZSm2P2+gH
uKA/w3c23yMmYdjjd7yJXtrf6TZJ63d737gHKrDgercDrMyoma2OB9YiMKYziC/j
2BO356eWcUXh6yLJYIWm4wBbUkPu1ji7z/I=
-----END CERTIFICATE-----
CERTIFICATE
  end
  let(:capath_parent) { '/etc/pki/tls/certs/a4144c98.pem' }

  it 'check with empty parameters list' do
    params = {
      title: 'namevar',
      catalog: catalog
    }
    expect { described_class.new(params) }.to raise_error Puppet::Error, %r{File paths must be fully qualified, not 'namevar'}
  end

  it 'check with empty parameters and proper title' do
    params = {
      title: certpath,
      catalog: catalog
    }
    expect { described_class.new(params) }.to raise_error Puppet::Error, %r{:content property is mandatory for Sslcertificate resource}
  end

  it 'check with empty parameters and ensure: :absent' do
    params = {
      title: certpath,
      ensure: :absent,
      catalog: catalog
    }
    expect { described_class.new(params) }.not_to raise_error
  end

  context 'when only content specified' do
    let(:params) do
      {
        title: certpath,
        content: www_domain_com_certificate,
        catalog: catalog
      }
    end
    let(:cert) { described_class.new(params) }

    it 'not fail' do
      expect { described_class.new(params) }.not_to raise_error
    end

    it 'set subject hash' do
        expect(cert[:subject_hash]).to eq('c07dba14')
    end

    it 'set old subject hash' do
        expect(cert[:subject_hash_old]).to eq('ee3cd8bd')
    end
  end

  context 'when title_patterns match / at the end' do
    let(:cert) do
      described_class.new(
        title: "#{certpath}//",
        content: www_domain_com_certificate,
        catalog: catalog,
      )
    end

    it 'set path without slashes at the end' do
      expect(cert[:path]).to eq(certpath)
    end
  end

  context 'when pkey specified' do
    let(:params) do
      {
        title: certpath,
        content: www_domain_com_certificate,
        pkey: keypath,
        catalog: catalog,
      }
    end
    let(:cert) { described_class.new(params) }
    let(:key) do
        Puppet::Type.type(:sslkey).new(name: keypath, content: www_domain_com_private)
    end
    let(:key_wildcard) do
        Puppet::Type.type(:sslkey).new(name: keypath_wildcard, content: wildcard_domain_com_private)
    end

    it 'with relative path to key' do
      expect { described_class.new(params.merge(pkey: 'www.domain.com.key')) }.to raise_error \
        Puppet::Error, %r{Pkey parameter must be fully qualified path to private key, not 'www.domain.com.key'}
    end

    it 'with full path to key' do
      expect { described_class.new(params) }.to raise_error \
        Puppet::Error, %r{You must define resource Sslkey\[/etc/pki/tls/private/www.domain.com.key\]}
    end

    it 'with wrong key' do
      catalog.add_resource key_wildcard
      expect { described_class.new(params.merge(pkey: keypath_wildcard)) }.to raise_error \
        Puppet::Error, %r{Certificate public key does not match private key /etc/pki/tls/private/wildcard.domain.com.key}
    end

    context 'with correct key' do
      before(:each) { catalog.add_resource key }

      it 'not fail' do
        expect { described_class.new(params) }.not_to raise_error
      end

      it 'check pkey keyobj type' do
        expect(cert.parameters[:pkey].keyobj).to be_instance_of(OpenSSL::PKey::RSA)
      end

      it 'check pkey keyobj modulus' do
        expect(cert.parameters[:pkey].keyobj.params['n'].to_s(16)).to eq(www_domain_com_certificate_modulus)
      end
    end
  end

  context 'when cacert specified' do
    let(:params) do
      {
        title: certpath,
        content: www_domain_com_certificate,
        pkey: keypath,
        cacert: true,
        catalog: catalog,
      }
    end
    let(:cert) { described_class.new(params) }
    let(:key) do
      Puppet::Type.type(:sslkey).new(name: keypath, content: www_domain_com_private)
    end
    let(:cacert) do
      Puppet::Type.type(:sslcertificate).new(name: capath, content: www_domain_com_intermediate)
    end

    before(:each) { catalog.add_resource key }

    it 'fail if ca cert not in catalog' do
      expect { described_class.new(params) }.to raise_error \
        Puppet::Error, %r{You must define Sslcertificate resource with subject /C=DE/ST=Hessen/L=Frankfurt/O=Company CA Limited/CN=Company RSA Domain Validation Secure Server CA}
    end

    context 'with CA cert in catalog' do
      before(:each) { catalog.add_resource cacert }

      it 'not fail' do
        expect { described_class.new(params) }.not_to raise_error
      end

      it 'check cacert certobj with single CA cert' do
        certobj = cert.parameters[:cacert].certobj
        expect(certobj).to be_instance_of(Array)
        expect(certobj.count).to eq(1)
      end

      it 'check cacert certchain with single CA cert is empty' do
        certchain = cert.parameters[:cacert].certchain
        expect(certchain).to be_instance_of(Array)
        expect(certchain).to be_empty
      end
    end

    context 'when multipath CA' do
      let(:cacert_params) do
        {
          title: capath,
          content: www_domain_com_intermediate,
          cacert: true,
          catalog: catalog,
        }
      end
      let(:cacert_parent) do
        Puppet::Type.type(:sslcertificate).new(name: capath_parent, content: www_domain_com_intermediate_parent)
      end

      it 'fail if parent CA is not in catalog' do
        expect { described_class.new(cacert_params) }.to raise_error \
          Puppet::Error, %r{You must define Sslcertificate resource with subject /C=DE/ST=Hessen/L=Frankfurt/O=Company CA Limited/CN=Company RSA Certification Authority}
      end

      context 'when parent CA is in catalog' do
        before(:each) do
          catalog.add_resource cacert_parent
        end

        it 'not fail' do
          expect { described_class.new(cacert_params) }.not_to raise_error
        end

        it 'check certchain value' do
          cacert = described_class.new(cacert_params)
          content = cacert.certchain.map { |c| c.to_pem }.join

          expect(content).to eq([www_domain_com_intermediate, www_domain_com_intermediate_parent].join)
        end

        it 'check actual content value' do
          cacert = described_class.new(cacert_params.merge(chain: false))

          expect(cacert.parameters[:content].actual_content).to eq(www_domain_com_intermediate)
        end
      end

      context 'with both CA certs in catalog' do
        let(:params) do
          {
            title: certpath,
            content: www_domain_com_certificate,
            pkey: keypath,
            cacert: true,
            catalog: catalog,
          }
        end
        let(:cacert) { described_class.new(cacert_params) }

        before(:each) do
          catalog.add_resource cacert_parent
          catalog.add_resource cacert
        end

        def check_cacerts(chain, size)
          expect(chain).to be_instance_of(Array)
          expect(chain.count).to eq(size)
          chain.each do |c|
            basicconstraints, = c.extensions.select { |e| e.oid == 'basicConstraints' }.map { |e| e.to_h }
            is_ca = basicconstraints && basicconstraints['value'].include?('CA:TRUE')

            expect(is_ca).to eq(true)
          end
        end

        it 'check cacert certchain should consist all CA certificates' do
          cert = described_class.new(params)
          certchain = cert.parameters[:cacert].certchain

          check_cacerts(certchain, 2)
        end

        it "check check cacert certobj when 'cacert' parameter is array" do
            cert = described_class.new(params.merge(cacert: [capath, capath_parent]))
            certobj = cert.parameters[:cacert].certobj

            check_cacerts(certobj, 2)
        end

        it 'check certchain value' do
            cert = described_class.new(params)
            content = cert.certchain.map { |c| c.to_pem }.join

            expect(content).to eq([www_domain_com_certificate, www_domain_com_intermediate, www_domain_com_intermediate_parent].join)
          end
      end
    end
  end
end