#! /usr/bin/env ruby
require 'spec_helper'
require 'openssl'

describe Puppet::Type.type(:sslkey) do
  let(:catalog) { Puppet::Resource::Catalog.new }
  let(:www_domain_com_private) do
    <<-RSAKEYDATA
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2ioyHOr0O+/j7ztapdb9qJl2lmOEOC8u/AwajAJhhZ5NZ9cF
et54WyGx+ou59dKQDgGRB6El5wNzMhwVoVhY6VwJrem/e3UDDhI9trr2Ei+0wZkF
LK/wmTNdZ9RmnZfRL24g/2F/7wphq/akRGPjQjQC7Ev6jXyd3O+o0qqC7diMEd+f
WpZS94Tvacf/7C1q6pvBoxTv+bf37D8hYDi4FM+E7GcykJcMDaeAdu36oCaM9DHj
ZsedOGE5+ggt0Km+Y5rRmphTLtgwfwNGnHV38lOkQc5nXNEXkyj0AwQW0eMurmI5
eP20FLngig4y/s8X5OiYn1LrOW7i0KMj0K0yywIDAQABAoIBACLL+iQ8oWnx8EQX
DnVHHjxHBfAkvVEMzYysDYvpUU6zmhsG47veQgofDLkukiGQTSO+wjgaTuZS2YvT
iOusILpP0Mdpcf4qAqu64xcDKP5rl4QNeRLQmSqGU86cxSU7ssTC5wZ0sagZ2sxH
0ZmK6ROFIjY4RCVPDArSOvYm9i0jQoII/eQSQPHAxQ9bvG9wHhFKtkR4Yg8CWVhH
ZyDHDH7Wbvn6gY19bqYYK80NwMoh9CnWFux+nesiGbLfGunL7TPBoK+ckbT5awEP
RSjSn4uAkj1ll/MwCJpEytNwr3gKhE0eUVa3hfLX2p99OKYRKZQl0tcfE4EnxjcV
pASD2bECgYEA8p4q40E+Dpr7zGSVA9WPWJvjZUfjvF/WQ8f3kQP4YX8oMAvt3zn5
hyaz91Lh5fXwNNSVhVn4Ze5unzvcDAR/leqLSHoc4u74A9zwWJN6CdtHxK8HW3Nd
gjhwY7qrVPEPX3WPM1pP08+obi8HV9JrrfauKbfTNxQFU0twBffdkPkCgYEA5jK+
p77sCvSUh40NqofMo+TaUMSI463CDZ1qhse2LiEBuxcmShsBb/Mm62Q5MjpSNQ7g
pyoiys09vuRCkhbXIpQT9SYiHRDy3Ha4Cjix8wWU7c2bpAc7gVBNg1JHAP9E/xwn
ucHjRhFyZLr8E7DJ/S9QeZunUGozFaJY1F8SVuMCgYEArY2pflFwdAA3+VlGI60E
Us2I2C2Z4mnoGyqTlP/zEMNmWyBdc97D+gMcn+KBSAAraY9cujzG7RuntG6clVgu
cG6MXjdELK3natQEdkhg92YOK8tNBwU6selvtFeXMjcS2SV+X6zOB+W3RcKMjS0v
7AzXP26JQBApUxFWvF439/kCgYBegdLYV3/c95DLHdPQgTQ4zUn8AtQYdUvH/yqu
7usSgSaOwvBLWE78wRznYxxATMVXVyZQOvJRxHVnG5thEtN8NMME0IUM3dp3PJ5O
Q/x6w33jK5iMfROnAWrxUSQpeqO/ALYmgz1llOAcDtBS3S/wLC6j3o2QbClQ5ngF
qIqE9QKBgD+DFd6cc5zeyDNvVLkjcP7OQNs4ftnhZiMZKT8GgqGMw4prQr3VYUSS
2OR7a6YU3qLdBeX7/3w0FFmPVudDm3v0B+gGa6z+waAUP9ctGmHEEKTZHXY9CV3x
FbqDhaZYwLRaQNBmSWUi49bI68c4w4mVOKGPqjPH+k/1p6OpgSz4
-----END RSA PRIVATE KEY-----
RSAKEYDATA
  end

  let(:self_signed_encrypted) do
    <<-RSAKEYDATA
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,8D571C492C63A335

9xFX/0xxyYeVDmSIAUSV/EsqqqM8UxXTqT2qASuqAO5B7tnyN2cPoZx6kntSrBfo
xU0Vyg/kZHMRGSPPVfwxPd6+cylR7SHIR+ya/oKJj0kawLgt7q6cyMxtwzLweip4
T9QzrkeeiN5FvrRFg8pe2fXgX9Ngf1aCgZJdRQQuj6xN9txf86bbv2U/9WpL72wv
3V+y2vB1yL+rOvvltqHfwt+RAWkhXGRjL0sea9gNiyWKmnygfCpKX4FDOrWaVWhX
/jGD+anMLI2/+VmfAy4eC7fKOtCp0Q9qCxwPPmwAEvtM/Gba6zm+tW0b+rLzO0W6
k7mzIBhtXwzXVKhZW6QbmP+s/5LAPsvyCrjAXNicTD4wB3JHrU3d/EXpJMj1Nb2L
ufk990E2SkAmUy2BpsJ7L4uWPkpAt9PEdDILQr/ftIDLQQh2jYKQCRTHKNk+OrzL
HsUDStRxRhhrbjPjZ0FZ9XiF2VSvULDPLoKZl8y5gkfwokFvY8Nid+0dv6fOjeMl
WTkvJW4PKdC5hj28e2faus8utaU43TWKDyZNXhPamaFun2ROJcSykingQbLXQt7q
uUqpZlp348035Sqcc4IiuqE9wxJPX58CLZF51YYFzkoLfdCFZK7pZUEFkXHCKlbg
I1lcbRLP0Zr2O4DMTSQymJLtuWVpnr20SpRDEGc3QRyo/hX4hxad9P/NcdD1vPTv
3I93E4Q4mh7jkdpVTszgIVFPKy83Uq7b66WNBvqwQ803Ow7C2bvKLb0INdSPZriv
JDyG7MmQyimGM5Pmg0t2Ne/XnYha8CFgH8TrYt/3/qdjXiLBEYsE8cqorjrd0w6z
XUHA6oU5z9a8yZVsarfTiZygL9UQYQM1+xaaVFkqVrpYg5j7fVZV4q+dNulOPJPi
zHh0PrRYLtteWZOX++/PZn0+eaUFHJ/DOAD+8PdnqRaSMxyzoYK3f4BmI/eyDetx
jsE9ocTm23r5knayLqLQHNP4QdGnKiiF4xkwERkOrQs1KyseVBE4UKfs5v41TNYA
EwIhJYVVOPaMi/Zxuosne7aTMGHsP52Zp1qi4l+pgJssoGtRSHSgyoqgsMU2OjHX
anQrJhU1R6SSZNqgzGq3CFajnSQ9x5Y6Ryqj+Kp2+F8GgnerEx9R/QSDiVKrE7cR
iOIZQrSSobCFtHjyvQCGF4qLS4lxnAFidTq6wIwsiNKk+OUZ8/F4c4Ef8xE/gPzK
3mlrV5c3RDyQcuhihuQB9R5edkSCC+fG0fSqzuD9ZzsHgLKDjRqFqZFEkTUPYG2b
Uk4KARMmHa1oIXDPnsoueFSWch8Ac5ZtudY03WnpQstWKJoo6ivIYFvnfNq7962i
rbBJPfJZaRVTBonFySbDJCKson8DHSXLrdoVNOzNBNZKyCwXY0JJDF/cOUsz5IJr
6KEpBHznYMzJo3+uAtt7cgYT2xx/z7iQQS5SZOsiHcc8uGOdIzwDK7iV8N61l8n0
eJhh+HR3RF/SlleXTxTTBkuzUAEO8hg7qNL2AQMxx6yk0G87E2RMjuKXHxbei+Mx
DaWiH5/lbYeEu559R18JVtY11Gx43SmcndlSe7F+WYLHS7ZBpD5Tsg==
-----END RSA PRIVATE KEY-----
RSAKEYDATA
  end

  let(:self_signed_encrypted_modulus) do
    'C4C9D6E02EAF9EB0D1C8425D24E294907C3F5E6CE780F13E6C78325F163D67EB0D2EAC91'\
    '7BD9C8CE72D01C48AE70ABF2BE19A9C32FBAF39FB999AA13CC2187EA70F06C7870BD4C63'\
    '09AD2C523B7FA503DA0AA81C7C1E879A458CA1F6A49CDEC1793FA77F33A4AAF07EACF3D9'\
    '5901262ADE738835C6FEC6EDB85E76191B871AEDF5EEA747380D3C1620B1DFC20474B531'\
    '736DB3A056EFAEC4C3C40F47E10FB1A93D206ABDD47274E9548DC4F8E70C0DB0FA17DB38'\
    '00EC0B8BD8076B997B15EB84E71EE99D63933E87C989E68DE55F24EE20BFE59E371B0B07'\
    '76F5C69E6298F7EFC53D9A622F1A86A0BD3441292A50B10A5D912D039F93AB8CCC78BA5B'\
    '3C023769'
  end

  it 'check with empty parameters list' do
    params = {
      title: 'namevar',
      catalog: catalog
    }
    expect { described_class.new(params) }.to raise_error Puppet::Error, %r{File paths must be fully qualified, not 'namevar'}
  end

  it 'check with empty parameters and proper title' do
    params = {
      title: '/etc/pki/tls/private/www.domain.com.key',
      catalog: catalog
    }
    expect { described_class.new(params) }.to raise_error Puppet::Error, %r{:content property is mandatory for Sslkey resource}
  end

  context 'when title_patterns match / at the end' do
    let(:key) do
      described_class.new(
        title: '/etc/pki/tls/private/www.domain.com.key//',
        content: www_domain_com_private,
        catalog: catalog,
      )
    end

    it 'set path without slashes at the end' do
      expect(key[:path]).to eq('/etc/pki/tls/private/www.domain.com.key')
    end
  end

  context 'when encrypted key passed' do
    let(:params) do
      {
        title: '/etc/pki/tls/private/8994aafb.key',
        content: self_signed_encrypted,
        catalog: catalog
      }
    end

    it 'fail without password' do
      expect { described_class.new(params) }.to raise_error Puppet::Error, %r{Can not read private key content}
    end

    context 'with valid passowrd' do
      let(:key) do
        described_class.new(params.merge(password: 'SecureSecret'))
      end

      it 'not fail' do
        expect { described_class.new(params.merge(password: 'SecureSecret')) }.not_to raise_error
      end

      it 'check content keyobj type to be OpenSSL::PKey::RSA' do
        expect(key.parameters[:content].keyobj).to be_instance_of(OpenSSL::PKey::RSA)
      end

      it 'check content keyobj modulus' do
        expect(key.parameters[:content].keyobj.params['n'].to_s(16)).to eq(self_signed_encrypted_modulus)
      end
    end
  end

  context 'when password property specified' do
    let(:params) do
      {
        title: '/etc/pki/tls/private/www.domain.com.key',
        content: www_domain_com_private,
        catalog: catalog
      }
    end

    it 'raise error if password is not a string' do
      expect { described_class.new(params.merge(password: 123_456)) }.to raise_error Puppet::Error, %r{Passwords must be a string or :undef}
    end

    it 'not raise error when password is empty string' do
      expect { described_class.new(params.merge(password: '')) }.not_to raise_error
    end

    it 'ignore password if private key is not encrypted' do
      expect { described_class.new(params.merge(password: 'secret')) }.not_to raise_error
    end
  end
end
