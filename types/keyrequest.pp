type Tlsinfo::KeyRequest = Struct[{
    algo => Enum['rsa', 'ecdsa', 'ed25519'],
    size => Integer,
}]
