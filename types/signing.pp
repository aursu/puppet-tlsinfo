# Signing codifies the signature configuration policy for a CA.
type Tlsinfo::Signing = Struct[{
    profiles => Hash[
      String,
      Tlsinfo::SigningProfile,
    ],
    'default' => Tlsinfo::SigningProfile,
}]
