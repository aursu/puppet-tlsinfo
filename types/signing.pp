type Tlsinfo::Signing = Struct[{
    profiles => Hash[
      String,
      Tlsinfo::SigningProfile,
    ],
    default => Tlsinfo::SigningProfile,
}]
