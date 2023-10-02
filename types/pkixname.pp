type Tlsinfo::PKIXName = Struct[{
    Optional[common] => String,
    Optional['C']            => String, # Country
    Optional['ST']           => String, # State
    Optional['L']            => String, # Locality
    Optional['O']            => String, # OrganisationName
    Optional['OU']           => String, # OrganisationalUnitName
    Optional['E']            => String,
    Optional['SerialNumber'] => String,
    Optional['OID']          => Hash[String, String],
}]
