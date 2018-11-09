Puppet::Functions.create_function(:'tlsinfo::getcertpath') do
    dispatch :certpath do
        param 'String', :certpairname
    end
  
    def lookupcatalog(key)
        catalog = closure_scope.catalog
        # path, subject_hash and title are all key values
        catalog.resources.find { |r| r.is_a?(Puppet::Type.type(:sslcertificate)) &&
                                     [r[:subject_hash], r[:subject_hash_old], r[:path], r.title].include?(key) }
    end

    def certpath(certpairname)
        cert = lookupcatalog(certpairname)
        cert[:path]
    end
  end