Puppet::Functions.create_function(:'tlsinfo::certpath') do
    dispatch :certpath do
        scope_param
        param 'String', :cert
    end

    def certpath(scope, cert)
        found = scope.catalog.resources.find { |r| r.is_a?(Puppet::Type.type(:sslcertificate)) && [r[:subject_hash], r[:path], r.title].include?(cert) }
        return found[:path] if found
        nil
    end
  end
