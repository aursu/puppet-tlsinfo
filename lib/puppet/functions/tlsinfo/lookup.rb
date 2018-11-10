Puppet::Functions.create_function(:'tlsinfo::getcertpath') do
    dispatch :certpath do
        param 'String', :certpairname
    end

    def certpath(certpairname)

    end
  end