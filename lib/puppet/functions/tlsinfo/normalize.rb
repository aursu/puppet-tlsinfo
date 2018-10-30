Puppet::Functions.create_function(:'tlsinfo::normalize') do
    dispatch :normalize do
        param 'String', :name
    end

    def normalize(name)
        name.sub('*', 'wildcard').gsub('.', '_').gsub("'", '_').gsub(' ', '_')
    end
  end