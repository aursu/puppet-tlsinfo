require 'spec_helper'

describe 'tlsinfo::normalize' do
  context 'with dash inside name' do
    it {
      is_expected.to run.with_params('ssloffload-wildcard.domain.com').and_return('ssloffload_wildcard_domain_com')
    }
  end
end