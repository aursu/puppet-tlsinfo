#! /usr/bin/env ruby
require 'spec_helper'

describe Puppet::Type.type(:sslkey) do
  let(:catalog) { Puppet::Resource::Catalog.new }

  it 'check with empty parameters list' do
    params = {
      title: 'namevar',
      catalog: catalog
    }
    expect { described_class.new(params) }.to raise_error Puppet::Error, %r{File paths must be fully qualified, not 'namevar'}
  end
end
