# frozen_string_literal: true

require 'bundler/setup'
require 'stirshaken'
require 'webmock/rspec'
require 'vcr'

# Configure WebMock to allow localhost connections for testing
WebMock.disable_net_connect!(allow_localhost: true)

# Configure VCR for recording HTTP interactions
VCR.configure do |config|
  config.cassette_library_dir = 'spec/vcr_cassettes'
  config.hook_into :webmock
  config.configure_rspec_metadata!
  config.default_cassette_options = {
    record: :once,
    match_requests_on: [:method, :uri, :body]
  }
end

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on Module and main
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  # Reset configuration before each test
  config.before(:each) do
    StirShaken.reset_configuration!
    StirShaken::CertificateManager.clear_cache!
  end

  # Shared test helpers
  config.include Module.new {
    def generate_test_key_pair
      StirShaken::AuthenticationService.generate_key_pair
    end

    def create_test_certificate(private_key, subject: '/CN=Test STIR Certificate/O=Test Organization', telephone_numbers: ['+15551234567'])
      StirShaken::AuthenticationService.create_test_certificate(
        private_key,
        subject: subject,
        telephone_numbers: telephone_numbers
      )
    end

    def create_auth_service(private_key:, certificate: nil, cert_url: 'https://test.example.com/cert.pem')
      StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )
    end

    def mock_certificate_fetch(url, certificate)
      cache = StirShaken::CertificateManager.certificate_cache
      mutex = StirShaken::CertificateManager.cache_mutex
      
      mutex.synchronize do
        cache[url] = {
          certificate: certificate,
          fetched_at: Time.now
        }
      end
    end

    def valid_phone_numbers
      ['+15551234567', '+15559876543', '+12125551234', '+442071234567']
    end

    def invalid_phone_numbers
      ['invalid', '123', 'abc123', '+', '++15551234567', '15551234567']
    end
  }
end 