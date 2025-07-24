# frozen_string_literal: true

require 'spec_helper'

RSpec.describe StirShaken do
  describe 'VERSION' do
    it 'has a version number' do
      expect(StirShaken::VERSION).not_to be nil
      expect(StirShaken::VERSION).to match(/\d+\.\d+\.\d+/)
    end
  end

  describe 'configuration' do
    it 'has default configuration values' do
      config = StirShaken.configuration
      expect(config.certificate_cache_ttl).to eq(3600)
      expect(config.http_timeout).to eq(30)
      expect(config.default_attestation).to eq('C')
    end

    it 'allows configuration to be set' do
      StirShaken.configure do |config|
        config.certificate_cache_ttl = 7200
        config.http_timeout = 60
        config.default_attestation = 'A'
      end

      config = StirShaken.configuration
      expect(config.certificate_cache_ttl).to eq(7200)
      expect(config.http_timeout).to eq(60)
      expect(config.default_attestation).to eq('A')
    end

    it 'can reset configuration to defaults' do
      StirShaken.configure do |config|
        config.certificate_cache_ttl = 7200
        config.http_timeout = 60
        config.default_attestation = 'A'
      end

      StirShaken.reset_configuration!

      config = StirShaken.configuration
      expect(config.certificate_cache_ttl).to eq(3600)
      expect(config.http_timeout).to eq(30)
      expect(config.default_attestation).to eq('C')
    end

    it 'yields configuration object in configure block' do
      expect { |b| StirShaken.configure(&b) }.to yield_with_args(StirShaken::Configuration)
    end
  end

  describe 'module structure' do
    it 'defines all required classes' do
      expect(defined?(StirShaken::Passport)).to be_truthy
      expect(defined?(StirShaken::DivPassport)).to be_truthy
      expect(defined?(StirShaken::AuthenticationService)).to be_truthy
      expect(defined?(StirShaken::VerificationService)).to be_truthy
      expect(defined?(StirShaken::CertificateManager)).to be_truthy
      expect(defined?(StirShaken::SipIdentity)).to be_truthy
      expect(defined?(StirShaken::Attestation)).to be_truthy
      expect(defined?(StirShaken::SecurityLogger)).to be_truthy
    end

    it 'defines all error classes' do
      expect(defined?(StirShaken::Error)).to be_truthy
      expect(defined?(StirShaken::PassportValidationError)).to be_truthy
      expect(defined?(StirShaken::CertificateError)).to be_truthy
      expect(defined?(StirShaken::CertificateFetchError)).to be_truthy
      expect(defined?(StirShaken::CertificateValidationError)).to be_truthy
      expect(defined?(StirShaken::SignatureVerificationError)).to be_truthy
      expect(defined?(StirShaken::InvalidAttestationError)).to be_truthy
      expect(defined?(StirShaken::InvalidPhoneNumberError)).to be_truthy
      expect(defined?(StirShaken::InvalidIdentityHeaderError)).to be_truthy
      expect(defined?(StirShaken::InvalidTokenError)).to be_truthy
      expect(defined?(StirShaken::ConfigurationError)).to be_truthy
      expect(defined?(StirShaken::InvalidDiversionReasonError)).to be_truthy
    end

    it 'has proper error inheritance' do
      expect(StirShaken::PassportValidationError.superclass).to eq(StirShaken::Error)
      expect(StirShaken::CertificateError.superclass).to eq(StirShaken::Error)
      expect(StirShaken::CertificateFetchError.superclass).to eq(StirShaken::CertificateError)
      expect(StirShaken::CertificateValidationError.superclass).to eq(StirShaken::CertificateError)
      expect(StirShaken::SignatureVerificationError.superclass).to eq(StirShaken::Error)
      expect(StirShaken::InvalidDiversionReasonError.superclass).to eq(StirShaken::Error)
      expect(StirShaken::Error.superclass).to eq(StandardError)
    end
  end
end 