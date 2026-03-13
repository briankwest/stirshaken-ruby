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

  describe 'security validation' do
    let(:config) { StirShaken::Configuration.new }

    describe 'timeout security' do
      it 'rejects http_timeout below minimum (5)' do
        config.http_timeout = 3
        expect { config.send(:validate_timeout_security!) }.to raise_error(
          StirShaken::ConfigurationError, /HTTP timeout too low/
        )
      end

      it 'rejects http_timeout above maximum (120)' do
        config.http_timeout = 150
        expect { config.send(:validate_timeout_security!) }.to raise_error(
          StirShaken::ConfigurationError, /HTTP timeout too high/
        )
      end

      it 'rejects negative http_timeout' do
        config.http_timeout = -1
        expect { config.send(:validate_timeout_security!) }.to raise_error(
          StirShaken::ConfigurationError, /HTTP timeout must be a positive number/
        )
      end

      it 'rejects non-numeric http_timeout' do
        config.http_timeout = 'fast'
        expect { config.send(:validate_timeout_security!) }.to raise_error(
          StirShaken::ConfigurationError, /HTTP timeout must be a positive number/
        )
      end

      it 'rejects zero http_timeout' do
        config.http_timeout = 0
        expect { config.send(:validate_timeout_security!) }.to raise_error(
          StirShaken::ConfigurationError, /HTTP timeout must be a positive number/
        )
      end

      it 'accepts http_timeout at minimum boundary (5)' do
        config.http_timeout = 5
        expect { config.send(:validate_timeout_security!) }.not_to raise_error
      end

      it 'accepts http_timeout at maximum boundary (120)' do
        config.http_timeout = 120
        expect { config.send(:validate_timeout_security!) }.not_to raise_error
      end

      it 'accepts valid http_timeout within range' do
        config.http_timeout = 30
        expect { config.send(:validate_timeout_security!) }.not_to raise_error
      end
    end

    describe 'cache TTL security' do
      it 'rejects cache_ttl below minimum (300)' do
        config.certificate_cache_ttl = 100
        expect { config.send(:validate_cache_security!) }.to raise_error(
          StirShaken::ConfigurationError, /Cache TTL too low/
        )
      end

      it 'rejects cache_ttl above maximum (86400)' do
        config.certificate_cache_ttl = 100_000
        expect { config.send(:validate_cache_security!) }.to raise_error(
          StirShaken::ConfigurationError, /Cache TTL too high/
        )
      end

      it 'rejects negative cache_ttl' do
        config.certificate_cache_ttl = -1
        expect { config.send(:validate_cache_security!) }.to raise_error(
          StirShaken::ConfigurationError, /Cache TTL must be a positive number/
        )
      end

      it 'rejects non-numeric cache_ttl' do
        config.certificate_cache_ttl = 'long'
        expect { config.send(:validate_cache_security!) }.to raise_error(
          StirShaken::ConfigurationError, /Cache TTL must be a positive number/
        )
      end

      it 'accepts cache_ttl at minimum boundary (300)' do
        config.certificate_cache_ttl = 300
        expect { config.send(:validate_cache_security!) }.not_to raise_error
      end

      it 'accepts cache_ttl at maximum boundary (86400)' do
        config.certificate_cache_ttl = 86_400
        expect { config.send(:validate_cache_security!) }.not_to raise_error
      end

      it 'accepts valid cache_ttl within range' do
        config.certificate_cache_ttl = 3600
        expect { config.send(:validate_cache_security!) }.not_to raise_error
      end
    end

    describe 'attestation security' do
      it 'rejects invalid attestation X' do
        config.default_attestation = 'X'
        expect { config.send(:validate_attestation_security!) }.to raise_error(
          StirShaken::ConfigurationError, /Invalid default attestation 'X'/
        )
      end

      it 'rejects invalid attestation D' do
        config.default_attestation = 'D'
        expect { config.send(:validate_attestation_security!) }.to raise_error(
          StirShaken::ConfigurationError, /Invalid default attestation 'D'/
        )
      end

      it 'rejects lowercase attestation' do
        config.default_attestation = 'a'
        expect { config.send(:validate_attestation_security!) }.to raise_error(
          StirShaken::ConfigurationError, /Invalid default attestation/
        )
      end

      it 'accepts attestation A' do
        config.default_attestation = 'A'
        expect { config.send(:validate_attestation_security!) }.not_to raise_error
      end

      it 'accepts attestation B' do
        config.default_attestation = 'B'
        expect { config.send(:validate_attestation_security!) }.not_to raise_error
      end

      it 'accepts attestation C' do
        config.default_attestation = 'C'
        expect { config.send(:validate_attestation_security!) }.not_to raise_error
      end
    end

    describe 'valid configuration' do
      it 'passes all validation with default values' do
        expect { config.send(:validate_timeout_security!) }.not_to raise_error
        expect { config.send(:validate_cache_security!) }.not_to raise_error
        expect { config.send(:validate_attestation_security!) }.not_to raise_error
      end

      it 'passes all validation with custom valid values' do
        config.http_timeout = 60
        config.certificate_cache_ttl = 7200
        config.default_attestation = 'A'
        expect { config.send(:validate_timeout_security!) }.not_to raise_error
        expect { config.send(:validate_cache_security!) }.not_to raise_error
        expect { config.send(:validate_attestation_security!) }.not_to raise_error
      end
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