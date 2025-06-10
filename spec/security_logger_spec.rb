# frozen_string_literal: true

require 'spec_helper'

RSpec.describe StirShaken::SecurityLogger do
  let(:test_phone_number) { '+15551234567' }
  let(:test_url) { 'https://example.com/certificate.pem' }
  let(:test_identity_header) { 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.test.signature' }

  before do
    # Ensure logging is enabled for tests
    allow(ENV).to receive(:[]).with('STIRSHAKEN_SECURITY_LOGGING').and_return(nil)
    
    # Capture log output from stderr
    @original_stderr = $stderr
    $stderr = StringIO.new
  end

  after do
    $stderr = @original_stderr
  end

  describe '.enabled?' do
    context 'when STIRSHAKEN_SECURITY_LOGGING is not set' do
      it 'returns true by default' do
        allow(ENV).to receive(:[]).with('STIRSHAKEN_SECURITY_LOGGING').and_return(nil)
        expect(described_class.enabled?).to be true
      end
    end

    context 'when STIRSHAKEN_SECURITY_LOGGING is set to false' do
      it 'returns false' do
        allow(ENV).to receive(:[]).with('STIRSHAKEN_SECURITY_LOGGING').and_return('false')
        expect(described_class.enabled?).to be false
      end
    end

    context 'when STIRSHAKEN_SECURITY_LOGGING is set to any other value' do
      it 'returns true' do
        allow(ENV).to receive(:[]).with('STIRSHAKEN_SECURITY_LOGGING').and_return('true')
        expect(described_class.enabled?).to be true
      end
    end
  end

  describe '.log_security_event' do
    context 'when logging is enabled' do
      it 'logs a basic security event' do
        described_class.log_security_event(:authentication_success, { test: 'data' })
        
        output = $stderr.string
        expect(output).to include('[STIRSHAKEN-SECURITY]')
        expect(output).to include('AUTH_SUCCESS')
        expect(output).to include('test')
        expect(output).to include('data')
      end

      it 'includes required fields in log entry' do
        described_class.log_security_event(:verification_failure, { error: 'test error' })
        
        output = $stderr.string
        log_entry = JSON.parse(output.match(/\{.*\}$/m).to_s)
        
        expect(log_entry).to have_key('timestamp')
        expect(log_entry).to have_key('event_type')
        expect(log_entry).to have_key('severity')
        expect(log_entry).to have_key('details')
        expect(log_entry).to have_key('library_version')
        expect(log_entry).to have_key('process_id')
      end

      it 'uses custom severity when provided' do
        described_class.log_security_event(:authentication_success, {}, severity: :critical)
        
        output = $stderr.string
        expect(output).to include('CRITICAL')
      end

      it 'determines severity automatically when not provided' do
        described_class.log_security_event(:rate_limit_exceeded, {})
        
        output = $stderr.string
        expect(output).to include('HIGH')
      end

      it 'handles unknown event types' do
        described_class.log_security_event(:unknown_event, {})
        
        output = $stderr.string
        expect(output).to include('UNKNOWN_EVENT')
      end
    end

    context 'when logging is disabled' do
      before do
        allow(ENV).to receive(:[]).with('STIRSHAKEN_SECURITY_LOGGING').and_return('false')
      end

      it 'does not log anything' do
        described_class.log_security_event(:authentication_success, { test: 'data' })
        
        output = $stderr.string
        expect(output).to be_empty
      end
    end
  end

  describe '.log_authentication_success' do
    it 'logs authentication success with masked phone number' do
      destination_numbers = ['+15559876543', '+12125551234']
      
      described_class.log_authentication_success(test_phone_number, destination_numbers, 'A')
      
      output = $stderr.string
      expect(output).to include('AUTH_SUCCESS')
      expect(output).to include('LOW')
      expect(output).to include('+15*******4567') # masked phone number
      expect(output).to include('"destination_count":2')
      expect(output).to include('"attestation":"A"')
    end

    it 'handles single destination number' do
      described_class.log_authentication_success(test_phone_number, ['+15559876543'], 'B')
      
      output = $stderr.string
      expect(output).to include('"destination_count":1')
      expect(output).to include('"attestation":"B"')
    end
  end

  describe '.log_verification_success' do
    let(:verification_result) do
      {
        attestation: 'A',
        certificate_url: test_url,
        valid: true
      }
    end

    it 'logs verification success with masked URL' do
      described_class.log_verification_success(test_identity_header, verification_result)
      
      output = $stderr.string
      expect(output).to include('VERIFY_SUCCESS')
      expect(output).to include('LOW')
      expect(output).to include('"header_length":')
      expect(output).to include('"attestation":"A"')
      expect(output).to include('https://example.com/***')
    end
  end

  describe '.log_security_failure' do
    let(:test_error) { StirShaken::CertificateFetchError.new('Certificate fetch failed') }
    let(:context) { { url: test_url, retry_count: 3 } }

    it 'logs security failure with error details' do
      described_class.log_security_failure(:certificate_fetch, test_error, context)
      
      output = $stderr.string
      expect(output).to include('CERT_FETCH')
      expect(output).to include('HIGH') # CertificateFetchError should be HIGH severity
      expect(output).to include('CertificateFetchError')
      expect(output).to include('Certificate fetch failed')
      expect(output).to include('retry_count')
    end

    it 'determines severity based on error type' do
      config_error = StirShaken::ConfigurationError.new('Invalid config')
      described_class.log_security_failure(:configuration_error, config_error)
      
      output = $stderr.string
      expect(output).to include('CRITICAL')
    end

    it 'handles errors without context' do
      described_class.log_security_failure(:verification_failure, test_error)
      
      output = $stderr.string
      expect(output).to include('VERIFY_FAILURE')
      expect(output).to include('"context":{}')
    end
  end

  describe '.log_certificate_fetch' do
    it 'logs successful certificate fetch' do
      described_class.log_certificate_fetch(test_url, true, cache_hit: false)
      
      output = $stderr.string
      expect(output).to include('CERT_FETCH')
      expect(output).to include('LOW')
      expect(output).to include('"success":true')
      expect(output).to include('"cache_hit":false')
      expect(output).to include('https://example.com/***')
    end

    it 'logs failed certificate fetch with higher severity' do
      described_class.log_certificate_fetch(test_url, false)
      
      output = $stderr.string
      expect(output).to include('CERT_FETCH')
      expect(output).to include('MEDIUM')
      expect(output).to include('"success":false')
    end

    it 'logs cache hit information' do
      described_class.log_certificate_fetch(test_url, true, cache_hit: true)
      
      output = $stderr.string
      expect(output).to include('"cache_hit":true')
    end
  end

  describe '.log_rate_limit_exceeded' do
    it 'logs rate limit exceeded with high severity' do
      described_class.log_rate_limit_exceeded(test_url, 100)
      
      output = $stderr.string
      expect(output).to include('RATE_LIMIT')
      expect(output).to include('HIGH')
      expect(output).to include('"request_count":100')
      expect(output).to include('https://example.com/***')
    end
  end

  describe 'data sanitization' do
    it 'removes sensitive private key information' do
      sensitive_details = {
        private_key: 'sensitive-private-key-data',
        jwt_token: 'sensitive-jwt-token',
        safe_data: 'this is safe'
      }
      
      described_class.log_security_event(:authentication_success, sensitive_details)
      
      output = $stderr.string
      expect(output).not_to include('sensitive-private-key-data')
      expect(output).not_to include('sensitive-jwt-token')
      expect(output).to include('this is safe')
    end

    it 'masks phone numbers in details' do
      details = { originating_number: '+15551234567' }
      
      described_class.log_security_event(:authentication_success, details)
      
      output = $stderr.string
      expect(output).to include('+15******4567')
      expect(output).not_to include('+15551234567')
    end
  end

  describe 'phone number masking' do
    it 'masks long phone numbers correctly' do
      # This tests the private method indirectly through public methods
      described_class.log_authentication_success('+442071234567', ['+15559876543'], 'A')
      
      output = $stderr.string
      expect(output).to include('+44********4567')
    end

    it 'does not mask short phone numbers' do
      short_number = '+1234'
      described_class.log_authentication_success(short_number, ['+15559876543'], 'A')
      
      output = $stderr.string
      expect(output).to include('+1234') # Should not be masked
    end

    it 'handles non-string phone numbers' do
      described_class.log_authentication_success(nil, ['+15559876543'], 'A')
      
      output = $stderr.string
      expect(output).to include('null') # JSON representation of nil
    end
  end

  describe 'URL masking' do
    it 'masks URLs in certificate fetch logs' do
      long_url = 'https://certificates.example.com/very/long/path/certificate.pem'
      described_class.log_certificate_fetch(long_url, true)
      
      output = $stderr.string
      expect(output).to include('https://certificates.example.com/***')
      expect(output).not_to include('/very/long/path/certificate.pem')
    end

    it 'handles non-string URLs' do
      described_class.log_certificate_fetch(nil, true)
      
      output = $stderr.string
      expect(output).to include('null')
    end
  end

  describe 'severity determination' do
    it 'assigns correct severity levels for different event types' do
      test_cases = [
        [:authentication_success, 'LOW'],
        [:verification_success, 'LOW'],
        [:certificate_fetch, 'LOW'],
        [:authentication_failure, 'MEDIUM'],
        [:verification_failure, 'MEDIUM'],
        [:certificate_validation_failure, 'MEDIUM'],
        [:rate_limit_exceeded, 'HIGH'],
        [:configuration_error, 'HIGH'],
        [:network_error, 'MEDIUM'],
        [:invalid_input, 'MEDIUM']
      ]
      
      test_cases.each do |event_type, expected_severity|
        $stderr = StringIO.new # Reset output capture
        described_class.log_security_event(event_type, {})
        
        output = $stderr.string
        expect(output).to include(expected_severity), 
               "Expected #{event_type} to have #{expected_severity} severity"
      end
    end
  end

  describe 'error severity determination' do
    it 'assigns critical severity to configuration errors' do
      error = StirShaken::ConfigurationError.new('Config error')
      described_class.log_security_failure(:configuration_error, error)
      
      output = $stderr.string
      expect(output).to include('CRITICAL')
    end

    it 'assigns high severity to certificate and signature errors' do
      [
        StirShaken::CertificateFetchError.new('Cert fetch error'),
        StirShaken::SignatureVerificationError.new('Signature error')
      ].each do |error|
        $stderr = StringIO.new
        described_class.log_security_failure(:test_event, error)
        
        output = $stderr.string
        expect(output).to include('HIGH')
      end
    end

    it 'assigns medium severity to validation errors' do
      [
        StirShaken::InvalidPhoneNumberError.new('Invalid phone'),
        StirShaken::InvalidAttestationError.new('Invalid attestation')
      ].each do |error|
        $stderr = StringIO.new
        described_class.log_security_failure(:test_event, error)
        
        output = $stderr.string
        expect(output).to include('MEDIUM')
      end
    end

    it 'assigns medium severity to unknown errors' do
      error = StandardError.new('Unknown error')
      described_class.log_security_failure(:test_event, error)
      
      output = $stderr.string
      expect(output).to include('MEDIUM')
    end
  end

  describe 'JSON output format' do
    it 'produces valid JSON output' do
      described_class.log_security_event(:authentication_success, { test: 'data' })
      
      output = $stderr.string
      json_match = output.match(/\{.*\}$/m)
      expect(json_match).not_to be_nil
      
      parsed_json = JSON.parse(json_match.to_s)
      expect(parsed_json).to be_a(Hash)
    end

    it 'includes timestamp in ISO8601 format' do
      described_class.log_security_event(:authentication_success, {})
      
      output = $stderr.string
      log_entry = JSON.parse(output.match(/\{.*\}$/m).to_s)
      
      timestamp = log_entry['timestamp']
      expect { Time.iso8601(timestamp) }.not_to raise_error
    end

    it 'includes process ID' do
      described_class.log_security_event(:authentication_success, {})
      
      output = $stderr.string
      log_entry = JSON.parse(output.match(/\{.*\}$/m).to_s)
      
      expect(log_entry['process_id']).to eq(Process.pid)
    end

    it 'includes library version' do
      described_class.log_security_event(:authentication_success, {})
      
      output = $stderr.string
      log_entry = JSON.parse(output.match(/\{.*\}$/m).to_s)
      
      expect(log_entry['library_version']).to eq(StirShaken::VERSION)
    end
  end
end 