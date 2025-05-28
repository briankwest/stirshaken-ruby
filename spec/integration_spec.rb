# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'STIR/SHAKEN Integration Tests' do
  let(:key_pair) { generate_test_key_pair }
  let(:private_key) { key_pair[:private_key] }
  let(:public_key) { key_pair[:public_key] }
  let(:certificate) { create_test_certificate(private_key, telephone_numbers: ['+15551234567', '+15559876543']) }
  let(:cert_url) { 'https://test.example.com/cert.pem' }

  before do
    # Mock certificate fetch for all tests
    stub_request(:get, cert_url)
      .to_return(status: 200, body: certificate.to_pem, headers: {})
  end

  describe 'Complete Call Signing and Verification Workflow' do
    it 'signs and verifies a complete call successfully' do
      # Step 1: Create authentication service
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )

      # Step 2: Sign a call
      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )

      expect(identity_header).to be_a(String)
      expect(identity_header).to include('eyJ') # JWT token present

      # Step 3: Create verification service
      verification_service = StirShaken::VerificationService.new

      # Step 4: Verify the call
      result = verification_service.verify_call(identity_header)

      # Step 5: Validate results
      expect(result.valid?).to be true
      expect(result.attestation).to eq('A')
      expect(result.confidence_level).to eq(100)
      expect(result.passport.originating_number).to eq('+15551234567')
      expect(result.passport.destination_numbers).to eq(['+15559876543'])
      expect(result.certificate.subject.to_s).to include('Test')
    end

    it 'handles the complete workflow with multiple destinations' do
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )

      destinations = ['+15559876543', '+15551111111', '+15552222222']
      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: destinations,
        attestation: 'B'
      )

      verification_service = StirShaken::VerificationService.new
      result = verification_service.verify_call(identity_header)

      expect(result.valid?).to be true
      expect(result.attestation).to eq('B')
      expect(result.confidence_level).to eq(75)
      expect(result.passport.destination_numbers).to eq(destinations)
    end

    it 'validates specific call parameters during verification' do
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )

      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )

      verification_service = StirShaken::VerificationService.new

      # Verify with matching parameters
      result = verification_service.verify_call(
        identity_header,
        originating_number: '+15551234567',
        destination_number: '+15559876543'
      )
      expect(result.valid?).to be true

      # Verify with mismatched originating number
      result = verification_service.verify_call(
        identity_header,
        originating_number: '+15559999999'
      )
      expect(result.valid?).to be false
      expect(result.reason).to include('mismatch')

      # Verify with mismatched destination number
      result = verification_service.verify_call(
        identity_header,
        destination_number: '+15559999999'
      )
      expect(result.valid?).to be false
      expect(result.reason).to include('not found')
    end
  end

  describe 'All Attestation Levels' do
    let(:auth_service) do
      StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )
    end

    let(:verification_service) { StirShaken::VerificationService.new }

    %w[A B C].each do |attestation|
      it "handles attestation level #{attestation} correctly" do
        identity_header = auth_service.sign_call(
          originating_number: '+15551234567',
          destination_number: '+15559876543',
          attestation: attestation
        )

        result = verification_service.verify_call(identity_header)

        expect(result.valid?).to be true
        expect(result.attestation).to eq(attestation)
        expect(result.confidence_level).to eq(StirShaken::Attestation.confidence_level(attestation))

        # Verify structure validation also works
        structure_info = verification_service.validate_structure(identity_header)
        expect(structure_info[:valid_structure]).to be true
        expect(structure_info[:attestation]).to eq(attestation)
        expect(structure_info[:attestation_description]).to eq(StirShaken::Attestation.description(attestation))
      end
    end
  end

  describe 'Certificate Management Integration' do
    it 'fetches and caches certificates during verification' do
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )

      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )

      verification_service = StirShaken::VerificationService.new

      # Clear any existing cache
      StirShaken::CertificateManager.clear_cache!

      # First verification should fetch certificate
      expect(HTTParty).to receive(:get).once.and_call_original
      result1 = verification_service.verify_call(identity_header)
      expect(result1.valid?).to be true

      # Second verification should use cached certificate
      expect(HTTParty).not_to receive(:get)
      result2 = verification_service.verify_call(identity_header)
      expect(result2.valid?).to be true

      # Verify cache statistics
      cache_stats = StirShaken::CertificateManager.cache_stats
      expect(cache_stats[:size]).to eq(1)
      expect(cache_stats[:entries]).to include(cert_url)
    end

    it 'handles certificate fetch failures gracefully' do
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )

      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )

      # Clear cache and mock failure
      StirShaken::CertificateManager.clear_cache!
      stub_request(:get, cert_url).to_return(status: 404, body: 'Not Found')

      verification_service = StirShaken::VerificationService.new
      result = verification_service.verify_call(identity_header)

      expect(result.valid?).to be false
      expect(result.reason).to include('Certificate fetch failed')
    end

    it 'validates certificate authorization for phone numbers' do
      # Create certificate that doesn't authorize the originating number
      unauthorized_cert = create_test_certificate(private_key, telephone_numbers: ['+15559999999'])
      
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: unauthorized_cert
      )

      identity_header = auth_service.sign_call(
        originating_number: '+15551234567', # Not authorized by certificate
        destination_number: '+15559876543',
        attestation: 'A'
      )

      # Mock the unauthorized certificate fetch
      StirShaken::CertificateManager.clear_cache!
      stub_request(:get, cert_url).to_return(status: 200, body: unauthorized_cert.to_pem)

      verification_service = StirShaken::VerificationService.new
      result = verification_service.verify_call(identity_header)

      expect(result.valid?).to be false
      expect(result.reason).to include('not authorized')
    end
  end

  describe 'PASSporT Token Lifecycle' do
    it 'maintains data integrity through complete lifecycle' do
      # Original call data
      call_data = {
        originating_number: '+15551234567',
        destination_numbers: ['+15559876543', '+15551111111'],
        attestation: 'B',
        origination_id: 'integration-test-123'
      }

      # Step 1: Create authentication service
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )

      # Step 2: Create PASSporT token
      passport_token = auth_service.create_passport(
        originating_number: call_data[:originating_number],
        destination_numbers: call_data[:destination_numbers],
        attestation: call_data[:attestation],
        origination_id: call_data[:origination_id]
      )

      # Step 3: Parse token without verification
      passport = StirShaken::Passport.parse(passport_token, verify_signature: false)
      expect(passport.originating_number).to eq(call_data[:originating_number])
      expect(passport.destination_numbers).to eq(call_data[:destination_numbers])
      expect(passport.attestation).to eq(call_data[:attestation])
      expect(passport.origination_id).to eq(call_data[:origination_id])

      # Step 4: Parse and verify token
      verified_passport = StirShaken::Passport.parse(passport_token, public_key: public_key, verify_signature: true)
      expect(verified_passport.originating_number).to eq(call_data[:originating_number])

      # Step 5: Create SIP Identity header
      identity_header = StirShaken::SipIdentity.create(
        passport_token: passport_token,
        certificate_url: cert_url
      )

      # Step 6: Parse SIP Identity header
      sip_identity = StirShaken::SipIdentity.parse(identity_header)
      expect(sip_identity.passport_token).to eq(passport_token)
      expect(sip_identity.info_url).to eq(cert_url)

      # Step 7: Extract and verify PASSporT from SIP header
      extracted_passport = sip_identity.parse_passport(public_key: public_key, verify_signature: true)
      expect(extracted_passport.originating_number).to eq(call_data[:originating_number])
      expect(extracted_passport.destination_numbers).to eq(call_data[:destination_numbers])
      expect(extracted_passport.attestation).to eq(call_data[:attestation])
      expect(extracted_passport.origination_id).to eq(call_data[:origination_id])

      # Step 8: Full verification service validation
      verification_service = StirShaken::VerificationService.new
      result = verification_service.verify_call(identity_header)
      expect(result.valid?).to be true
      expect(result.passport.originating_number).to eq(call_data[:originating_number])
      expect(result.passport.destination_numbers).to eq(call_data[:destination_numbers])
      expect(result.passport.attestation).to eq(call_data[:attestation])
      expect(result.passport.origination_id).to eq(call_data[:origination_id])
    end
  end

  describe 'Error Handling Integration' do
    it 'provides consistent error handling across all components' do
      verification_service = StirShaken::VerificationService.new

      # Test various invalid inputs
      invalid_inputs = [
        nil,
        '',
        'invalid-header',
        'token-without-semicolon',
        'token;missing=required-params',
        'eyJhbGciOiJFUzI1NiJ9.invalid.signature;info=<https://example.com>;alg=ES256;ppt=shaken'
      ]

      invalid_inputs.each do |input|
        result = verification_service.verify_call(input)
        expect(result.valid?).to be false
        expect(result.reason).to be_a(String)
        expect(result.reason).not_to be_empty
        expect(result.confidence_level).to eq(0)
      end
    end

    it 'handles cryptographic errors gracefully' do
      # Create valid header with one key
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )

      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )

      # Try to verify with different certificate (wrong public key)
      wrong_key_pair = generate_test_key_pair
      wrong_certificate = create_test_certificate(wrong_key_pair[:private_key], telephone_numbers: ['+15551234567'])
      
      StirShaken::CertificateManager.clear_cache!
      stub_request(:get, cert_url).to_return(status: 200, body: wrong_certificate.to_pem)

      verification_service = StirShaken::VerificationService.new
      result = verification_service.verify_call(identity_header)

      expect(result.valid?).to be false
      expect(result.reason).to include('Signature verification failed')
    end
  end

  describe 'Performance and Scalability' do
    it 'handles batch operations efficiently' do
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )

      verification_service = StirShaken::VerificationService.new

      # Generate multiple calls
      call_count = 50
      calls = (1..call_count).map do |i|
        {
          from: '+15551234567',
          to: "+1555#{i.to_s.rjust(7, '0')}",
          attestation: %w[A B C].sample,
          id: "batch-call-#{i}"
        }
      end

      # Sign all calls
      start_time = Time.now
      signed_calls = calls.map do |call|
        auth_service.sign_call(
          originating_number: call[:from],
          destination_number: call[:to],
          attestation: call[:attestation],
          origination_id: call[:id]
        )
      end
      signing_time = Time.now - start_time

      # Verify all calls
      start_time = Time.now
      results = signed_calls.map do |header|
        verification_service.verify_call(header)
      end
      verification_time = Time.now - start_time

      # Validate results
      expect(results.length).to eq(call_count)
      expect(results.all?(&:valid?)).to be true

      # Performance expectations (these may need adjustment based on hardware)
      expect(signing_time).to be < 10.0 # Should sign 50 calls in under 10 seconds
      expect(verification_time).to be < 15.0 # Should verify 50 calls in under 15 seconds

      # Verify statistics
      stats = verification_service.stats
      expect(stats[:total_verifications]).to eq(call_count)
      expect(stats[:successful_verifications]).to eq(call_count)
      expect(stats[:success_rate]).to eq(100.0)
    end

    it 'benefits from certificate caching in batch operations' do
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )

      verification_service = StirShaken::VerificationService.new

      # Create multiple calls with same certificate
      headers = 10.times.map do |i|
        auth_service.sign_call(
          originating_number: '+15551234567',
          destination_number: '+15559876543',
          attestation: 'A',
          origination_id: "cache-test-#{i}"
        )
      end

      # Clear cache and expect only one HTTP request
      StirShaken::CertificateManager.clear_cache!
      expect(HTTParty).to receive(:get).once.and_call_original

      # Verify all calls
      results = headers.map { |header| verification_service.verify_call(header) }
      expect(results.all?(&:valid?)).to be true

      # Verify cache was used
      cache_stats = StirShaken::CertificateManager.cache_stats
      expect(cache_stats[:size]).to eq(1)
    end
  end

  describe 'Configuration Integration' do
    it 'respects global configuration settings' do
      # Configure custom settings
      StirShaken.configure do |config|
        config.certificate_cache_ttl = 1800 # 30 minutes
        config.http_timeout = 15
        config.default_attestation = 'B'
      end

      # Verify configuration is applied
      expect(StirShaken.configuration.certificate_cache_ttl).to eq(1800)
      expect(StirShaken.configuration.http_timeout).to eq(15)
      expect(StirShaken.configuration.default_attestation).to eq('B')

      # Test that HTTP timeout is used
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )

      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )

      StirShaken::CertificateManager.clear_cache!
      expect(HTTParty).to receive(:get).with(
        cert_url,
        hash_including(timeout: 15)
      ).and_call_original

      verification_service = StirShaken::VerificationService.new
      result = verification_service.verify_call(identity_header)
      expect(result.valid?).to be true
    end
  end

  describe 'Real-world Scenarios' do
    it 'handles a complete telecommunications call flow' do
      # Scenario: Telecom provider A calls telecom provider B
      
      # Provider A setup
      provider_a_keys = generate_test_key_pair
      provider_a_cert = create_test_certificate(
        provider_a_keys[:private_key],
        subject: '/CN=Provider A STIR Certificate/O=Telecom Provider A',
        telephone_numbers: ['+15551234567', '+15551234568', '+15551234569']
      )
      provider_a_cert_url = 'https://provider-a.com/stir-cert.pem'

      # Mock Provider A's certificate
      stub_request(:get, provider_a_cert_url)
        .to_return(status: 200, body: provider_a_cert.to_pem)

      # Provider A signs outbound call
      provider_a_auth = StirShaken::AuthenticationService.new(
        private_key: provider_a_keys[:private_key],
        certificate_url: provider_a_cert_url,
        certificate: provider_a_cert
      )

      # Call details
      call_details = {
        from: '+15551234567',
        to: '+15559876543',
        attestation: 'A', # Full attestation - Provider A knows the caller
        call_id: 'call-20231201-123456'
      }

      # Sign the call
      identity_header = provider_a_auth.sign_call(
        originating_number: call_details[:from],
        destination_number: call_details[:to],
        attestation: call_details[:attestation],
        origination_id: call_details[:call_id]
      )

      # Provider B receives the call and verifies
      provider_b_verification = StirShaken::VerificationService.new

      # Verify the incoming call
      result = provider_b_verification.verify_call(
        identity_header,
        originating_number: call_details[:from],
        destination_number: call_details[:to]
      )

      # Provider B validates the call
      expect(result.valid?).to be true
      expect(result.attestation).to eq('A')
      expect(result.confidence_level).to eq(100)
      expect(result.passport.originating_number).to eq(call_details[:from])
      expect(result.passport.destination_numbers).to eq([call_details[:to]])
      expect(result.passport.origination_id).to eq(call_details[:call_id])

      # Provider B can trust this call has high confidence
      expect(result.confidence_level).to be >= 75 # High confidence threshold
    end

    it 'handles gateway attestation scenario' do
      # Scenario: Call comes through a gateway with limited information
      
      gateway_keys = generate_test_key_pair
      gateway_cert = create_test_certificate(
        gateway_keys[:private_key],
        subject: '/CN=Gateway STIR Certificate/O=SIP Gateway Inc',
        telephone_numbers: ['+15551234567'] # Gateway is authorized for this range
      )
      gateway_cert_url = 'https://gateway.example.com/stir-cert.pem'

      stub_request(:get, gateway_cert_url)
        .to_return(status: 200, body: gateway_cert.to_pem)

      gateway_auth = StirShaken::AuthenticationService.new(
        private_key: gateway_keys[:private_key],
        certificate_url: gateway_cert_url,
        certificate: gateway_cert
      )

      # Gateway can only provide gateway attestation
      identity_header = gateway_auth.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'C', # Gateway attestation - limited information
        origination_id: 'gateway-call-789'
      )

      verification_service = StirShaken::VerificationService.new
      result = verification_service.verify_call(identity_header)

      expect(result.valid?).to be true
      expect(result.attestation).to eq('C')
      expect(result.confidence_level).to eq(50) # Lower confidence for gateway attestation
      
      # Still provides some assurance that the call went through a verified gateway
      expect(result.confidence_level).to be > 0
    end
  end
end 