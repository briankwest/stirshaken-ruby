# frozen_string_literal: true

require 'spec_helper'

RSpec.describe StirShaken::VerificationService do
  let(:key_pair) { generate_test_key_pair }
  let(:private_key) { key_pair[:private_key] }
  let(:public_key) { key_pair[:public_key] }
  let(:certificate) { create_test_certificate(private_key, telephone_numbers: ['+15551234567']) }
  let(:cert_url) { 'https://test.example.com/cert.pem' }
  let(:auth_service) { create_auth_service(private_key: private_key, certificate: certificate, cert_url: cert_url) }
  let(:verification_service) { StirShaken::VerificationService.new }

  before do
    # Mock certificate fetch for verification
    mock_certificate_fetch(cert_url, certificate)
  end

  describe '#initialize' do
    it 'creates a new verification service' do
      service = StirShaken::VerificationService.new
      expect(service).to be_a(StirShaken::VerificationService)
    end

    it 'initializes with empty stats' do
      service = StirShaken::VerificationService.new
      stats = service.stats
      
      expect(stats[:total_verifications]).to eq(0)
      expect(stats[:successful_verifications]).to eq(0)
      expect(stats[:failed_verifications]).to eq(0)
    end
  end

  describe '#verify_call' do
    let(:identity_header) do
      auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )
    end

    it 'verifies a valid call successfully' do
      result = verification_service.verify_call(identity_header)

      expect(result).to be_a(StirShaken::VerificationResult)
      expect(result.valid?).to be true
      expect(result.attestation).to eq('A')
      expect(result.confidence_level).to eq(100)
      expect(result.certificate).to eq(certificate)
      expect(result.passport).to be_a(StirShaken::Passport)
      expect(result.reason).to be_nil
    end

    it 'validates originating number when provided' do
      result = verification_service.verify_call(
        identity_header,
        originating_number: '+15551234567'
      )

      expect(result.valid?).to be true
    end

    it 'fails when originating number does not match' do
      result = verification_service.verify_call(
        identity_header,
        originating_number: '+15559999999'
      )

      expect(result.valid?).to be false
      expect(result.reason).to include('Originating number mismatch')
    end

    it 'validates destination number when provided' do
      result = verification_service.verify_call(
        identity_header,
        destination_number: '+15559876543'
      )

      expect(result.valid?).to be true
    end

    it 'fails when destination number does not match' do
      result = verification_service.verify_call(
        identity_header,
        destination_number: '+15559999999'
      )

      expect(result.valid?).to be false
      expect(result.reason).to include('Destination number not found')
    end

    it 'validates token age' do
      result = verification_service.verify_call(
        identity_header,
        max_age: 60
      )

      expect(result.valid?).to be true
    end

    it 'fails for expired tokens' do
      # Create an old token by manipulating the passport
      old_passport = StirShaken::Passport.new(
        header: {
          'alg' => 'ES256',
          'typ' => 'passport',
          'ppt' => 'shaken',
          'x5u' => cert_url
        },
        payload: {
          'attest' => 'A',
          'dest' => { 'tn' => ['+15559876543'] },
          'iat' => Time.now.to_i - 120, # 2 minutes ago
          'orig' => { 'tn' => '+15551234567' },
          'origid' => 'test-id'
        }
      )

      old_token = JWT.encode(old_passport.payload, private_key, 'ES256', old_passport.header)
      old_header = StirShaken::SipIdentity.create(
        passport_token: old_token,
        certificate_url: cert_url
      )

      result = verification_service.verify_call(old_header, max_age: 60)

      expect(result.valid?).to be false
      expect(result.reason).to include('expired')
    end

    it 'handles certificate fetch failures' do
      # Clear the mocked certificate
      StirShaken::CertificateManager.clear_cache!
      
      # Mock a failed certificate fetch
      stub_request(:get, cert_url).to_return(status: 404)

      result = verification_service.verify_call(identity_header)

      expect(result.valid?).to be false
      expect(result.reason).to include('Certificate fetch failed')
    end

    it 'handles invalid certificate' do
      # Create certificate that doesn't authorize the number
      unauthorized_cert = create_test_certificate(private_key, telephone_numbers: ['+15559999999'])
      mock_certificate_fetch(cert_url, unauthorized_cert)

      result = verification_service.verify_call(identity_header)

      expect(result.valid?).to be false
      expect(result.reason).to include('not authorized')
    end

    it 'handles signature verification failures' do
      # Create header with different key
      other_key_pair = generate_test_key_pair
      other_auth_service = create_auth_service(
        private_key: other_key_pair[:private_key],
        certificate: certificate,
        cert_url: cert_url
      )
      
      invalid_header = other_auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )

      result = verification_service.verify_call(invalid_header)

      expect(result.valid?).to be false
      expect(result.reason).to include('Signature verification failed')
    end

    it 'updates verification statistics' do
      initial_stats = verification_service.stats
      
      verification_service.verify_call(identity_header)
      
      updated_stats = verification_service.stats
      expect(updated_stats[:total_verifications]).to eq(initial_stats[:total_verifications] + 1)
      expect(updated_stats[:successful_verifications]).to eq(initial_stats[:successful_verifications] + 1)
    end

    it 'tracks failed verifications in statistics' do
      initial_stats = verification_service.stats
      
      # Create invalid header
      result = verification_service.verify_call('invalid-header')
      
      updated_stats = verification_service.stats
      expect(updated_stats[:total_verifications]).to eq(initial_stats[:total_verifications] + 1)
      expect(updated_stats[:failed_verifications]).to eq(initial_stats[:failed_verifications] + 1)
      expect(result.valid?).to be false
    end
  end

  describe '#verify_passport' do
    let(:passport_token) do
      auth_service.create_passport(
        originating_number: '+15551234567',
        destination_numbers: ['+15559876543'],
        attestation: 'A'
      )
    end

    it 'verifies a valid PASSporT token' do
      result = verification_service.verify_passport(passport_token, cert_url)

      expect(result).to be_a(StirShaken::VerificationResult)
      expect(result.valid?).to be true
      expect(result.attestation).to eq('A')
      expect(result.passport).to be_a(StirShaken::Passport)
    end

    it 'validates token age' do
      result = verification_service.verify_passport(passport_token, cert_url, max_age: 60)

      expect(result.valid?).to be true
    end

    it 'fails for expired tokens' do
      # Create old token
      old_payload = {
        'attest' => 'A',
        'dest' => { 'tn' => ['+15559876543'] },
        'iat' => Time.now.to_i - 120, # 2 minutes ago
        'orig' => { 'tn' => '+15551234567' },
        'origid' => 'test-id'
      }

      old_header = {
        'alg' => 'ES256',
        'typ' => 'passport',
        'ppt' => 'shaken',
        'x5u' => cert_url
      }

      old_token = JWT.encode(old_payload, private_key, 'ES256', old_header)

      result = verification_service.verify_passport(old_token, cert_url, max_age: 60)

      expect(result.valid?).to be false
      expect(result.reason).to include('expired')
    end

    it 'handles invalid token format' do
      result = verification_service.verify_passport('invalid-token', cert_url)

      expect(result.valid?).to be false
      expect(result.reason).to include('Invalid token format')
    end

    it 'handles certificate fetch failures' do
      StirShaken::CertificateManager.clear_cache!
      stub_request(:get, cert_url).to_return(status: 404)

      result = verification_service.verify_passport(passport_token, cert_url)

      expect(result.valid?).to be false
      expect(result.reason).to include('Certificate fetch failed')
    end
  end

  describe '#validate_structure' do
    let(:identity_header) do
      auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )
    end

    it 'validates structure of valid header' do
      info = verification_service.validate_structure(identity_header)

      expect(info).to be_a(Hash)
      expect(info[:valid_structure]).to be true
      expect(info[:attestation]).to eq('A')
      expect(info[:attestation_description]).to include('Full Attestation')
      expect(info[:originating_number]).to eq('+15551234567')
      expect(info[:destination_numbers]).to eq(['+15559876543'])
      expect(info[:certificate_url]).to eq(cert_url)
      expect(info[:algorithm]).to eq('ES256')
      expect(info[:extension]).to eq('shaken')
      expect(info[:issued_at]).to be_a(Integer)
      expect(info[:origination_id]).to be_a(String)
    end

    it 'handles invalid header structure' do
      info = verification_service.validate_structure('invalid-header')

      expect(info[:valid_structure]).to be false
      expect(info[:error]).to be_a(String)
    end

    it 'handles malformed JWT tokens' do
      malformed_header = 'malformed.jwt.token;info=<https://example.com>;alg=ES256;ppt=shaken'
      info = verification_service.validate_structure(malformed_header)

      expect(info[:valid_structure]).to be false
      expect(info[:error]).to include('token')
    end

    it 'provides detailed information for valid structures' do
      info = verification_service.validate_structure(identity_header)

      expect(info).to have_key(:valid_structure)
      expect(info).to have_key(:attestation)
      expect(info).to have_key(:attestation_description)
      expect(info).to have_key(:originating_number)
      expect(info).to have_key(:destination_numbers)
      expect(info).to have_key(:certificate_url)
      expect(info).to have_key(:algorithm)
      expect(info).to have_key(:extension)
      expect(info).to have_key(:issued_at)
      expect(info).to have_key(:origination_id)
    end
  end

  describe '#stats' do
    it 'returns verification statistics' do
      stats = verification_service.stats

      expect(stats).to be_a(Hash)
      expect(stats).to have_key(:total_verifications)
      expect(stats).to have_key(:successful_verifications)
      expect(stats).to have_key(:failed_verifications)
      expect(stats).to have_key(:success_rate)
    end

    it 'calculates success rate correctly' do
      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )

      # Perform some verifications
      verification_service.verify_call(identity_header) # Success
      verification_service.verify_call('invalid') # Failure
      verification_service.verify_call(identity_header) # Success

      stats = verification_service.stats
      expect(stats[:total_verifications]).to eq(3)
      expect(stats[:successful_verifications]).to eq(2)
      expect(stats[:failed_verifications]).to eq(1)
      expect(stats[:success_rate]).to be_within(0.01).of(66.67)
    end

    it 'handles zero verifications' do
      stats = verification_service.stats
      expect(stats[:success_rate]).to eq(0.0)
    end
  end

  describe 'VerificationResult' do
    let(:passport) do
      token = auth_service.create_passport(
        originating_number: '+15551234567',
        destination_numbers: ['+15559876543'],
        attestation: 'A'
      )
      StirShaken::Passport.parse(token, verify_signature: false)
    end

    describe 'successful result' do
      let(:result) do
        StirShaken::VerificationResult.new(
          valid: true,
          attestation: 'A',
          certificate: certificate,
          passport: passport
        )
      end

      it 'indicates success' do
        expect(result.valid?).to be true
        expect(result.attestation).to eq('A')
        expect(result.confidence_level).to eq(100)
        expect(result.certificate).to eq(certificate)
        expect(result.passport).to eq(passport)
        expect(result.reason).to be_nil
      end

      it 'provides confidence level based on attestation' do
        result_b = StirShaken::VerificationResult.new(
          valid: true,
          attestation: 'B',
          certificate: certificate,
          passport: passport
        )

        result_c = StirShaken::VerificationResult.new(
          valid: true,
          attestation: 'C',
          certificate: certificate,
          passport: passport
        )

        expect(result.confidence_level).to eq(100) # A
        expect(result_b.confidence_level).to eq(75) # B
        expect(result_c.confidence_level).to eq(50) # C
      end
    end

    describe 'failed result' do
      let(:result) do
        StirShaken::VerificationResult.new(
          valid: false,
          reason: 'Test failure reason'
        )
      end

      it 'indicates failure' do
        expect(result.valid?).to be false
        expect(result.reason).to eq('Test failure reason')
        expect(result.confidence_level).to eq(0)
        expect(result.attestation).to be_nil
        expect(result.certificate).to be_nil
        expect(result.passport).to be_nil
      end
    end
  end

  describe 'integration tests' do
    it 'verifies calls with all attestation levels' do
      %w[A B C].each do |attestation|
        identity_header = auth_service.sign_call(
          originating_number: '+15551234567',
          destination_number: '+15559876543',
          attestation: attestation
        )

        result = verification_service.verify_call(identity_header)

        expect(result.valid?).to be true
        expect(result.attestation).to eq(attestation)
        expect(result.confidence_level).to eq(StirShaken::Attestation.confidence_level(attestation))
      end
    end

    it 'handles multiple destination numbers' do
      destinations = ['+15559876543', '+15551111111', '+15552222222']
      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: destinations,
        attestation: 'A'
      )

      result = verification_service.verify_call(identity_header)

      expect(result.valid?).to be true
      expect(result.passport.destination_numbers).to eq(destinations)

      # Verify each destination individually
      destinations.each do |dest|
        result = verification_service.verify_call(
          identity_header,
          destination_number: dest
        )
        expect(result.valid?).to be true
      end
    end

    it 'maintains consistency across verification methods' do
      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )

      # Extract passport token from header
      sip_identity = StirShaken::SipIdentity.parse(identity_header)
      passport_token = sip_identity.passport_token

      # Verify using both methods
      call_result = verification_service.verify_call(identity_header)
      passport_result = verification_service.verify_passport(passport_token, cert_url)

      expect(call_result.valid?).to eq(passport_result.valid?)
      expect(call_result.attestation).to eq(passport_result.attestation)
      expect(call_result.confidence_level).to eq(passport_result.confidence_level)
    end
  end

  describe 'error handling edge cases' do
    it 'handles nil input gracefully' do
      result = verification_service.verify_call(nil)
      expect(result.valid?).to be false
      expect(result.reason).to include('Invalid')
    end

    it 'handles empty string input' do
      result = verification_service.verify_call('')
      expect(result.valid?).to be false
      expect(result.reason).to include('Invalid')
    end

    it 'handles malformed SIP headers' do
      malformed_headers = [
        'just-a-token',
        'token;missing=params',
        'token;info=missing-alg-ppt',
        ';info=<url>;alg=ES256;ppt=shaken' # Missing token
      ]

      malformed_headers.each do |header|
        result = verification_service.verify_call(header)
        expect(result.valid?).to be false
        expect(result.reason).to be_a(String)
      end
    end

    it 'handles certificate validation edge cases' do
      # Test with expired certificate
      expired_cert = create_test_certificate(private_key, telephone_numbers: ['+15551234567'])
      expired_cert.not_after = Time.now - 1
      expired_cert.sign(private_key, OpenSSL::Digest::SHA256.new)
      
      mock_certificate_fetch(cert_url, expired_cert)

      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )

      result = verification_service.verify_call(identity_header)
      expect(result.valid?).to be false
      expect(result.reason).to include('Certificate validation failed')
    end
  end

  describe 'performance considerations' do
    it 'can verify multiple calls efficiently' do
      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )

      start_time = Time.now
      
      100.times do
        verification_service.verify_call(identity_header)
      end
      
      elapsed = Time.now - start_time
      expect(elapsed).to be < 10.0 # Should complete in under 10 seconds
    end

    context 'with HTTP-based certificate fetching' do
      # Skip the global certificate mocking for these tests
      before do
        StirShaken::CertificateManager.clear_cache!
        # Don't call mock_certificate_fetch here - use HTTP mocking instead
      end

      it 'benefits from certificate caching' do
        # Use HTTP mocking instead of direct cache manipulation
        stub_request(:get, cert_url)
          .to_return(status: 200, body: certificate.to_pem, headers: { 'Content-Type' => 'application/x-pem-file' })
        
        identity_header = auth_service.sign_call(
          originating_number: '+15551234567',
          destination_number: '+15559876543',
          attestation: 'A'
        )

        # Track cache statistics instead of timing
        initial_stats = StirShaken::CertificateManager.cache_stats
        
        # First verification should populate cache (cache miss)
        verification_service.verify_call(identity_header)
        after_first_stats = StirShaken::CertificateManager.cache_stats
        
        # Second verification should use cached certificate (cache hit)
        verification_service.verify_call(identity_header)
        after_second_stats = StirShaken::CertificateManager.cache_stats

        # Verify cache behavior: 
        # - Cache size should increase after first call
        # - Misses should increase by 1 after first call
        # - Hits should increase by 1 after second call
        # - Cache size should remain the same after second call
        expect(after_first_stats[:size]).to be > initial_stats[:size]
        expect(after_first_stats[:misses]).to eq(initial_stats[:misses] + 1)
        expect(after_second_stats[:hits]).to eq(after_first_stats[:hits] + 1)
        expect(after_second_stats[:size]).to eq(after_first_stats[:size])
      end

      it 'maintains cache efficiency across different certificates' do
        # Test with multiple different certificates
        cert_urls = [
          'https://example.com/cert1.pem',
          'https://example.com/cert2.pem',
          'https://example.com/cert3.pem'
        ]
        
        initial_stats = StirShaken::CertificateManager.cache_stats
        
        cert_urls.each_with_index do |url, index|
          # Mock HTTP response for each certificate URL
          stub_request(:get, url)
            .to_return(status: 200, body: certificate.to_pem, headers: { 'Content-Type' => 'application/x-pem-file' })
          
          # Create verification service with different cert URL
          service = StirShaken::VerificationService.new
          
          identity_header = auth_service.sign_call(
            originating_number: '+15551234567',
            destination_number: '+15559876543',
            attestation: 'A'
          )
          
          # Replace cert URL in the header
          modified_header = identity_header.gsub(cert_url, url)
          
          # First verification should add to cache
          service.verify_call(modified_header)
          current_stats = StirShaken::CertificateManager.cache_stats
          expect(current_stats[:size]).to eq(initial_stats[:size] + index + 1)
          
          # Second verification should use cache
          service.verify_call(modified_header)
          expect(StirShaken::CertificateManager.cache_stats[:size]).to eq(current_stats[:size])
        end
      end
    end

    it 'demonstrates performance improvement with multiple verifications' do
      identity_header = auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )

      # Measure time for batch of verifications (more stable than single calls)
      iterations = 50
      
      # First batch - may include cache misses
      start_time = Time.now
      iterations.times { verification_service.verify_call(identity_header) }
      first_batch_time = Time.now - start_time
      
      # Second batch - should benefit from caching
      start_time = Time.now
      iterations.times { verification_service.verify_call(identity_header) }
      second_batch_time = Time.now - start_time
      
      # Second batch should be at least as fast (allowing for some variance)
      # Use a tolerance to account for system variability
      tolerance_factor = 1.5 # Allow up to 50% variance
      expect(second_batch_time).to be <= (first_batch_time * tolerance_factor)
      
      # Also verify both batches complete in reasonable time
      expect(first_batch_time).to be < 5.0
      expect(second_batch_time).to be < 5.0
    end
  end
end 