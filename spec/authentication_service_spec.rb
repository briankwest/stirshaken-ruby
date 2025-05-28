# frozen_string_literal: true

require 'spec_helper'

RSpec.describe StirShaken::AuthenticationService do
  let(:key_pair) { generate_test_key_pair }
  let(:private_key) { key_pair[:private_key] }
  let(:public_key) { key_pair[:public_key] }
  let(:certificate) { create_test_certificate(private_key, telephone_numbers: ['+15551234567']) }
  let(:cert_url) { 'https://test.example.com/cert.pem' }

  describe '.generate_key_pair' do
    it 'generates a valid EC key pair' do
      key_pair = StirShaken::AuthenticationService.generate_key_pair
      
      expect(key_pair).to be_a(Hash)
      expect(key_pair).to have_key(:private_key)
      expect(key_pair).to have_key(:public_key)
      
      private_key = key_pair[:private_key]
      public_key = key_pair[:public_key]
      
      expect(private_key).to be_a(OpenSSL::PKey::EC)
      expect(public_key).to be_a(OpenSSL::PKey::EC)
      expect(private_key.group.curve_name).to eq('prime256v1')
      expect(public_key.group.curve_name).to eq('prime256v1')
    end

    it 'generates different keys each time' do
      key_pair1 = StirShaken::AuthenticationService.generate_key_pair
      key_pair2 = StirShaken::AuthenticationService.generate_key_pair
      
      expect(key_pair1[:private_key].to_pem).not_to eq(key_pair2[:private_key].to_pem)
    end
  end

  describe '.create_test_certificate' do
    it 'creates a valid self-signed certificate' do
      cert = StirShaken::AuthenticationService.create_test_certificate(
        private_key,
        subject: '/CN=Test Certificate',
        telephone_numbers: ['+15551234567']
      )
      
      expect(cert).to be_a(OpenSSL::X509::Certificate)
      expect(cert.subject.to_s).to include('Test Certificate')
      expect(cert.issuer).to eq(cert.subject) # Self-signed
    end

    it 'includes telephone numbers in SAN extension' do
      numbers = ['+15551234567', '+15559876543']
      cert = StirShaken::AuthenticationService.create_test_certificate(
        private_key,
        telephone_numbers: numbers
      )
      
      san_ext = cert.extensions.find { |ext| ext.oid == 'subjectAltName' }
      expect(san_ext).not_to be_nil
      
      numbers.each do |number|
        expect(san_ext.value).to include("URI:tel:#{number}")
      end
    end

    it 'sets appropriate validity period' do
      cert = StirShaken::AuthenticationService.create_test_certificate(private_key)
      
      expect(cert.not_before).to be <= Time.now
      expect(cert.not_after).to be > Time.now
      expect(cert.not_after - cert.not_before).to be >= 365 * 24 * 60 * 60 # At least 1 year
    end

    it 'includes digital signature key usage' do
      cert = StirShaken::AuthenticationService.create_test_certificate(private_key)
      
      key_usage_ext = cert.extensions.find { |ext| ext.oid == 'keyUsage' }
      expect(key_usage_ext).not_to be_nil
      expect(key_usage_ext.value).to include('Digital Signature')
    end
  end

  describe '#initialize' do
    it 'creates service with valid parameters' do
      service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url
      )
      
      expect(service.private_key).to eq(private_key)
      expect(service.certificate_url).to eq(cert_url)
    end

    it 'accepts optional certificate parameter' do
      service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: cert_url,
        certificate: certificate
      )
      
      expect(service.certificate).to eq(certificate)
    end

    it 'validates private key type' do
      rsa_key = OpenSSL::PKey::RSA.new(2048)
      
      expect {
        StirShaken::AuthenticationService.new(
          private_key: rsa_key,
          certificate_url: cert_url
        )
      }.to raise_error(StirShaken::ConfigurationError, /must be an EC key/)
    end

    it 'validates private key curve' do
      wrong_curve_key = OpenSSL::PKey::EC.generate('secp384r1')
      
      expect {
        StirShaken::AuthenticationService.new(
          private_key: wrong_curve_key,
          certificate_url: cert_url
        )
      }.to raise_error(StirShaken::ConfigurationError, /must use P-256 curve/)
    end

    it 'validates that key is private' do
      # Create a public-only key by extracting the public key from the private key
      public_key_pem = private_key.public_to_pem
      public_only_key = OpenSSL::PKey::EC.new(public_key_pem)
      
      expect {
        StirShaken::AuthenticationService.new(
          private_key: public_only_key,
          certificate_url: cert_url
        )
      }.to raise_error(StirShaken::ConfigurationError, /must be a private key/)
    end
  end

  describe '#sign_call' do
    let(:service) { create_auth_service(private_key: private_key, certificate: certificate) }
    let(:originating_number) { '+15551234567' }
    let(:destination_number) { '+15559876543' }

    it 'signs a call and returns SIP Identity header' do
      identity_header = service.sign_call(
        originating_number: originating_number,
        destination_number: destination_number,
        attestation: 'A'
      )
      
      expect(identity_header).to be_a(String)
      expect(identity_header).to include('eyJ') # JWT token
      expect(identity_header).to include('info=')
      expect(identity_header).to include('alg=ES256')
      expect(identity_header).to include('ppt=shaken')
    end

    it 'handles single destination number' do
      identity_header = service.sign_call(
        originating_number: originating_number,
        destination_number: destination_number,
        attestation: 'A'
      )
      
      sip_identity = StirShaken::SipIdentity.parse(identity_header)
      passport = sip_identity.parse_passport(verify_signature: false)
      
      expect(passport.destination_numbers).to eq([destination_number])
    end

    it 'handles multiple destination numbers' do
      destinations = ['+15559876543', '+15551111111']
      identity_header = service.sign_call(
        originating_number: originating_number,
        destination_number: destinations,
        attestation: 'A'
      )
      
      sip_identity = StirShaken::SipIdentity.parse(identity_header)
      passport = sip_identity.parse_passport(verify_signature: false)
      
      expect(passport.destination_numbers).to eq(destinations)
    end

    it 'accepts custom origination_id' do
      custom_id = 'custom-call-123'
      identity_header = service.sign_call(
        originating_number: originating_number,
        destination_number: destination_number,
        attestation: 'A',
        origination_id: custom_id
      )
      
      sip_identity = StirShaken::SipIdentity.parse(identity_header)
      passport = sip_identity.parse_passport(verify_signature: false)
      
      expect(passport.origination_id).to eq(custom_id)
    end

    it 'accepts additional info for SIP header' do
      additional_info = { 'custom' => 'value' }
      identity_header = service.sign_call(
        originating_number: originating_number,
        destination_number: destination_number,
        attestation: 'A',
        additional_info: additional_info
      )
      
      expect(identity_header).to include('custom=value')
    end

    it 'validates attestation level' do
      expect {
        service.sign_call(
          originating_number: originating_number,
          destination_number: destination_number,
          attestation: 'X'
        )
      }.to raise_error(StirShaken::InvalidAttestationError)
    end

    it 'works with all valid attestation levels' do
      %w[A B C].each do |attestation|
        identity_header = service.sign_call(
          originating_number: originating_number,
          destination_number: destination_number,
          attestation: attestation
        )
        
        sip_identity = StirShaken::SipIdentity.parse(identity_header)
        passport = sip_identity.parse_passport(verify_signature: false)
        
        expect(passport.attestation).to eq(attestation)
      end
    end
  end

  describe '#create_passport' do
    let(:service) { create_auth_service(private_key: private_key) }

    it 'creates a PASSporT token' do
      token = service.create_passport(
        originating_number: '+15551234567',
        destination_numbers: ['+15559876543'],
        attestation: 'A'
      )
      
      expect(token).to be_a(String)
      expect(token.count('.')).to eq(2) # JWT format
    end

    it 'handles multiple destination numbers' do
      destinations = ['+15559876543', '+15551111111']
      token = service.create_passport(
        originating_number: '+15551234567',
        destination_numbers: destinations,
        attestation: 'A'
      )
      
      passport = StirShaken::Passport.parse(token, verify_signature: false)
      expect(passport.destination_numbers).to eq(destinations)
    end

    it 'accepts custom origination_id' do
      custom_id = 'test-id-123'
      token = service.create_passport(
        originating_number: '+15551234567',
        destination_numbers: ['+15559876543'],
        attestation: 'A',
        origination_id: custom_id
      )
      
      passport = StirShaken::Passport.parse(token, verify_signature: false)
      expect(passport.origination_id).to eq(custom_id)
    end
  end

  describe '#authorized_for_number?' do
    let(:service) { create_auth_service(private_key: private_key, certificate: certificate) }

    it 'returns true when certificate authorizes the number' do
      # Certificate was created with +15551234567
      expect(service.authorized_for_number?('+15551234567')).to be true
    end

    it 'returns false when certificate does not authorize the number' do
      expect(service.authorized_for_number?('+15559876543')).to be false
    end

    it 'returns true when no certificate is provided' do
      service_without_cert = create_auth_service(private_key: private_key, certificate: nil)
      expect(service_without_cert.authorized_for_number?('+15551234567')).to be true
    end
  end

  describe '#load_certificate' do
    let(:service) { create_auth_service(private_key: private_key) }

    before do
      stub_request(:get, cert_url)
        .to_return(status: 200, body: certificate.to_pem)
    end

    it 'loads certificate from URL' do
      cert = service.load_certificate
      expect(cert).to be_a(OpenSSL::X509::Certificate)
      expect(service.certificate).to eq(cert)
    end

    it 'supports force refresh' do
      service.load_certificate
      
      # Should make another HTTP request
      expect(HTTParty).to receive(:get).and_call_original
      service.load_certificate(force_refresh: true)
    end
  end

  describe '#certificate_valid?' do
    let(:service) { create_auth_service(private_key: private_key, certificate: certificate) }

    it 'returns true for valid certificate' do
      expect(service.certificate_valid?).to be true
    end

    it 'returns false when no certificate is loaded' do
      service_without_cert = create_auth_service(private_key: private_key, certificate: nil)
      expect(service_without_cert.certificate_valid?).to be false
    end

    it 'returns false for expired certificate' do
      expired_cert = create_test_certificate(private_key)
      expired_cert.not_after = Time.now - 1
      expired_cert.sign(private_key, OpenSSL::Digest::SHA256.new)
      
      service_with_expired = create_auth_service(private_key: private_key, certificate: expired_cert)
      expect(service_with_expired.certificate_valid?).to be false
    end
  end

  describe '#info' do
    let(:service) { create_auth_service(private_key: private_key, certificate: certificate) }

    it 'returns service information' do
      info = service.info
      
      expect(info).to be_a(Hash)
      expect(info[:certificate_url]).to eq(cert_url)
      expect(info[:algorithm]).to eq('ES256')
      expect(info[:extension]).to eq('shaken')
      expect(info[:has_certificate]).to be true
      expect(info[:certificate_valid]).to be true
    end

    it 'handles missing certificate' do
      service_without_cert = create_auth_service(private_key: private_key, certificate: nil)
      info = service_without_cert.info
      
      expect(info[:has_certificate]).to be false
      expect(info[:certificate_valid]).to be_nil
    end
  end

  describe 'integration tests' do
    let(:service) { create_auth_service(private_key: private_key, certificate: certificate) }

    it 'creates verifiable tokens' do
      identity_header = service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A'
      )
      
      sip_identity = StirShaken::SipIdentity.parse(identity_header)
      passport = sip_identity.parse_passport(public_key: public_key, verify_signature: true)
      
      expect(passport.originating_number).to eq('+15551234567')
      expect(passport.destination_numbers).to eq(['+15559876543'])
      expect(passport.attestation).to eq('A')
    end

    it 'maintains consistency between sign_call and create_passport' do
      # Create using both methods with same parameters
      identity_header = service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A',
        origination_id: 'test-123'
      )
      
      passport_token = service.create_passport(
        originating_number: '+15551234567',
        destination_numbers: ['+15559876543'],
        attestation: 'A',
        origination_id: 'test-123'
      )
      
      # Extract passport from identity header
      sip_identity = StirShaken::SipIdentity.parse(identity_header)
      passport_from_header = sip_identity.parse_passport(verify_signature: false)
      
      # Parse standalone passport
      passport_standalone = StirShaken::Passport.parse(passport_token, verify_signature: false)
      
      # Should have same core data
      expect(passport_from_header.originating_number).to eq(passport_standalone.originating_number)
      expect(passport_from_header.destination_numbers).to eq(passport_standalone.destination_numbers)
      expect(passport_from_header.attestation).to eq(passport_standalone.attestation)
      expect(passport_from_header.origination_id).to eq(passport_standalone.origination_id)
    end

    it 'handles edge cases in phone number validation' do
      valid_numbers = [
        '+15551234567',
        '+442071234567',
        '+33123456789',
        '+8613812345678'
      ]

      valid_numbers.each do |number|
        expect {
          service.sign_call(
            originating_number: number,
            destination_number: '+15559876543',
            attestation: 'A'
          )
        }.not_to raise_error
      end
    end

    it 'rejects invalid phone numbers' do
      invalid_numbers = [
        'invalid',
        '123',
        '+',
        '++15551234567',
        '15551234567'
      ]

      invalid_numbers.each do |number|
        expect {
          service.sign_call(
            originating_number: number,
            destination_number: '+15559876543',
            attestation: 'A'
          )
        }.to raise_error(StirShaken::InvalidPhoneNumberError)
      end
    end
  end

  describe 'performance considerations' do
    let(:service) { create_auth_service(private_key: private_key, certificate: certificate) }

    it 'can sign multiple calls efficiently' do
      start_time = Time.now
      
      100.times do |i|
        service.sign_call(
          originating_number: '+15551234567',
          destination_number: '+15559876543',
          attestation: 'A',
          origination_id: "call-#{i}"
        )
      end
      
      elapsed = Time.now - start_time
      expect(elapsed).to be < 5.0 # Should complete in under 5 seconds
    end
  end

  describe 'error handling' do
    it 'provides meaningful error messages for configuration issues' do
      expect {
        StirShaken::AuthenticationService.new(
          private_key: 'not-a-key',
          certificate_url: cert_url
        )
      }.to raise_error(StirShaken::ConfigurationError)
    end

    it 'handles certificate loading failures gracefully' do
      service = create_auth_service(private_key: private_key)
      
      stub_request(:get, cert_url).to_return(status: 404)
      
      expect {
        service.load_certificate
      }.to raise_error(StirShaken::CertificateFetchError)
    end
  end
end 