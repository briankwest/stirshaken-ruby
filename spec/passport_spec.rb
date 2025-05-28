# frozen_string_literal: true

require 'spec_helper'

RSpec.describe StirShaken::Passport do
  let(:key_pair) { generate_test_key_pair }
  let(:private_key) { key_pair[:private_key] }
  let(:public_key) { key_pair[:public_key] }
  let(:certificate_url) { 'https://test.example.com/cert.pem' }
  let(:originating_number) { '+15551234567' }
  let(:destination_numbers) { ['+15559876543'] }
  let(:attestation) { 'A' }

  describe 'constants' do
    it 'defines required constants' do
      expect(StirShaken::Passport::ALGORITHM).to eq('ES256')
      expect(StirShaken::Passport::TOKEN_TYPE).to eq('passport')
      expect(StirShaken::Passport::EXTENSION).to eq('shaken')
    end
  end

  describe '.create' do
    it 'creates a valid PASSporT token' do
      token = StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        certificate_url: certificate_url,
        private_key: private_key
      )

      expect(token).to be_a(String)
      expect(token.count('.')).to eq(2) # JWT format: header.payload.signature
    end

    it 'creates token with custom origination_id' do
      custom_id = 'custom-call-id-123'
      token = StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        origination_id: custom_id,
        certificate_url: certificate_url,
        private_key: private_key
      )

      passport = StirShaken::Passport.parse(token, verify_signature: false)
      expect(passport.origination_id).to eq(custom_id)
    end

    it 'generates UUID origination_id when not provided' do
      token = StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        certificate_url: certificate_url,
        private_key: private_key
      )

      passport = StirShaken::Passport.parse(token, verify_signature: false)
      expect(passport.origination_id).to match(/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i)
    end

    it 'handles multiple destination numbers' do
      destinations = ['+15559876543', '+15551111111', '+15552222222']
      token = StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: destinations,
        attestation: attestation,
        certificate_url: certificate_url,
        private_key: private_key
      )

      passport = StirShaken::Passport.parse(token, verify_signature: false)
      expect(passport.destination_numbers).to eq(destinations)
    end

    it 'validates attestation level' do
      expect {
        StirShaken::Passport.create(
          originating_number: originating_number,
          destination_numbers: destination_numbers,
          attestation: 'X', # Invalid
          certificate_url: certificate_url,
          private_key: private_key
        )
      }.to raise_error(StirShaken::InvalidAttestationError)
    end

    it 'validates originating phone number' do
      expect {
        StirShaken::Passport.create(
          originating_number: 'invalid-number',
          destination_numbers: destination_numbers,
          attestation: attestation,
          certificate_url: certificate_url,
          private_key: private_key
        )
      }.to raise_error(StirShaken::InvalidPhoneNumberError)
    end

    it 'validates destination phone numbers' do
      expect {
        StirShaken::Passport.create(
          originating_number: originating_number,
          destination_numbers: ['invalid-number'],
          attestation: attestation,
          certificate_url: certificate_url,
          private_key: private_key
        )
      }.to raise_error(StirShaken::InvalidPhoneNumberError)
    end

    it 'creates token with correct header' do
      token = StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        certificate_url: certificate_url,
        private_key: private_key
      )

      passport = StirShaken::Passport.parse(token, verify_signature: false)
      expect(passport.header['alg']).to eq('ES256')
      expect(passport.header['typ']).to eq('passport')
      expect(passport.header['ppt']).to eq('shaken')
      expect(passport.header['x5u']).to eq(certificate_url)
    end

    it 'creates token with correct payload structure' do
      token = StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        certificate_url: certificate_url,
        private_key: private_key
      )

      passport = StirShaken::Passport.parse(token, verify_signature: false)
      expect(passport.payload).to have_key('attest')
      expect(passport.payload).to have_key('dest')
      expect(passport.payload).to have_key('iat')
      expect(passport.payload).to have_key('orig')
      expect(passport.payload).to have_key('origid')
    end

    it 'sets issued at timestamp' do
      before_time = Time.now.to_i
      token = StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        certificate_url: certificate_url,
        private_key: private_key
      )
      after_time = Time.now.to_i

      passport = StirShaken::Passport.parse(token, verify_signature: false)
      expect(passport.issued_at).to be >= before_time
      expect(passport.issued_at).to be <= after_time
    end
  end

  describe '.parse' do
    let(:token) do
      StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        certificate_url: certificate_url,
        private_key: private_key
      )
    end

    it 'parses a valid token without verification' do
      passport = StirShaken::Passport.parse(token, verify_signature: false)
      
      expect(passport).to be_a(StirShaken::Passport)
      expect(passport.originating_number).to eq(originating_number)
      expect(passport.destination_numbers).to eq(destination_numbers)
      expect(passport.attestation).to eq(attestation)
      expect(passport.certificate_url).to eq(certificate_url)
    end

    it 'parses and verifies a valid token with public key' do
      passport = StirShaken::Passport.parse(token, public_key: public_key, verify_signature: true)
      
      expect(passport).to be_a(StirShaken::Passport)
      expect(passport.originating_number).to eq(originating_number)
    end

    it 'raises error for invalid JWT format' do
      expect {
        StirShaken::Passport.parse('invalid.jwt', verify_signature: false)
      }.to raise_error(StirShaken::InvalidTokenError)
    end

    it 'raises error for malformed JWT' do
      expect {
        StirShaken::Passport.parse('not-a-jwt-token', verify_signature: false)
      }.to raise_error(StirShaken::InvalidTokenError)
    end

    it 'raises error for signature verification failure' do
      other_key_pair = generate_test_key_pair
      wrong_public_key = other_key_pair[:public_key]

      expect {
        StirShaken::Passport.parse(token, public_key: wrong_public_key, verify_signature: true)
      }.to raise_error(StirShaken::InvalidTokenError)
    end
  end

  describe '#validate!' do
    let(:passport) do
      token = StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        certificate_url: certificate_url,
        private_key: private_key
      )
      StirShaken::Passport.parse(token, verify_signature: false)
    end

    it 'validates a correct PASSporT' do
      expect { passport.validate! }.not_to raise_error
    end

    it 'validates header algorithm' do
      passport.instance_variable_get(:@header)['alg'] = 'RS256'
      expect {
        passport.validate!
      }.to raise_error(StirShaken::PassportValidationError, /Invalid algorithm/)
    end

    it 'validates header type' do
      passport.instance_variable_get(:@header)['typ'] = 'jwt'
      expect {
        passport.validate!
      }.to raise_error(StirShaken::PassportValidationError, /Invalid type/)
    end

    it 'validates header extension' do
      passport.instance_variable_get(:@header)['ppt'] = 'invalid'
      expect {
        passport.validate!
      }.to raise_error(StirShaken::PassportValidationError, /Invalid extension/)
    end

    it 'validates certificate URL presence' do
      passport.instance_variable_get(:@header).delete('x5u')
      expect {
        passport.validate!
      }.to raise_error(StirShaken::PassportValidationError, /Missing certificate URL/)
    end

    it 'validates required payload claims' do
      required_claims = ['attest', 'dest', 'iat', 'orig', 'origid']
      
      required_claims.each do |claim|
        passport_copy = StirShaken::Passport.parse(
          StirShaken::Passport.create(
            originating_number: originating_number,
            destination_numbers: destination_numbers,
            attestation: attestation,
            certificate_url: certificate_url,
            private_key: private_key
          ),
          verify_signature: false
        )
        
        passport_copy.instance_variable_get(:@payload).delete(claim)
        expect {
          passport_copy.validate!
        }.to raise_error(StirShaken::PassportValidationError, /Missing.*#{claim.gsub('_', ' ')}/)
      end
    end
  end

  describe 'accessor methods' do
    let(:passport) do
      token = StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        certificate_url: certificate_url,
        private_key: private_key
      )
      StirShaken::Passport.parse(token, verify_signature: false)
    end

    it 'provides access to originating number' do
      expect(passport.originating_number).to eq(originating_number)
    end

    it 'provides access to destination numbers' do
      expect(passport.destination_numbers).to eq(destination_numbers)
    end

    it 'provides access to attestation' do
      expect(passport.attestation).to eq(attestation)
    end

    it 'provides access to origination ID' do
      expect(passport.origination_id).to be_a(String)
      expect(passport.origination_id).not_to be_empty
    end

    it 'provides access to issued at timestamp' do
      expect(passport.issued_at).to be_a(Integer)
      expect(passport.issued_at).to be > 0
    end

    it 'provides access to certificate URL' do
      expect(passport.certificate_url).to eq(certificate_url)
    end
  end

  describe '#expired?' do
    it 'returns false for fresh token' do
      token = StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        certificate_url: certificate_url,
        private_key: private_key
      )
      passport = StirShaken::Passport.parse(token, verify_signature: false)
      
      expect(passport.expired?).to be false
    end

    it 'returns true for old token' do
      # Create a passport with old timestamp
      passport = StirShaken::Passport.new(
        header: {
          'alg' => 'ES256',
          'typ' => 'passport',
          'ppt' => 'shaken',
          'x5u' => certificate_url
        },
        payload: {
          'attest' => attestation,
          'dest' => { 'tn' => destination_numbers },
          'iat' => Time.now.to_i - 120, # 2 minutes ago
          'orig' => { 'tn' => originating_number },
          'origid' => 'test-id'
        }
      )
      
      expect(passport.expired?(max_age: 60)).to be true
    end

    it 'uses custom max_age parameter' do
      passport = StirShaken::Passport.new(
        header: {
          'alg' => 'ES256',
          'typ' => 'passport',
          'ppt' => 'shaken',
          'x5u' => certificate_url
        },
        payload: {
          'attest' => attestation,
          'dest' => { 'tn' => destination_numbers },
          'iat' => Time.now.to_i - 30, # 30 seconds ago
          'orig' => { 'tn' => originating_number },
          'origid' => 'test-id'
        }
      )
      
      expect(passport.expired?(max_age: 60)).to be false
      expect(passport.expired?(max_age: 15)).to be true
    end

    it 'returns true when issued_at is missing' do
      passport = StirShaken::Passport.new(
        header: {},
        payload: {}
      )
      
      expect(passport.expired?).to be true
    end
  end

  describe '#to_h' do
    let(:passport) do
      token = StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        certificate_url: certificate_url,
        private_key: private_key
      )
      StirShaken::Passport.parse(token, verify_signature: false)
    end

    it 'returns hash representation' do
      hash = passport.to_h
      
      expect(hash).to be_a(Hash)
      expect(hash[:originating_number]).to eq(originating_number)
      expect(hash[:destination_numbers]).to eq(destination_numbers)
      expect(hash[:attestation]).to eq(attestation)
      expect(hash[:certificate_url]).to eq(certificate_url)
      expect(hash[:header]).to be_a(Hash)
      expect(hash[:payload]).to be_a(Hash)
    end
  end

  describe '.validate_phone_number!' do
    it 'accepts valid E.164 phone numbers' do
      valid_numbers = [
        '+15551234567',
        '+442071234567',
        '+33123456789',
        '+8613812345678',
        '+12125551234'
      ]

      valid_numbers.each do |number|
        expect {
          StirShaken::Passport.validate_phone_number!(number)
        }.not_to raise_error
      end
    end

    it 'rejects invalid phone numbers' do
      invalid_numbers = [
        'invalid',
        '123',
        'abc123',
        '+',
        '++15551234567',
        '15551234567', # Missing +
        '+0123456789', # Starts with 0
        '+1234567890123456', # Too long
        '+1' # Too short
      ]

      invalid_numbers.each do |number|
        expect {
          StirShaken::Passport.validate_phone_number!(number)
        }.to raise_error(StirShaken::InvalidPhoneNumberError)
      end
    end
  end

  describe 'integration tests' do
    it 'creates and parses token with all attestation levels' do
      %w[A B C].each do |level|
        token = StirShaken::Passport.create(
          originating_number: originating_number,
          destination_numbers: destination_numbers,
          attestation: level,
          certificate_url: certificate_url,
          private_key: private_key
        )

        passport = StirShaken::Passport.parse(token, public_key: public_key, verify_signature: true)
        expect(passport.attestation).to eq(level)
      end
    end

    it 'maintains data integrity through create/parse cycle' do
      original_data = {
        originating_number: '+15551234567',
        destination_numbers: ['+15559876543', '+15551111111'],
        attestation: 'B',
        origination_id: 'test-call-123'
      }

      token = StirShaken::Passport.create(
        **original_data,
        certificate_url: certificate_url,
        private_key: private_key
      )

      passport = StirShaken::Passport.parse(token, verify_signature: false)

      expect(passport.originating_number).to eq(original_data[:originating_number])
      expect(passport.destination_numbers).to eq(original_data[:destination_numbers])
      expect(passport.attestation).to eq(original_data[:attestation])
      expect(passport.origination_id).to eq(original_data[:origination_id])
    end
  end
end 