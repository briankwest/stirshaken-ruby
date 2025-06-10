# frozen_string_literal: true

require 'spec_helper'

RSpec.describe StirShaken::DivPassport do
  let(:key_pair) { generate_test_key_pair }
  let(:private_key) { key_pair[:private_key] }
  let(:public_key) { key_pair[:public_key] }
  let(:certificate_url) { 'https://test.example.com/cert.pem' }
  let(:originating_number) { '+15551234567' }
  let(:original_destination) { '+15551111111' }
  let(:new_destination) { '+15559876543' }
  let(:diversion_reason) { 'forwarding' }

  # Create a sample original SHAKEN PASSporT
  let(:original_passport) do
    token = StirShaken::Passport.create(
      originating_number: originating_number,
      destination_numbers: [original_destination],
      attestation: 'A',
      certificate_url: certificate_url,
      private_key: private_key
    )
    StirShaken::Passport.parse(token, verify_signature: false)
  end

  describe 'constants' do
    it 'defines required constants' do
      expect(StirShaken::DivPassport::EXTENSION).to eq('div')
      expect(StirShaken::DivPassport::VALID_DIVERSION_REASONS).to include('forwarding')
      expect(StirShaken::DivPassport::VALID_DIVERSION_REASONS).to include('deflection')
      expect(StirShaken::DivPassport::VALID_DIVERSION_REASONS).to include('follow-me')
    end
  end

  describe '.create_div' do
    it 'creates a valid DIV PASSporT token' do
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        certificate_url: certificate_url,
        private_key: private_key
      )

      expect(token).to be_a(String)
      expect(token.count('.')).to eq(2) # JWT format: header.payload.signature
    end

    it 'creates token with correct DIV extension' do
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.header['ppt']).to eq('div')
    end

    it 'preserves original attestation level' do
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.attestation).to eq(original_passport.attestation)
    end

    it 'includes DIV-specific claims' do
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.original_destination).to eq(original_destination)
      expect(div_passport.diversion_reason).to eq(diversion_reason)
      expect(div_passport.destination_numbers).to eq([new_destination])
    end

    it 'handles multiple new destinations' do
      multiple_destinations = ['+15559876543', '+15552222222', '+15553333333']
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: multiple_destinations,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.destination_numbers).to eq(multiple_destinations)
    end

    it 'uses original passport origination_id by default' do
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.origination_id).to eq(original_passport.origination_id)
    end

    it 'accepts custom origination_id' do
      custom_id = 'div-call-123'
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        origination_id: custom_id,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.origination_id).to eq(custom_id)
    end

    it 'validates diversion reason' do
      expect {
        StirShaken::DivPassport.create_div(
          original_passport: original_passport,
          new_destination: new_destination,
          original_destination: original_destination,
          diversion_reason: 'invalid-reason',
          certificate_url: certificate_url,
          private_key: private_key
        )
      }.to raise_error(StirShaken::InvalidDiversionReasonError)
    end

    it 'validates phone number formats' do
      expect {
        StirShaken::DivPassport.create_div(
          original_passport: original_passport,
          new_destination: 'invalid-number',
          original_destination: original_destination,
          diversion_reason: diversion_reason,
          certificate_url: certificate_url,
          private_key: private_key
        )
      }.to raise_error(StirShaken::InvalidPhoneNumberError)

      expect {
        StirShaken::DivPassport.create_div(
          original_passport: original_passport,
          new_destination: new_destination,
          original_destination: 'invalid-original',
          diversion_reason: diversion_reason,
          certificate_url: certificate_url,
          private_key: private_key
        )
      }.to raise_error(StirShaken::InvalidPhoneNumberError)
    end

    it 'works with all valid diversion reasons' do
      StirShaken::DivPassport::VALID_DIVERSION_REASONS.each do |reason|
        expect {
          StirShaken::DivPassport.create_div(
            original_passport: original_passport,
            new_destination: new_destination,
            original_destination: original_destination,
            diversion_reason: reason,
            certificate_url: certificate_url,
            private_key: private_key
          )
        }.not_to raise_error
      end
    end
  end

  describe '.create_from_identity_header' do
    let(:shaken_identity_header) do
      StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: certificate_url
      ).sign_call(
        originating_number: originating_number,
        destination_number: original_destination,
        attestation: 'A'
      )
    end

    it 'creates DIV PASSporT from SHAKEN Identity header' do
      token = StirShaken::DivPassport.create_from_identity_header(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        certificate_url: certificate_url,
        private_key: private_key
      )

      expect(token).to be_a(String)
      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.div_passport?).to be true
    end

    it 'preserves original call information' do
      token = StirShaken::DivPassport.create_from_identity_header(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.originating_number).to eq(originating_number)
      expect(div_passport.attestation).to eq('A')
    end

    it 'can verify original passport when public key provided' do
      expect {
        StirShaken::DivPassport.create_from_identity_header(
          shaken_identity_header: shaken_identity_header,
          new_destination: new_destination,
          original_destination: original_destination,
          diversion_reason: diversion_reason,
          certificate_url: certificate_url,
          private_key: private_key,
          public_key: public_key
        )
      }.not_to raise_error
    end
  end

  describe '.parse' do
    let(:div_token) do
      StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        certificate_url: certificate_url,
        private_key: private_key
      )
    end

    it 'parses DIV PASSporT token without verification' do
      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)

      expect(div_passport).to be_a(StirShaken::DivPassport)
      expect(div_passport.originating_number).to eq(originating_number)
      expect(div_passport.original_destination).to eq(original_destination)
      expect(div_passport.diversion_reason).to eq(diversion_reason)
    end

    it 'parses and verifies DIV PASSporT token with public key' do
      div_passport = StirShaken::DivPassport.parse(div_token, public_key: public_key, verify_signature: true)

      expect(div_passport).to be_a(StirShaken::DivPassport)
      expect(div_passport.originating_number).to eq(originating_number)
    end

    it 'raises error for signature verification failure' do
      other_key_pair = generate_test_key_pair
      wrong_public_key = other_key_pair[:public_key]

      expect {
        StirShaken::DivPassport.parse(div_token, public_key: wrong_public_key, verify_signature: true)
      }.to raise_error(StirShaken::InvalidTokenError)
    end

    it 'raises error for invalid token format' do
      expect {
        StirShaken::DivPassport.parse('invalid-token', verify_signature: false)
      }.to raise_error(StirShaken::InvalidTokenError)
    end
  end

  describe 'instance methods' do
    let(:div_passport) do
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        certificate_url: certificate_url,
        private_key: private_key
      )
      StirShaken::DivPassport.parse(token, verify_signature: false)
    end

    describe '#original_destination' do
      it 'returns the original destination' do
        expect(div_passport.original_destination).to eq(original_destination)
      end
    end

    describe '#diversion_reason' do
      it 'returns the diversion reason' do
        expect(div_passport.diversion_reason).to eq(diversion_reason)
      end
    end

    describe '#div_passport?' do
      it 'returns true for DIV PASSporT' do
        expect(div_passport.div_passport?).to be true
      end

      it 'returns false for regular PASSporT' do
        regular_passport = StirShaken::Passport.parse(
          StirShaken::Passport.create(
            originating_number: originating_number,
            destination_numbers: [new_destination],
            attestation: 'A',
            certificate_url: certificate_url,
            private_key: private_key
          ),
          verify_signature: false
        )
        expect(regular_passport.respond_to?(:div_passport?)).to be false
      end
    end

    describe '#to_h' do
      it 'includes DIV-specific fields' do
        hash = div_passport.to_h
        expect(hash[:original_destination]).to eq(original_destination)
        expect(hash[:diversion_reason]).to eq(diversion_reason)
        expect(hash[:div_passport]).to be true
      end

      it 'includes all standard PASSporT fields' do
        hash = div_passport.to_h
        expect(hash[:originating_number]).to eq(originating_number)
        expect(hash[:destination_numbers]).to eq([new_destination])
        expect(hash[:attestation]).to eq('A')
        expect(hash[:origination_id]).to be_a(String)
      end
    end
  end

  describe 'validation' do
    it 'validates required DIV claims' do
      # Create a malformed DIV token manually
      header = {
        'alg' => 'ES256',
        'typ' => 'passport',
        'ppt' => 'div',
        'x5u' => certificate_url
      }

      # Missing div claim
      payload = {
        'attest' => 'A',
        'dest' => { 'tn' => [new_destination] },
        'iat' => Time.now.to_i,
        'orig' => { 'tn' => originating_number },
        'origid' => 'test-id'
      }

      malformed_token = JWT.encode(payload, private_key, 'ES256', header)

      expect {
        StirShaken::DivPassport.parse(malformed_token, verify_signature: false)
      }.to raise_error(StirShaken::PassportValidationError, /Missing div claim/)
    end

    it 'validates original destination in div claim' do
      header = {
        'alg' => 'ES256',
        'typ' => 'passport',
        'ppt' => 'div',
        'x5u' => certificate_url
      }

      # Missing div.tn
      payload = {
        'attest' => 'A',
        'dest' => { 'tn' => [new_destination] },
        'div' => { 'reason' => 'forwarding' },
        'iat' => Time.now.to_i,
        'orig' => { 'tn' => originating_number },
        'origid' => 'test-id'
      }

      malformed_token = JWT.encode(payload, private_key, 'ES256', header)

      expect {
        StirShaken::DivPassport.parse(malformed_token, verify_signature: false)
      }.to raise_error(StirShaken::PassportValidationError, /Missing original destination/)
    end

    it 'validates diversion reason in div claim' do
      header = {
        'alg' => 'ES256',
        'typ' => 'passport',
        'ppt' => 'div',
        'x5u' => certificate_url
      }

      # Missing div.reason
      payload = {
        'attest' => 'A',
        'dest' => { 'tn' => [new_destination] },
        'div' => { 'tn' => original_destination },
        'iat' => Time.now.to_i,
        'orig' => { 'tn' => originating_number },
        'origid' => 'test-id'
      }

      malformed_token = JWT.encode(payload, private_key, 'ES256', header)

      expect {
        StirShaken::DivPassport.parse(malformed_token, verify_signature: false)
      }.to raise_error(StirShaken::PassportValidationError, /Missing diversion reason/)
    end

    it 'validates diversion reason value' do
      header = {
        'alg' => 'ES256',
        'typ' => 'passport',
        'ppt' => 'div',
        'x5u' => certificate_url
      }

      # Invalid div.reason
      payload = {
        'attest' => 'A',
        'dest' => { 'tn' => [new_destination] },
        'div' => { 'tn' => original_destination, 'reason' => 'invalid-reason' },
        'iat' => Time.now.to_i,
        'orig' => { 'tn' => originating_number },
        'origid' => 'test-id'
      }

      malformed_token = JWT.encode(payload, private_key, 'ES256', header)

      expect {
        StirShaken::DivPassport.parse(malformed_token, verify_signature: false)
      }.to raise_error(StirShaken::InvalidDiversionReasonError)
    end

    it 'validates header extension' do
      header = {
        'alg' => 'ES256',
        'typ' => 'passport',
        'ppt' => 'shaken', # Wrong extension
        'x5u' => certificate_url
      }

      payload = {
        'attest' => 'A',
        'dest' => { 'tn' => [new_destination] },
        'div' => { 'tn' => original_destination, 'reason' => 'forwarding' },
        'iat' => Time.now.to_i,
        'orig' => { 'tn' => originating_number },
        'origid' => 'test-id'
      }

      malformed_token = JWT.encode(payload, private_key, 'ES256', header)

      expect {
        StirShaken::DivPassport.parse(malformed_token, verify_signature: false)
      }.to raise_error(StirShaken::PassportValidationError, /Invalid extension.*expected div/)
    end
  end

  describe '.validate_diversion_reason!' do
    it 'accepts valid diversion reasons' do
      StirShaken::DivPassport::VALID_DIVERSION_REASONS.each do |reason|
        expect {
          StirShaken::DivPassport.validate_diversion_reason!(reason)
        }.not_to raise_error
      end
    end

    it 'rejects invalid diversion reasons' do
      expect {
        StirShaken::DivPassport.validate_diversion_reason!('invalid-reason')
      }.to raise_error(StirShaken::InvalidDiversionReasonError)
    end
  end

  describe 'integration with standard PASSporT' do
    it 'inherits standard PASSporT functionality' do
      div_passport = StirShaken::DivPassport.parse(
        StirShaken::DivPassport.create_div(
          original_passport: original_passport,
          new_destination: new_destination,
          original_destination: original_destination,
          diversion_reason: diversion_reason,
          certificate_url: certificate_url,
          private_key: private_key
        ),
        verify_signature: false
      )

      # Should have all standard PASSporT methods
      expect(div_passport.originating_number).to eq(originating_number)
      expect(div_passport.destination_numbers).to eq([new_destination])
      expect(div_passport.attestation).to eq('A')
      expect(div_passport.issued_at).to be_a(Integer)
      expect(div_passport.certificate_url).to eq(certificate_url)
      expect(div_passport.expired?).to be false
    end
  end
end 