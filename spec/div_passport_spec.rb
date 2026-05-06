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
    it 'defines the div extension' do
      expect(StirShaken::DivPassport::EXTENSION).to eq('div')
    end
  end

  describe '.create_div' do
    it 'creates a valid DIV PASSporT token' do
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        certificate_url: certificate_url,
        private_key: private_key
      )

      expect(token).to be_a(String)
      expect(token.count('.')).to eq(2)
    end

    it 'creates token with correct DIV extension' do
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.header['ppt']).to eq('div')
    end

    it 'emits only RFC 8946 claims (no attest, origid, or div.reason)' do
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.payload.keys).to contain_exactly('orig', 'dest', 'iat', 'div')
      expect(div_passport.payload['div']).to eq('tn' => original_destination)
    end

    it 'sets iat equal to the original passport iat (RFC 8946 §3)' do
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.issued_at).to eq(original_passport.issued_at)
    end

    it 'preserves orig and original_destination' do
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.originating_number).to eq(originating_number)
      expect(div_passport.original_destination).to eq(original_destination)
      expect(div_passport.destination_numbers).to eq([new_destination])
    end

    it 'handles multiple new destinations' do
      multiple_destinations = ['+15559876543', '+15552222222', '+15553333333']
      token = StirShaken::DivPassport.create_div(
        original_passport: original_passport,
        new_destination: multiple_destinations,
        original_destination: original_destination,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.destination_numbers).to eq(multiple_destinations)
    end

    it 'validates phone number formats' do
      expect {
        StirShaken::DivPassport.create_div(
          original_passport: original_passport,
          new_destination: 'invalid-number',
          original_destination: original_destination,
          certificate_url: certificate_url,
          private_key: private_key
        )
      }.to raise_error(StirShaken::InvalidPhoneNumberError)

      expect {
        StirShaken::DivPassport.create_div(
          original_passport: original_passport,
          new_destination: new_destination,
          original_destination: 'invalid-original',
          certificate_url: certificate_url,
          private_key: private_key
        )
      }.to raise_error(StirShaken::InvalidPhoneNumberError)
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
        certificate_url: certificate_url,
        private_key: private_key
      )

      expect(token).to be_a(String)
      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.div_passport?).to be true
    end

    it 'preserves original orig.tn from header' do
      token = StirShaken::DivPassport.create_from_identity_header(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination,
        certificate_url: certificate_url,
        private_key: private_key
      )

      div_passport = StirShaken::DivPassport.parse(token, verify_signature: false)
      expect(div_passport.originating_number).to eq(originating_number)
    end

    it 'can verify original passport when public key provided' do
      expect {
        StirShaken::DivPassport.create_from_identity_header(
          shaken_identity_header: shaken_identity_header,
          new_destination: new_destination,
          original_destination: original_destination,
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
        certificate_url: certificate_url,
        private_key: private_key
      )
    end

    it 'parses DIV PASSporT token without verification' do
      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)

      expect(div_passport).to be_a(StirShaken::DivPassport)
      expect(div_passport.originating_number).to eq(originating_number)
      expect(div_passport.original_destination).to eq(original_destination)
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
      it 'includes DIV-specific fields and omits SHAKEN-only fields' do
        hash = div_passport.to_h
        expect(hash[:original_destination]).to eq(original_destination)
        expect(hash[:div_passport]).to be true
        expect(hash).not_to have_key(:attestation)
        expect(hash).not_to have_key(:origination_id)
      end

      it 'includes RFC 8946 PASSporT fields' do
        hash = div_passport.to_h
        expect(hash[:originating_number]).to eq(originating_number)
        expect(hash[:destination_numbers]).to eq([new_destination])
        expect(hash[:issued_at]).to be_a(Integer)
        expect(hash[:certificate_url]).to eq(certificate_url)
      end
    end
  end

  describe 'validation' do
    let(:base_payload) do
      {
        'dest' => { 'tn' => [new_destination] },
        'div'  => { 'tn' => original_destination },
        'iat'  => Time.now.to_i,
        'orig' => { 'tn' => originating_number }
      }
    end

    let(:base_header) do
      {
        'alg' => 'ES256',
        'typ' => 'passport',
        'ppt' => 'div',
        'x5u' => certificate_url
      }
    end

    it 'accepts a payload with only RFC 8946 claims' do
      token = JWT.encode(base_payload, private_key, 'ES256', base_header)
      expect {
        StirShaken::DivPassport.parse(token, verify_signature: false)
      }.not_to raise_error
    end

    it 'rejects a payload missing the div claim' do
      payload = base_payload.dup
      payload.delete('div')
      token = JWT.encode(payload, private_key, 'ES256', base_header)

      expect {
        StirShaken::DivPassport.parse(token, verify_signature: false)
      }.to raise_error(StirShaken::PassportValidationError, /Missing div claim/)
    end

    it 'rejects a payload missing div.tn' do
      payload = base_payload.merge('div' => {})
      token = JWT.encode(payload, private_key, 'ES256', base_header)

      expect {
        StirShaken::DivPassport.parse(token, verify_signature: false)
      }.to raise_error(StirShaken::PassportValidationError, /Missing original destination/)
    end

    it 'rejects a payload missing orig' do
      payload = base_payload.dup
      payload.delete('orig')
      token = JWT.encode(payload, private_key, 'ES256', base_header)

      expect {
        StirShaken::DivPassport.parse(token, verify_signature: false)
      }.to raise_error(StirShaken::PassportValidationError, /Missing orig/)
    end

    it 'rejects a payload missing iat' do
      payload = base_payload.dup
      payload.delete('iat')
      token = JWT.encode(payload, private_key, 'ES256', base_header)

      expect {
        StirShaken::DivPassport.parse(token, verify_signature: false)
      }.to raise_error(StirShaken::PassportValidationError, /Missing iat/)
    end

    it 'rejects the wrong header extension' do
      header = base_header.merge('ppt' => 'shaken')
      token = JWT.encode(base_payload, private_key, 'ES256', header)

      expect {
        StirShaken::DivPassport.parse(token, verify_signature: false)
      }.to raise_error(StirShaken::PassportValidationError, /Invalid extension.*expected div/)
    end
  end

  describe '.verify_chain' do
    let(:shaken_token) do
      StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: [original_destination],
        attestation: 'A',
        certificate_url: certificate_url,
        private_key: private_key
      )
    end

    let(:div_token) do
      original = StirShaken::Passport.parse(shaken_token, verify_signature: false)
      StirShaken::DivPassport.create_div(
        original_passport: original,
        new_destination: new_destination,
        original_destination: original_destination,
        certificate_url: certificate_url,
        private_key: private_key
      )
    end

    it 'validates a correct DIV-original chain' do
      result = StirShaken::DivPassport.verify_chain(
        div_token: div_token,
        shaken_token: shaken_token,
        div_public_key: public_key,
        shaken_public_key: public_key
      )

      expect(result[:valid]).to be true
      expect(result[:div_passport]).to be_a(StirShaken::DivPassport)
      expect(result[:shaken_passport]).to be_a(StirShaken::Passport)
    end

    it 'rejects chain with mismatched originating number' do
      other_shaken = StirShaken::Passport.create(
        originating_number: '+15559999999',
        destination_numbers: [original_destination],
        attestation: 'A',
        certificate_url: certificate_url,
        private_key: private_key
      )

      result = StirShaken::DivPassport.verify_chain(
        div_token: div_token,
        shaken_token: other_shaken,
        div_public_key: public_key
      )

      expect(result[:valid]).to be false
      expect(result[:reason]).to include('Originating number mismatch')
    end

    it 'rejects chain when DIV original destination not in original destinations' do
      other_shaken = StirShaken::Passport.create(
        originating_number: originating_number,
        destination_numbers: ['+15558888888'],
        attestation: 'A',
        certificate_url: certificate_url,
        private_key: private_key
      )

      result = StirShaken::DivPassport.verify_chain(
        div_token: div_token,
        shaken_token: other_shaken,
        div_public_key: public_key
      )

      expect(result[:valid]).to be false
      expect(result[:reason]).to include('not found in original PASSporT destinations')
    end
  end

  describe 'integration with standard PASSporT' do
    it 'inherits standard PASSporT readers' do
      div_passport = StirShaken::DivPassport.parse(
        StirShaken::DivPassport.create_div(
          original_passport: original_passport,
          new_destination: new_destination,
          original_destination: original_destination,
          certificate_url: certificate_url,
          private_key: private_key
        ),
        verify_signature: false
      )

      expect(div_passport.originating_number).to eq(originating_number)
      expect(div_passport.destination_numbers).to eq([new_destination])
      expect(div_passport.issued_at).to be_a(Integer)
      expect(div_passport.certificate_url).to eq(certificate_url)
      expect(div_passport.expired?).to be false
    end
  end
end
