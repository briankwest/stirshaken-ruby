# frozen_string_literal: true

require 'spec_helper'

RSpec.describe StirShaken::AuthenticationService, 'DIV PASSporT functionality' do
  let(:key_pair) { generate_test_key_pair }
  let(:private_key) { key_pair[:private_key] }
  let(:public_key) { key_pair[:public_key] }
  let(:certificate_url) { 'https://test.example.com/cert.pem' }
  let(:certificate) { create_test_certificate(private_key) }

  let(:service) do
    StirShaken::AuthenticationService.new(
      private_key: private_key,
      certificate_url: certificate_url,
      certificate: certificate
    )
  end

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

  let(:shaken_identity_header) do
    service.sign_call(
      originating_number: originating_number,
      destination_number: original_destination,
      attestation: 'A'
    )
  end

  before do
    @original_stderr = $stderr
    $stderr = StringIO.new
  end

  after do
    $stderr = @original_stderr
  end

  describe '#create_div_passport' do
    it 'creates a valid DIV PASSporT token' do
      div_token = service.create_div_passport(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination
      )

      expect(div_token).to be_a(String)
      expect(div_token.count('.')).to eq(2)

      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)
      expect(div_passport.div_passport?).to be true
      expect(div_passport.original_destination).to eq(original_destination)
    end

    it 'preserves original orig.tn and iat' do
      div_token = service.create_div_passport(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination
      )

      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)
      expect(div_passport.originating_number).to eq(original_passport.originating_number)
      expect(div_passport.issued_at).to eq(original_passport.issued_at)
    end

    it 'handles multiple new destinations' do
      multiple_destinations = ['+15559876543', '+15552222222', '+15553333333']
      div_token = service.create_div_passport(
        original_passport: original_passport,
        new_destination: multiple_destinations,
        original_destination: original_destination
      )

      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)
      expect(div_passport.destination_numbers).to eq(multiple_destinations)
    end

    it 'logs successful DIV PASSporT creation' do
      service.create_div_passport(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination
      )

      output = $stderr.string
      expect(output).to include('DIV_PASSPORT_CREATED')
    end

    it 'logs and re-raises errors' do
      invalid_passport = double('passport')
      allow(invalid_passport).to receive(:originating_number).and_return(originating_number)
      allow(invalid_passport).to receive(:issued_at).and_return(Time.now.to_i)

      expect {
        service.create_div_passport(
          original_passport: invalid_passport,
          new_destination: 'invalid-number',
          original_destination: original_destination
        )
      }.to raise_error(StirShaken::InvalidPhoneNumberError)

      output = $stderr.string
      expect(output).to include('DIV_PASSPORT_CREATION_FAILURE')
    end
  end

  describe '#create_div_passport_from_header' do
    it 'creates DIV PASSporT from SHAKEN Identity header' do
      div_token = service.create_div_passport_from_header(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination
      )

      expect(div_token).to be_a(String)
      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)
      expect(div_passport.div_passport?).to be true
    end

    it 'preserves original orig.tn from header' do
      div_token = service.create_div_passport_from_header(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination
      )

      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)
      expect(div_passport.originating_number).to eq(originating_number)
    end

    it 'can verify original passport when requested' do
      expect {
        service.create_div_passport_from_header(
          shaken_identity_header: shaken_identity_header,
          new_destination: new_destination,
          original_destination: original_destination,
          verify_original: true
        )
      }.not_to raise_error
    end

    it 'logs successful DIV PASSporT creation from header' do
      service.create_div_passport_from_header(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination
      )

      output = $stderr.string
      expect(output).to include('DIV_PASSPORT_FROM_HEADER_CREATED')
    end

    it 'logs and re-raises errors' do
      expect {
        service.create_div_passport_from_header(
          shaken_identity_header: 'invalid-header',
          new_destination: new_destination,
          original_destination: original_destination
        )
      }.to raise_error(StandardError)

      output = $stderr.string
      expect(output).to include('DIV_PASSPORT_FROM_HEADER_FAILURE')
    end
  end

  describe '#sign_diverted_call' do
    it 'creates both original and DIV headers' do
      result = service.sign_diverted_call(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination
      )

      expect(result).to be_a(Hash)
      expect(result[:shaken_header]).to eq(shaken_identity_header)
      expect(result[:div_header]).to be_a(String)
      expect(result[:div_header]).to include('ppt=div')
    end

    it 'creates valid DIV SIP Identity header' do
      result = service.sign_diverted_call(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination
      )

      div_sip_identity = StirShaken::SipIdentity.parse(result[:div_header])
      expect(div_sip_identity.extension).to eq('div')
      expect(div_sip_identity.algorithm).to eq('ES256')

      div_passport = StirShaken::DivPassport.parse(div_sip_identity.passport_token, verify_signature: false)
      expect(div_passport.div_passport?).to be true
      expect(div_passport.original_destination).to eq(original_destination)
    end

    it 'includes additional info in DIV header' do
      additional_info = { 'custom' => 'value', 'session-id' => 'test-123' }
      result = service.sign_diverted_call(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination,
        additional_info: additional_info
      )

      expect(result[:div_header]).to include('custom=value')
      expect(result[:div_header]).to include('session-id=test-123')
    end

    it 'logs successful diverted call signing' do
      service.sign_diverted_call(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination
      )

      output = $stderr.string
      expect(output).to include('DIVERTED_CALL_SIGNED')
    end

    it 'logs and re-raises errors' do
      expect {
        service.sign_diverted_call(
          shaken_identity_header: 'invalid-header',
          new_destination: new_destination,
          original_destination: original_destination
        )
      }.to raise_error(StandardError)

      output = $stderr.string
      expect(output).to include('DIVERTED_CALL_SIGNING_FAILURE')
    end
  end

  describe '#create_call_forwarding' do
    let(:original_call_info) do
      {
        originating_number: originating_number,
        destination_number: original_destination,
        attestation: 'A',
        origination_id: 'test-call-123'
      }
    end

    let(:forwarding_info) do
      { new_destination: new_destination }
    end

    it 'creates complete call forwarding scenario' do
      result = service.create_call_forwarding(
        original_call_info: original_call_info,
        forwarding_info: forwarding_info
      )

      expect(result).to be_a(Hash)
      expect(result[:original_shaken_header]).to be_a(String)
      expect(result[:forwarded_shaken_header]).to be_a(String)
      expect(result[:div_header]).to be_a(String)
      expect(result[:metadata]).to be_a(Hash)
    end

    it 'reduces attestation level for forwarded calls' do
      result = service.create_call_forwarding(
        original_call_info: original_call_info,
        forwarding_info: forwarding_info
      )

      forwarded_sip_identity = StirShaken::SipIdentity.parse(result[:forwarded_shaken_header])
      forwarded_passport = forwarded_sip_identity.parse_passport(verify_signature: false)

      expect(forwarded_passport.attestation).to eq('B')
      expect(result[:metadata][:original_attestation]).to eq('A')
      expect(result[:metadata][:forwarded_attestation]).to eq('B')
    end

    it 'preserves origination_id across forwarded SHAKEN headers' do
      result = service.create_call_forwarding(
        original_call_info: original_call_info,
        forwarding_info: forwarding_info
      )

      original_sip_identity = StirShaken::SipIdentity.parse(result[:original_shaken_header])
      original_passport = original_sip_identity.parse_passport(verify_signature: false)

      forwarded_sip_identity = StirShaken::SipIdentity.parse(result[:forwarded_shaken_header])
      forwarded_passport = forwarded_sip_identity.parse_passport(verify_signature: false)

      expect(original_passport.origination_id).to eq(forwarded_passport.origination_id)
      expect(result[:metadata][:origination_id]).to eq('test-call-123')
    end

    it 'uses existing identity header when provided' do
      existing_header = service.sign_call(
        originating_number: originating_number,
        destination_number: original_destination,
        attestation: 'A',
        origination_id: 'existing-call-456'
      )

      call_info_with_header = original_call_info.merge(identity_header: existing_header)

      result = service.create_call_forwarding(
        original_call_info: call_info_with_header,
        forwarding_info: forwarding_info
      )

      expect(result[:original_shaken_header]).to eq(existing_header)
    end

    it 'allows custom attestation for forwarded call' do
      forwarding_with_custom_attestation = forwarding_info.merge(attestation: 'C')

      result = service.create_call_forwarding(
        original_call_info: original_call_info,
        forwarding_info: forwarding_with_custom_attestation
      )

      forwarded_sip_identity = StirShaken::SipIdentity.parse(result[:forwarded_shaken_header])
      forwarded_passport = forwarded_sip_identity.parse_passport(verify_signature: false)

      expect(forwarded_passport.attestation).to eq('C')
      expect(result[:metadata][:forwarded_attestation]).to eq('C')
    end

    it 'includes comprehensive metadata' do
      result = service.create_call_forwarding(
        original_call_info: original_call_info,
        forwarding_info: forwarding_info
      )

      metadata = result[:metadata]
      expect(metadata[:originating_number]).to eq(originating_number)
      expect(metadata[:original_destination]).to eq(original_destination)
      expect(metadata[:new_destination]).to eq(new_destination)
      expect(metadata[:original_attestation]).to eq('A')
      expect(metadata[:forwarded_attestation]).to eq('B')
      expect(metadata[:origination_id]).to eq('test-call-123')
      expect(metadata).not_to have_key(:diversion_reason)
    end

    it 'logs successful call forwarding creation' do
      service.create_call_forwarding(
        original_call_info: original_call_info,
        forwarding_info: forwarding_info
      )

      output = $stderr.string
      expect(output).to include('CALL_FORWARDING_CREATED')
    end

    it 'logs and re-raises errors' do
      invalid_call_info = { originating_number: 'invalid' }

      expect {
        service.create_call_forwarding(
          original_call_info: invalid_call_info,
          forwarding_info: forwarding_info
        )
      }.to raise_error(StandardError)

      output = $stderr.string
      expect(output).to include('CALL_FORWARDING_FAILURE')
    end

    it 'handles multiple forwarding destinations' do
      multiple_forwarding = forwarding_info.merge(
        new_destination: ['+15559876543', '+15552222222', '+15553333333']
      )

      result = service.create_call_forwarding(
        original_call_info: original_call_info,
        forwarding_info: multiple_forwarding
      )

      div_sip_identity = StirShaken::SipIdentity.parse(result[:div_header])
      div_passport = StirShaken::DivPassport.parse(div_sip_identity.passport_token, verify_signature: false)

      expect(div_passport.destination_numbers).to eq(multiple_forwarding[:new_destination])
    end
  end

  describe '#determine_forwarding_attestation (private method)' do
    it 'reduces attestation A to B' do
      expect(service.send(:determine_forwarding_attestation, 'A')).to eq('B')
    end

    it 'reduces attestation B to C' do
      expect(service.send(:determine_forwarding_attestation, 'B')).to eq('C')
    end

    it 'keeps attestation C as C' do
      expect(service.send(:determine_forwarding_attestation, 'C')).to eq('C')
    end

    it 'defaults unknown attestation to C' do
      expect(service.send(:determine_forwarding_attestation, 'X')).to eq('C')
    end
  end

  describe 'integration scenarios' do
    it 'handles complete call forwarding workflow' do
      original_header = service.sign_call(
        originating_number: originating_number,
        destination_number: original_destination,
        attestation: 'A'
      )

      forwarding_result = service.sign_diverted_call(
        shaken_identity_header: original_header,
        new_destination: new_destination,
        original_destination: original_destination
      )

      original_sip_identity = StirShaken::SipIdentity.parse(forwarding_result[:shaken_header])
      original_passport = original_sip_identity.parse_passport(verify_signature: false)
      expect(original_passport.attestation).to eq('A')

      div_sip_identity = StirShaken::SipIdentity.parse(forwarding_result[:div_header])
      div_passport = StirShaken::DivPassport.parse(div_sip_identity.passport_token, verify_signature: false)
      expect(div_passport.div_passport?).to be true
      expect(div_passport.original_destination).to eq(original_destination)
      expect(div_passport.destination_numbers).to eq([new_destination])
    end

    it 'handles multiple forwarding hops' do
      first_forwarding = service.sign_diverted_call(
        shaken_identity_header: shaken_identity_header,
        new_destination: '+15552222222',
        original_destination: original_destination
      )

      second_forwarding = service.sign_diverted_call(
        shaken_identity_header: first_forwarding[:shaken_header],
        new_destination: '+15553333333',
        original_destination: '+15552222222'
      )

      first_div_sip_identity = StirShaken::SipIdentity.parse(first_forwarding[:div_header])
      first_div_passport = StirShaken::DivPassport.parse(first_div_sip_identity.passport_token, verify_signature: false)
      expect(first_div_passport.original_destination).to eq(original_destination)

      second_div_sip_identity = StirShaken::SipIdentity.parse(second_forwarding[:div_header])
      second_div_passport = StirShaken::DivPassport.parse(second_div_sip_identity.passport_token, verify_signature: false)
      expect(second_div_passport.original_destination).to eq('+15552222222')
    end

    it 'preserves origination_id on forwarded SHAKEN leg only' do
      origination_id = 'chain-test-123'
      result = service.create_call_forwarding(
        original_call_info: {
          originating_number: originating_number,
          destination_number: original_destination,
          attestation: 'A',
          origination_id: origination_id
        },
        forwarding_info: { new_destination: new_destination }
      )

      original_sip_identity = StirShaken::SipIdentity.parse(result[:original_shaken_header])
      original_passport = original_sip_identity.parse_passport(verify_signature: false)

      forwarded_sip_identity = StirShaken::SipIdentity.parse(result[:forwarded_shaken_header])
      forwarded_passport = forwarded_sip_identity.parse_passport(verify_signature: false)

      div_sip_identity = StirShaken::SipIdentity.parse(result[:div_header])
      div_passport = StirShaken::DivPassport.parse(div_sip_identity.passport_token, verify_signature: false)

      expect(original_passport.originating_number).to eq(originating_number)
      expect(forwarded_passport.originating_number).to eq(originating_number)
      expect(div_passport.originating_number).to eq(originating_number)

      expect(original_passport.origination_id).to eq(origination_id)
      expect(forwarded_passport.origination_id).to eq(origination_id)

      # DIV PASSporT does not carry origid per RFC 8946
      expect(div_passport.origination_id).to be_nil

      expect(original_passport.attestation).to eq('A')
      expect(forwarded_passport.attestation).to eq('B')

      expect(div_passport.original_destination).to eq(original_destination)
      expect(div_passport.destination_numbers).to eq([new_destination])
    end
  end
end
