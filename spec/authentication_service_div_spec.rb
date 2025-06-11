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

  let(:shaken_identity_header) do
    service.sign_call(
      originating_number: originating_number,
      destination_number: original_destination,
      attestation: 'A'
    )
  end

  before do
    # Capture log output
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
        original_destination: original_destination,
        diversion_reason: diversion_reason
      )

      expect(div_token).to be_a(String)
      expect(div_token.count('.')).to eq(2) # JWT format

      # Parse and verify the token
      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)
      expect(div_passport.div_passport?).to be true
      expect(div_passport.original_destination).to eq(original_destination)
      expect(div_passport.diversion_reason).to eq(diversion_reason)
    end

    it 'preserves original passport information' do
      div_token = service.create_div_passport(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason
      )

      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)
      expect(div_passport.originating_number).to eq(original_passport.originating_number)
      expect(div_passport.attestation).to eq(original_passport.attestation)
      expect(div_passport.origination_id).to eq(original_passport.origination_id)
    end

    it 'handles multiple new destinations' do
      multiple_destinations = ['+15559876543', '+15552222222', '+15553333333']
      div_token = service.create_div_passport(
        original_passport: original_passport,
        new_destination: multiple_destinations,
        original_destination: original_destination,
        diversion_reason: diversion_reason
      )

      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)
      expect(div_passport.destination_numbers).to eq(multiple_destinations)
    end

    it 'accepts custom origination_id' do
      custom_id = 'div-call-123'
      div_token = service.create_div_passport(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        origination_id: custom_id
      )

      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)
      expect(div_passport.origination_id).to eq(custom_id)
    end

    it 'logs successful DIV PASSporT creation' do
      service.create_div_passport(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason
      )

      output = $stderr.string
      expect(output).to include('DIV_PASSPORT_CREATED')
      expect(output).to include('"diversion_reason":"forwarding"')
    end

    it 'logs and re-raises errors' do
      # Create invalid passport to trigger error
      invalid_passport = double('passport')
      allow(invalid_passport).to receive(:originating_number).and_return(originating_number)
      allow(invalid_passport).to receive(:attestation).and_return('A')
      allow(invalid_passport).to receive(:origination_id).and_return('test-id')

      expect {
        service.create_div_passport(
          original_passport: invalid_passport,
          new_destination: 'invalid-number', # This will trigger validation error
          original_destination: original_destination,
          diversion_reason: diversion_reason
        )
      }.to raise_error(StirShaken::InvalidPhoneNumberError)

      output = $stderr.string
      expect(output).to include('DIV_PASSPORT_CREATION_FAILURE')
    end

    it 'works with all valid diversion reasons' do
      StirShaken::DivPassport::VALID_DIVERSION_REASONS.each do |reason|
        expect {
          service.create_div_passport(
            original_passport: original_passport,
            new_destination: new_destination,
            original_destination: original_destination,
            diversion_reason: reason
          )
        }.not_to raise_error
      end
    end
  end

  describe '#create_div_passport_from_header' do
    it 'creates DIV PASSporT from SHAKEN Identity header' do
      div_token = service.create_div_passport_from_header(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason
      )

      expect(div_token).to be_a(String)
      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)
      expect(div_passport.div_passport?).to be true
    end

    it 'preserves original call information from header' do
      div_token = service.create_div_passport_from_header(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason
      )

      div_passport = StirShaken::DivPassport.parse(div_token, verify_signature: false)
      expect(div_passport.originating_number).to eq(originating_number)
      expect(div_passport.attestation).to eq('A')
    end

    it 'can verify original passport when requested' do
      expect {
        service.create_div_passport_from_header(
          shaken_identity_header: shaken_identity_header,
          new_destination: new_destination,
          original_destination: original_destination,
          diversion_reason: diversion_reason,
          verify_original: true
        )
      }.not_to raise_error
    end

    it 'logs successful DIV PASSporT creation from header' do
      service.create_div_passport_from_header(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason
      )

      output = $stderr.string
      expect(output).to include('DIV_PASSPORT_FROM_HEADER_CREATED')
    end

    it 'logs and re-raises errors' do
      expect {
        service.create_div_passport_from_header(
          shaken_identity_header: 'invalid-header',
          new_destination: new_destination,
          original_destination: original_destination,
          diversion_reason: diversion_reason
        )
      }.to raise_error

      output = $stderr.string
      expect(output).to include('DIV_PASSPORT_FROM_HEADER_FAILURE')
    end
  end

  describe '#sign_diverted_call' do
    it 'creates both SHAKEN and DIV headers' do
      result = service.sign_diverted_call(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason
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
        original_destination: original_destination,
        diversion_reason: diversion_reason
      )

      # Parse the DIV header
      div_sip_identity = StirShaken::SipIdentity.parse(result[:div_header])
      expect(div_sip_identity.extension).to eq('div')
      expect(div_sip_identity.algorithm).to eq('ES256')

      # Parse the embedded DIV PASSporT
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
        diversion_reason: diversion_reason,
        additional_info: additional_info
      )

      expect(result[:div_header]).to include('custom=value')
      expect(result[:div_header]).to include('session-id=test-123')
    end

    it 'logs successful diverted call signing' do
      service.sign_diverted_call(
        shaken_identity_header: shaken_identity_header,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason
      )

      output = $stderr.string
      expect(output).to include('DIVERTED_CALL_SIGNED')
    end

    it 'logs and re-raises errors' do
      expect {
        service.sign_diverted_call(
          shaken_identity_header: 'invalid-header',
          new_destination: new_destination,
          original_destination: original_destination,
          diversion_reason: diversion_reason
        )
      }.to raise_error

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
      {
        new_destination: new_destination,
        reason: 'forwarding'
      }
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

      # Parse forwarded SHAKEN header to check attestation
      forwarded_sip_identity = StirShaken::SipIdentity.parse(result[:forwarded_shaken_header])
      forwarded_passport = forwarded_sip_identity.parse_passport(verify_signature: false)
      
      expect(forwarded_passport.attestation).to eq('B') # Reduced from A to B
      expect(result[:metadata][:original_attestation]).to eq('A')
      expect(result[:metadata][:forwarded_attestation]).to eq('B')
    end

    it 'preserves origination_id across forwarding' do
      result = service.create_call_forwarding(
        original_call_info: original_call_info,
        forwarding_info: forwarding_info
      )

      # Parse both headers to verify same origination_id
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
      expect(metadata[:diversion_reason]).to eq('forwarding')
      expect(metadata[:origination_id]).to eq('test-call-123')
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
      }.to raise_error

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

      # Parse DIV header to verify multiple destinations
      div_sip_identity = StirShaken::SipIdentity.parse(result[:div_header])
      div_passport = StirShaken::DivPassport.parse(div_sip_identity.passport_token, verify_signature: false)
      
      expect(div_passport.destination_numbers).to eq(multiple_forwarding[:new_destination])
    end
  end

  describe '#determine_forwarding_attestation (private method)' do
    it 'reduces attestation A to B' do
      result = service.send(:determine_forwarding_attestation, 'A')
      expect(result).to eq('B')
    end

    it 'reduces attestation B to C' do
      result = service.send(:determine_forwarding_attestation, 'B')
      expect(result).to eq('C')
    end

    it 'keeps attestation C as C' do
      result = service.send(:determine_forwarding_attestation, 'C')
      expect(result).to eq('C')
    end

    it 'defaults unknown attestation to C' do
      result = service.send(:determine_forwarding_attestation, 'X')
      expect(result).to eq('C')
    end
  end

  describe 'integration scenarios' do
    it 'handles complete call forwarding workflow' do
      # Step 1: Original call comes in
      original_header = service.sign_call(
        originating_number: originating_number,
        destination_number: original_destination,
        attestation: 'A'
      )

      # Step 2: Call needs to be forwarded
      forwarding_result = service.sign_diverted_call(
        shaken_identity_header: original_header,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: 'forwarding'
      )

      # Step 3: Verify both headers are valid
      # Original SHAKEN header
      original_sip_identity = StirShaken::SipIdentity.parse(forwarding_result[:shaken_header])
      original_passport = original_sip_identity.parse_passport(verify_signature: false)
      expect(original_passport.attestation).to eq('A')

      # DIV header
      div_sip_identity = StirShaken::SipIdentity.parse(forwarding_result[:div_header])
      div_passport = StirShaken::DivPassport.parse(div_sip_identity.passport_token, verify_signature: false)
      expect(div_passport.div_passport?).to be true
      expect(div_passport.original_destination).to eq(original_destination)
      expect(div_passport.destination_numbers).to eq([new_destination])
    end

    it 'handles multiple forwarding hops' do
      # First forwarding
      first_forwarding = service.sign_diverted_call(
        shaken_identity_header: shaken_identity_header,
        new_destination: '+15552222222',
        original_destination: original_destination,
        diversion_reason: 'forwarding'
      )

      # Second forwarding (forwarding the already forwarded call)
      second_forwarding = service.sign_diverted_call(
        shaken_identity_header: first_forwarding[:shaken_header],
        new_destination: '+15553333333',
        original_destination: '+15552222222', # Previous destination becomes original
        diversion_reason: 'follow-me'
      )

      # Verify both DIV headers are valid
      first_div_sip_identity = StirShaken::SipIdentity.parse(first_forwarding[:div_header])
      first_div_passport = StirShaken::DivPassport.parse(first_div_sip_identity.passport_token, verify_signature: false)
      expect(first_div_passport.diversion_reason).to eq('forwarding')

      second_div_sip_identity = StirShaken::SipIdentity.parse(second_forwarding[:div_header])
      second_div_passport = StirShaken::DivPassport.parse(second_div_sip_identity.passport_token, verify_signature: false)
      expect(second_div_passport.diversion_reason).to eq('follow-me')
    end

    it 'maintains chain of trust through forwarding' do
      # Create complete forwarding scenario with explicit origination_id
      origination_id = 'chain-test-123'
      result = service.create_call_forwarding(
        original_call_info: {
          originating_number: originating_number,
          destination_number: original_destination,
          attestation: 'A',
          origination_id: origination_id
        },
        forwarding_info: {
          new_destination: new_destination,
          reason: 'forwarding'
        }
      )

      # Verify all components maintain consistent information
      original_sip_identity = StirShaken::SipIdentity.parse(result[:original_shaken_header])
      original_passport = original_sip_identity.parse_passport(verify_signature: false)

      forwarded_sip_identity = StirShaken::SipIdentity.parse(result[:forwarded_shaken_header])
      forwarded_passport = forwarded_sip_identity.parse_passport(verify_signature: false)

      div_sip_identity = StirShaken::SipIdentity.parse(result[:div_header])
      div_passport = StirShaken::DivPassport.parse(div_sip_identity.passport_token, verify_signature: false)

      # All should have same originating number and origination_id
      expect(original_passport.originating_number).to eq(originating_number)
      expect(forwarded_passport.originating_number).to eq(originating_number)
      expect(div_passport.originating_number).to eq(originating_number)

      expect(original_passport.origination_id).to eq(origination_id)
      expect(forwarded_passport.origination_id).to eq(origination_id)
      expect(div_passport.origination_id).to eq(origination_id)

      # Verify attestation reduction
      expect(original_passport.attestation).to eq('A')
      expect(forwarded_passport.attestation).to eq('B') # Reduced due to forwarding
      expect(div_passport.attestation).to eq('A') # Preserves original attestation

      # Verify DIV-specific information
      expect(div_passport.original_destination).to eq(original_destination)
      expect(div_passport.destination_numbers).to eq([new_destination])
      expect(div_passport.diversion_reason).to eq('forwarding')
    end
  end
end 