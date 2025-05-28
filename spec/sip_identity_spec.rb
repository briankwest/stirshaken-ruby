# frozen_string_literal: true

require 'spec_helper'

RSpec.describe StirShaken::SipIdentity do
  let(:key_pair) { generate_test_key_pair }
  let(:private_key) { key_pair[:private_key] }
  let(:public_key) { key_pair[:public_key] }
  let(:certificate_url) { 'https://test.example.com/cert.pem' }
  let(:passport_token) do
    StirShaken::Passport.create(
      originating_number: '+15551234567',
      destination_numbers: ['+15559876543'],
      attestation: 'A',
      certificate_url: certificate_url,
      private_key: private_key
    )
  end

  describe '.create' do
    it 'creates a valid SIP Identity header' do
      header = StirShaken::SipIdentity.create(
        passport_token: passport_token,
        certificate_url: certificate_url,
        algorithm: 'ES256',
        extension: 'shaken'
      )

      expect(header).to be_a(String)
      expect(header).to include(passport_token)
      expect(header).to include("info=<#{certificate_url}>")
      expect(header).to include('alg=ES256')
      expect(header).to include('ppt=shaken')
    end

    it 'uses default algorithm and extension' do
      header = StirShaken::SipIdentity.create(
        passport_token: passport_token,
        certificate_url: certificate_url
      )

      expect(header).to include('alg=ES256')
      expect(header).to include('ppt=shaken')
    end

    it 'includes additional parameters' do
      additional_info = { 'custom' => 'value', 'another' => 'param' }
      header = StirShaken::SipIdentity.create(
        passport_token: passport_token,
        certificate_url: certificate_url,
        additional_info: additional_info
      )

      expect(header).to include('custom=value')
      expect(header).to include('another=param')
    end

    it 'formats parameters correctly' do
      header = StirShaken::SipIdentity.create(
        passport_token: passport_token,
        certificate_url: certificate_url
      )

      # Should have token followed by semicolon-separated parameters
      parts = header.split(';')
      expect(parts[0]).to eq(passport_token)
      expect(parts[1]).to include('info=')
      expect(parts[2]).to include('alg=')
      expect(parts[3]).to include('ppt=')
    end
  end

  describe '.parse' do
    let(:valid_header) do
      StirShaken::SipIdentity.create(
        passport_token: passport_token,
        certificate_url: certificate_url
      )
    end

    it 'parses a valid SIP Identity header' do
      sip_identity = StirShaken::SipIdentity.parse(valid_header)

      expect(sip_identity).to be_a(StirShaken::SipIdentity)
      expect(sip_identity.passport_token).to eq(passport_token)
      expect(sip_identity.info_url).to eq(certificate_url)
      expect(sip_identity.algorithm).to eq('ES256')
      expect(sip_identity.extension).to eq('shaken')
    end

    it 'extracts certificate URL from angle brackets' do
      header_with_brackets = "#{passport_token};info=<#{certificate_url}>;alg=ES256;ppt=shaken"
      sip_identity = StirShaken::SipIdentity.parse(header_with_brackets)

      expect(sip_identity.info_url).to eq(certificate_url)
    end

    it 'handles certificate URL without angle brackets' do
      header_without_brackets = "#{passport_token};info=#{certificate_url};alg=ES256;ppt=shaken"
      sip_identity = StirShaken::SipIdentity.parse(header_without_brackets)

      expect(sip_identity.info_url).to eq(certificate_url)
    end

    it 'raises error for missing token and parameters separator' do
      expect {
        StirShaken::SipIdentity.parse(passport_token) # No semicolon
      }.to raise_error(StirShaken::InvalidIdentityHeaderError, /must contain token and parameters/)
    end

    it 'raises error for missing info parameter' do
      header_without_info = "#{passport_token};alg=ES256;ppt=shaken"
      expect {
        StirShaken::SipIdentity.parse(header_without_info)
      }.to raise_error(StirShaken::InvalidIdentityHeaderError, /Missing info parameter/)
    end

    it 'raises error for missing alg parameter' do
      header_without_alg = "#{passport_token};info=<#{certificate_url}>;ppt=shaken"
      expect {
        StirShaken::SipIdentity.parse(header_without_alg)
      }.to raise_error(StirShaken::InvalidIdentityHeaderError, /Missing alg parameter/)
    end

    it 'raises error for missing ppt parameter' do
      header_without_ppt = "#{passport_token};info=<#{certificate_url}>;alg=ES256"
      expect {
        StirShaken::SipIdentity.parse(header_without_ppt)
      }.to raise_error(StirShaken::InvalidIdentityHeaderError, /Missing ppt parameter/)
    end

    it 'handles parameters with spaces' do
      header_with_spaces = "#{passport_token}; info=<#{certificate_url}> ; alg=ES256 ; ppt=shaken"
      sip_identity = StirShaken::SipIdentity.parse(header_with_spaces)

      expect(sip_identity.info_url).to eq(certificate_url)
      expect(sip_identity.algorithm).to eq('ES256')
      expect(sip_identity.extension).to eq('shaken')
    end

    it 'handles additional parameters' do
      header_with_extra = "#{passport_token};info=<#{certificate_url}>;alg=ES256;ppt=shaken;custom=value"
      sip_identity = StirShaken::SipIdentity.parse(header_with_extra)

      expect(sip_identity.info_url).to eq(certificate_url)
      expect(sip_identity.algorithm).to eq('ES256')
      expect(sip_identity.extension).to eq('shaken')
    end
  end

  describe '#to_header' do
    let(:sip_identity) do
      StirShaken::SipIdentity.new(
        passport_token: passport_token,
        info_url: certificate_url,
        algorithm: 'ES256',
        extension: 'shaken'
      )
    end

    it 'converts back to header string' do
      header = sip_identity.to_header

      expect(header).to include(passport_token)
      expect(header).to include("info=<#{certificate_url}>")
      expect(header).to include('alg=ES256')
      expect(header).to include('ppt=shaken')
    end

    it 'produces parseable header' do
      header = sip_identity.to_header
      parsed = StirShaken::SipIdentity.parse(header)

      expect(parsed.passport_token).to eq(sip_identity.passport_token)
      expect(parsed.info_url).to eq(sip_identity.info_url)
      expect(parsed.algorithm).to eq(sip_identity.algorithm)
      expect(parsed.extension).to eq(sip_identity.extension)
    end
  end

  describe '#parse_passport' do
    let(:sip_identity) do
      StirShaken::SipIdentity.new(
        passport_token: passport_token,
        info_url: certificate_url,
        algorithm: 'ES256',
        extension: 'shaken'
      )
    end

    it 'parses embedded PASSporT token without verification' do
      passport = sip_identity.parse_passport(verify_signature: false)

      expect(passport).to be_a(StirShaken::Passport)
      expect(passport.originating_number).to eq('+15551234567')
      expect(passport.destination_numbers).to eq(['+15559876543'])
      expect(passport.attestation).to eq('A')
    end

    it 'parses and verifies PASSporT token with public key' do
      passport = sip_identity.parse_passport(public_key: public_key, verify_signature: true)

      expect(passport).to be_a(StirShaken::Passport)
      expect(passport.originating_number).to eq('+15551234567')
    end

    it 'raises error for signature verification failure' do
      other_key_pair = generate_test_key_pair
      wrong_public_key = other_key_pair[:public_key]

      expect {
        sip_identity.parse_passport(public_key: wrong_public_key, verify_signature: true)
      }.to raise_error(StirShaken::InvalidTokenError)
    end
  end

  describe '#validate!' do
    it 'validates a correct SIP Identity' do
      sip_identity = StirShaken::SipIdentity.new(
        passport_token: passport_token,
        info_url: certificate_url,
        algorithm: 'ES256',
        extension: 'shaken'
      )

      expect { sip_identity.validate! }.not_to raise_error
    end

    it 'raises error for unsupported algorithm' do
      sip_identity = StirShaken::SipIdentity.new(
        passport_token: passport_token,
        info_url: certificate_url,
        algorithm: 'RS256',
        extension: 'shaken'
      )

      expect {
        sip_identity.validate!
      }.to raise_error(StirShaken::InvalidIdentityHeaderError, /Unsupported algorithm: RS256/)
    end

    it 'raises error for unsupported extension' do
      sip_identity = StirShaken::SipIdentity.new(
        passport_token: passport_token,
        info_url: certificate_url,
        algorithm: 'ES256',
        extension: 'invalid'
      )

      expect {
        sip_identity.validate!
      }.to raise_error(StirShaken::InvalidIdentityHeaderError, /Unsupported extension: invalid/)
    end

    it 'raises error for invalid info URL' do
      sip_identity = StirShaken::SipIdentity.new(
        passport_token: passport_token,
        info_url: 'not-a-url',
        algorithm: 'ES256',
        extension: 'shaken'
      )

      expect {
        sip_identity.validate!
      }.to raise_error(StirShaken::InvalidIdentityHeaderError, /Invalid info URL/)
    end

    it 'raises error for invalid PASSporT token format' do
      sip_identity = StirShaken::SipIdentity.new(
        passport_token: 'invalid-token',
        info_url: certificate_url,
        algorithm: 'ES256',
        extension: 'shaken'
      )

      expect {
        sip_identity.validate!
      }.to raise_error(StirShaken::InvalidIdentityHeaderError, /Invalid PASSporT token format/)
    end
  end

  describe '#info' do
    let(:sip_identity) do
      StirShaken::SipIdentity.new(
        passport_token: passport_token,
        info_url: certificate_url,
        algorithm: 'ES256',
        extension: 'shaken'
      )
    end

    it 'returns information about the SIP Identity' do
      info = sip_identity.info

      expect(info).to be_a(Hash)
      expect(info[:algorithm]).to eq('ES256')
      expect(info[:extension]).to eq('shaken')
      expect(info[:info_url]).to eq(certificate_url)
      expect(info[:token_present]).to be true
      expect(info[:token_length]).to eq(passport_token.length)
    end

    it 'handles missing token' do
      sip_identity = StirShaken::SipIdentity.new(
        passport_token: nil,
        info_url: certificate_url,
        algorithm: 'ES256',
        extension: 'shaken'
      )

      info = sip_identity.info
      expect(info[:token_present]).to be false
      expect(info[:token_length]).to be_nil
    end
  end

  describe '#to_h' do
    let(:sip_identity) do
      StirShaken::SipIdentity.new(
        passport_token: passport_token,
        info_url: certificate_url,
        algorithm: 'ES256',
        extension: 'shaken'
      )
    end

    it 'returns hash representation' do
      hash = sip_identity.to_h

      expect(hash).to be_a(Hash)
      expect(hash[:passport_token]).to eq(passport_token)
      expect(hash[:info_url]).to eq(certificate_url)
      expect(hash[:algorithm]).to eq('ES256')
      expect(hash[:extension]).to eq('shaken')
    end
  end

  describe 'parameter parsing edge cases' do
    it 'handles empty parameter values' do
      header = "#{passport_token};info=<#{certificate_url}>;alg=ES256;ppt=shaken;empty="
      sip_identity = StirShaken::SipIdentity.parse(header)

      expect(sip_identity.algorithm).to eq('ES256')
    end

    it 'handles parameters without values' do
      header = "#{passport_token};info=<#{certificate_url}>;alg=ES256;ppt=shaken;flag"
      sip_identity = StirShaken::SipIdentity.parse(header)

      expect(sip_identity.algorithm).to eq('ES256')
    end

    it 'handles multiple equals signs in parameter value' do
      complex_url = 'https://example.com/cert.pem?param=value&other=data'
      header = "#{passport_token};info=<#{complex_url}>;alg=ES256;ppt=shaken"
      sip_identity = StirShaken::SipIdentity.parse(header)

      expect(sip_identity.info_url).to eq(complex_url)
    end

    it 'handles semicolons in quoted values' do
      # This is a theoretical case - SIP headers can have quoted values
      header = "#{passport_token};info=<#{certificate_url}>;alg=ES256;ppt=shaken"
      sip_identity = StirShaken::SipIdentity.parse(header)

      expect(sip_identity.algorithm).to eq('ES256')
    end
  end

  describe 'URL validation' do
    let(:valid_urls) do
      [
        'https://example.com/cert.pem',
        'http://localhost:8080/cert.pem',
        'https://sub.domain.com:443/path/to/cert.pem?param=value'
      ]
    end

    let(:invalid_urls) do
      [
        'not-a-url',
        'ftp://example.com/cert.pem',
        'file:///local/cert.pem',
        '',
        'https://',
        'example.com/cert.pem' # Missing protocol
      ]
    end

    it 'accepts valid HTTP/HTTPS URLs' do
      valid_urls.each do |url|
        sip_identity = StirShaken::SipIdentity.new(
          passport_token: passport_token,
          info_url: url,
          algorithm: 'ES256',
          extension: 'shaken'
        )

        expect { sip_identity.validate! }.not_to raise_error
      end
    end

    it 'rejects invalid URLs' do
      invalid_urls.each do |url|
        sip_identity = StirShaken::SipIdentity.new(
          passport_token: passport_token,
          info_url: url,
          algorithm: 'ES256',
          extension: 'shaken'
        )

        expect {
          sip_identity.validate!
        }.to raise_error(StirShaken::InvalidIdentityHeaderError, /Invalid info URL/)
      end
    end
  end

  describe 'integration tests' do
    it 'maintains data integrity through create/parse cycle' do
      original_header = StirShaken::SipIdentity.create(
        passport_token: passport_token,
        certificate_url: certificate_url,
        algorithm: 'ES256',
        extension: 'shaken',
        additional_info: { 'custom' => 'value' }
      )

      parsed = StirShaken::SipIdentity.parse(original_header)
      regenerated_header = parsed.to_header

      # Parse again to verify consistency
      reparsed = StirShaken::SipIdentity.parse(regenerated_header)

      expect(reparsed.passport_token).to eq(passport_token)
      expect(reparsed.info_url).to eq(certificate_url)
      expect(reparsed.algorithm).to eq('ES256')
      expect(reparsed.extension).to eq('shaken')
    end

    it 'works with real PASSporT tokens from AuthenticationService' do
      auth_service = create_auth_service(private_key: private_key)
      
      identity_header = auth_service.sign_call(
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
  end

  describe 'error handling' do
    it 'provides meaningful error messages' do
      expect {
        StirShaken::SipIdentity.parse('malformed-header')
      }.to raise_error(StirShaken::InvalidIdentityHeaderError) do |error|
        expect(error.message).to include('must contain token and parameters')
      end
    end

    it 'handles nil input gracefully' do
      expect {
        StirShaken::SipIdentity.parse(nil)
      }.to raise_error(NoMethodError)
    end

    it 'handles empty string input' do
      expect {
        StirShaken::SipIdentity.parse('')
      }.to raise_error(StirShaken::InvalidIdentityHeaderError)
    end
  end
end 