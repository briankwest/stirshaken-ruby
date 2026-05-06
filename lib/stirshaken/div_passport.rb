# frozen_string_literal: true

module StirShaken
  ##
  # DIV PASSporT (Diverted PASSporT) implementation per RFC 8946.
  #
  # A DIV PASSporT carries: orig, dest, iat, and the div claim (original
  # destination only). It does NOT carry SHAKEN-specific claims such as
  # attest or origid -- those belong to RFC 8588.
  class DivPassport < Passport
    # Required extension for DIV PASSporT
    EXTENSION = 'div'

    ##
    # Create a new DIV PASSporT token for call diversion
    #
    # @param original_passport [Passport] the original PASSporT being diverted
    # @param new_destination [String, Array<String>] where call is being diverted to
    # @param original_destination [String] where call was originally going
    # @param certificate_url [String] URL to the signing certificate
    # @param private_key [OpenSSL::PKey::EC] private key for signing
    # @return [String] encoded DIV PASSporT JWT token
    def self.create_div(original_passport:, new_destination:, original_destination:,
                       certificate_url:, private_key:)
      validate_phone_number!(original_destination)

      new_destinations = Array(new_destination)
      new_destinations.each { |num| validate_phone_number!(num) }

      header = {
        'alg' => ALGORITHM,
        'typ' => TOKEN_TYPE,
        'ppt' => EXTENSION,
        'x5u' => certificate_url
      }

      # RFC 8946 §3: iat SHOULD match the original PASSporT's iat.
      payload = {
        'dest' => { 'tn' => new_destinations },
        'div'  => { 'tn' => original_destination },
        'iat'  => original_passport.issued_at,
        'orig' => { 'tn' => original_passport.originating_number }
      }

      JWT.encode(payload, private_key, ALGORITHM, header)
    end

    ##
    # Create a DIV PASSporT from an existing SHAKEN Identity header
    #
    # @param shaken_identity_header [String] the original SHAKEN Identity header
    # @param new_destination [String, Array<String>] where call is being diverted to
    # @param original_destination [String] where call was originally going
    # @param certificate_url [String] URL to the signing certificate
    # @param private_key [OpenSSL::PKey::EC] private key for signing
    # @param public_key [OpenSSL::PKey::EC] public key for verifying original (optional)
    # @return [String] encoded DIV PASSporT JWT token
    def self.create_from_identity_header(shaken_identity_header:, new_destination:,
                                       original_destination:, certificate_url:,
                                       private_key:, public_key: nil)
      sip_identity = SipIdentity.parse(shaken_identity_header)

      original_passport = sip_identity.parse_passport(
        public_key: public_key,
        verify_signature: !public_key.nil?
      )

      create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        certificate_url: certificate_url,
        private_key: private_key
      )
    end

    ##
    # Parse and validate a DIV PASSporT token
    #
    # @param token [String] the JWT token to parse
    # @param public_key [OpenSSL::PKey::EC] public key for verification (optional)
    # @param verify_signature [Boolean] whether to verify the signature
    # @return [DivPassport] parsed DIV PASSporT object
    def self.parse(token, public_key: nil, verify_signature: true)
      if verify_signature && public_key
        decoded = JWT.decode(token, public_key, true, { algorithm: ALGORITHM })
        payload = decoded[0]
        header = decoded[1]
      else
        payload, header = JWT.decode(token, nil, false)
      end

      div_passport = new(header: header, payload: payload)
      div_passport.validate!
      div_passport
    rescue JWT::DecodeError => e
      raise InvalidTokenError, "Failed to decode DIV PASSporT: #{e.message}"
    end

    ##
    # Verify DIV PASSporT chains back to its original PASSporT (RFC 8946)
    #
    # @param div_token [String] the DIV PASSporT JWT token
    # @param shaken_token [String] the original PASSporT JWT token
    # @param div_public_key [OpenSSL::PKey::EC] public key for DIV token verification
    # @param shaken_public_key [OpenSSL::PKey::EC] public key for original token verification (optional)
    # @return [Hash] verification result with :valid and :reason
    def self.verify_chain(div_token:, shaken_token:, div_public_key:, shaken_public_key: nil)
      div_passport = parse(div_token, public_key: div_public_key, verify_signature: true)

      shaken_passport = if shaken_public_key
                          Passport.parse(shaken_token, public_key: shaken_public_key, verify_signature: true)
                        else
                          Passport.parse(shaken_token, verify_signature: false)
                        end

      unless div_passport.originating_number == shaken_passport.originating_number
        return { valid: false, reason: 'Originating number mismatch between DIV and original PASSporTs' }
      end

      shaken_dests = shaken_passport.destination_numbers
      unless shaken_dests.include?(div_passport.original_destination)
        return { valid: false, reason: 'DIV original destination not found in original PASSporT destinations' }
      end

      { valid: true, div_passport: div_passport, shaken_passport: shaken_passport }
    end

    ##
    # Get the original destination (where call was originally going)
    #
    # @return [String] the original destination number
    def original_destination
      payload.dig('div', 'tn')
    end

    ##
    # Check if this is a valid DIV PASSporT
    #
    # @return [Boolean] true if this is a DIV PASSporT
    def div_passport?
      header['ppt'] == EXTENSION
    end

    ##
    # Validate the DIV PASSporT structure and claims
    #
    # @raise [PassportValidationError] if validation fails
    def validate!
      validate_header!
      validate_payload!
      validate_div_claims!
    end

    ##
    # Convert to hash representation including DIV-specific fields
    #
    # @return [Hash] hash representation of the DIV PASSporT
    def to_h
      super.except(:attestation, :origination_id).merge(
        original_destination: original_destination,
        div_passport: true
      )
    end

    private

    ##
    # Validate the JWT header for DIV PASSporT
    def validate_header!
      raise PassportValidationError, 'Missing header' unless header

      unless header['alg'] == ALGORITHM
        raise PassportValidationError, "Invalid algorithm: #{header['alg']}, expected #{ALGORITHM}"
      end

      unless header['typ'] == TOKEN_TYPE
        raise PassportValidationError, "Invalid type: #{header['typ']}, expected #{TOKEN_TYPE}"
      end

      unless header['ppt'] == EXTENSION
        raise PassportValidationError, "Invalid extension: #{header['ppt']}, expected #{EXTENSION}"
      end

      raise PassportValidationError, 'Missing certificate URL (x5u)' unless header['x5u']
    end

    ##
    # Validate the DIV PASSporT payload (RFC 8946 §3)
    def validate_payload!
      raise PassportValidationError, 'Missing payload' unless payload

      raise PassportValidationError, 'Missing dest' unless payload['dest']
      raise PassportValidationError, 'Missing iat' unless payload['iat']
      raise PassportValidationError, 'Missing orig' unless payload['orig']

      validate_phone_number!(originating_number) if originating_number
      destination_numbers.each { |num| validate_phone_number!(num) }
    end

    ##
    # Validate DIV-specific claims (RFC 8946 §3)
    def validate_div_claims!
      raise PassportValidationError, 'Missing div claim in DIV PASSporT' unless payload['div']
      raise PassportValidationError, 'Missing original destination (div.tn) in DIV PASSporT' unless original_destination

      validate_phone_number!(original_destination)
    end
  end
end
