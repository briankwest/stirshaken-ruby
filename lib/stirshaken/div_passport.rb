# frozen_string_literal: true

module StirShaken
  ##
  # DIV PASSporT (Diversion Personal Assertion Token) implementation
  #
  # This class implements RFC 8946 for creating and validating DIV PASSporT tokens
  # used in STIR/SHAKEN call diversion/forwarding scenarios.
  class DivPassport < Passport
    # Required extension for DIV PASSporT
    EXTENSION = 'div'
    
    # Valid diversion reasons per RFC 8946
    VALID_DIVERSION_REASONS = %w[
      forwarding
      deflection
      follow-me
      time-of-day
      user-busy
      no-answer
      unavailable
      unconditional
      away
      unknown
    ].freeze

    ##
    # Create a new DIV PASSporT token for call diversion
    #
    # @param original_passport [Passport] the original SHAKEN PASSporT
    # @param new_destination [String, Array<String>] where call is being diverted to
    # @param original_destination [String] where call was originally going
    # @param diversion_reason [String] reason for diversion (default: 'forwarding')
    # @param origination_id [String] unique origination identifier (optional)
    # @param certificate_url [String] URL to the signing certificate
    # @param private_key [OpenSSL::PKey::EC] private key for signing
    # @return [String] encoded DIV PASSporT JWT token
    def self.create_div(original_passport:, new_destination:, original_destination:,
                       diversion_reason: 'forwarding', origination_id: nil,
                       certificate_url:, private_key:)
      
      # Validate inputs
      validate_diversion_reason!(diversion_reason)
      validate_phone_number!(original_destination)
      
      new_destinations = Array(new_destination)
      new_destinations.each { |num| validate_phone_number!(num) }

      # Use original passport's origination_id if not provided
      origination_id ||= original_passport.origination_id

      # Create header with DIV extension
      header = {
        'alg' => ALGORITHM,
        'typ' => TOKEN_TYPE,
        'ppt' => EXTENSION,
        'x5u' => certificate_url
      }

      # Create payload with DIV-specific claims
      payload = {
        'attest' => original_passport.attestation,
        'dest' => { 'tn' => new_destinations },
        'div' => {
          'tn' => original_destination,
          'reason' => diversion_reason
        },
        'iat' => Time.now.to_i,
        'orig' => { 'tn' => original_passport.originating_number },
        'origid' => origination_id
      }

      # Sign the token
      JWT.encode(payload, private_key, ALGORITHM, header)
    end

    ##
    # Create a DIV PASSporT from an existing SHAKEN Identity header
    #
    # @param shaken_identity_header [String] the original SHAKEN Identity header
    # @param new_destination [String, Array<String>] where call is being diverted to
    # @param original_destination [String] where call was originally going
    # @param diversion_reason [String] reason for diversion
    # @param certificate_url [String] URL to the signing certificate
    # @param private_key [OpenSSL::PKey::EC] private key for signing
    # @param public_key [OpenSSL::PKey::EC] public key for verifying original (optional)
    # @return [String] encoded DIV PASSporT JWT token
    def self.create_from_identity_header(shaken_identity_header:, new_destination:, 
                                       original_destination:, diversion_reason: 'forwarding',
                                       certificate_url:, private_key:, public_key: nil)
      
      # Parse the original SHAKEN Identity header
      sip_identity = SipIdentity.parse(shaken_identity_header)
      
      # Extract and optionally verify the original PASSporT
      original_passport = sip_identity.parse_passport(
        public_key: public_key, 
        verify_signature: !public_key.nil?
      )

      # Create DIV PASSporT
      create_div(
        original_passport: original_passport,
        new_destination: new_destination,
        original_destination: original_destination,
        diversion_reason: diversion_reason,
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
      begin
        if verify_signature && public_key
          decoded = JWT.decode(token, public_key, true, { algorithm: ALGORITHM })
          payload = decoded[0]
          header = decoded[1]
        else
          # Decode without verification for inspection
          payload, header = JWT.decode(token, nil, false)
        end

        div_passport = new(header: header, payload: payload)
        div_passport.validate!
        div_passport
      rescue JWT::DecodeError => e
        raise InvalidTokenError, "Failed to decode DIV PASSporT: #{e.message}"
      end
    end

    ##
    # Get the original destination (where call was originally going)
    #
    # @return [String] the original destination number
    def original_destination
      payload.dig('div', 'tn')
    end

    ##
    # Get the diversion reason
    #
    # @return [String] the reason for diversion
    def diversion_reason
      payload.dig('div', 'reason')
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
      super # Call parent validation
      validate_div_claims!
    end

    ##
    # Convert to hash representation including DIV-specific fields
    #
    # @return [Hash] hash representation of the DIV PASSporT
    def to_h
      super.merge({
        original_destination: original_destination,
        diversion_reason: diversion_reason,
        div_passport: true
      })
    end

    private

    ##
    # Validate DIV-specific claims
    def validate_div_claims!
      unless payload['div']
        raise PassportValidationError, 'Missing div claim in DIV PASSporT'
      end

      unless original_destination
        raise PassportValidationError, 'Missing original destination (div.tn) in DIV PASSporT'
      end

      unless diversion_reason
        raise PassportValidationError, 'Missing diversion reason (div.reason) in DIV PASSporT'
      end

      # Validate diversion reason
      self.class.validate_diversion_reason!(diversion_reason)

      # Validate original destination format
      validate_phone_number!(original_destination)
    end

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

      unless header['x5u']
        raise PassportValidationError, 'Missing certificate URL (x5u)'
      end
    end

    ##
    # Validate diversion reason
    #
    # @param reason [String] diversion reason to validate
    # @raise [InvalidDiversionReasonError] if invalid
    def self.validate_diversion_reason!(reason)
      unless VALID_DIVERSION_REASONS.include?(reason)
        raise InvalidDiversionReasonError, 
              "Invalid diversion reason: #{reason}. Valid reasons: #{VALID_DIVERSION_REASONS.join(', ')}"
      end
    end
  end
end 