# frozen_string_literal: true

require 'securerandom'

module StirShaken
  ##
  # PASSporT (Personal Assertion Token) implementation
  #
  # This class implements RFC 8225 for creating and validating PASSporT tokens
  # used in STIR/SHAKEN call authentication.
  class Passport
    # Required algorithm for STIR/SHAKEN
    ALGORITHM = 'ES256'
    
    # Required token type
    TOKEN_TYPE = 'passport'
    
    # Required extension for SHAKEN
    EXTENSION = 'shaken'

    attr_reader :header, :payload, :signature

    ##
    # Initialize a new PASSporT
    #
    # @param header [Hash] JWT header
    # @param payload [Hash] JWT payload
    # @param signature [String] JWT signature (optional for creation)
    def initialize(header: nil, payload: nil, signature: nil)
      @header = header
      @payload = payload
      @signature = signature
    end

    ##
    # Create a new PASSporT token
    #
    # @param originating_number [String] the calling number
    # @param destination_numbers [Array<String>] the called number(s)
    # @param attestation [String] attestation level (A, B, or C)
    # @param origination_id [String] unique origination identifier (optional)
    # @param certificate_url [String] URL to the signing certificate
    # @param private_key [OpenSSL::PKey::EC] private key for signing
    # @return [String] encoded JWT token
    def self.create(originating_number:, destination_numbers:, attestation:, 
                   origination_id: nil, certificate_url:, private_key:)
      
      # Validate inputs
      Attestation.validate!(attestation)
      validate_phone_number!(originating_number)
      destination_numbers.each { |num| validate_phone_number!(num) }

      # Generate origination ID if not provided
      origination_id ||= SecureRandom.uuid

      # Create header
      header = {
        'alg' => ALGORITHM,
        'typ' => TOKEN_TYPE,
        'ppt' => EXTENSION,
        'x5u' => certificate_url
      }

      # Create payload with claims in lexicographic order (RFC 8588 requirement)
      payload = {
        'attest' => attestation,
        'dest' => { 'tn' => destination_numbers },
        'iat' => Time.now.to_i,
        'orig' => { 'tn' => originating_number },
        'origid' => origination_id
      }

      # Sign the token
      JWT.encode(payload, private_key, ALGORITHM, header)
    end

    ##
    # Parse and validate a PASSporT token
    #
    # @param token [String] the JWT token to parse
    # @param public_key [OpenSSL::PKey::EC] public key for verification (optional)
    # @param verify_signature [Boolean] whether to verify the signature
    # @return [Passport] parsed PASSporT object
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

        passport = new(header: header, payload: payload)
        passport.validate!
        passport
      rescue JWT::DecodeError => e
        raise InvalidTokenError, "Failed to decode PASSporT: #{e.message}"
      end
    end

    ##
    # Validate the PASSporT structure and claims
    #
    # @raise [PassportValidationError] if validation fails
    def validate!
      validate_header!
      validate_payload!
    end

    ##
    # Get the originating telephone number
    #
    # @return [String] the originating number
    def originating_number
      payload.dig('orig', 'tn')
    end

    ##
    # Get the destination telephone numbers
    #
    # @return [Array<String>] the destination numbers
    def destination_numbers
      payload.dig('dest', 'tn') || []
    end

    ##
    # Get the attestation level
    #
    # @return [String] the attestation level
    def attestation
      payload['attest']
    end

    ##
    # Get the origination identifier
    #
    # @return [String] the origination ID
    def origination_id
      payload['origid']
    end

    ##
    # Get the issued at timestamp
    #
    # @return [Integer] Unix timestamp
    def issued_at
      payload['iat']
    end

    ##
    # Get the certificate URL
    #
    # @return [String] certificate URL
    def certificate_url
      header['x5u']
    end

    ##
    # Check if the token is expired
    #
    # @param max_age [Integer] maximum age in seconds (default: 60)
    # @return [Boolean] true if expired
    def expired?(max_age: 60)
      return true unless issued_at
      Time.now.to_i - issued_at > max_age
    end

    ##
    # Convert to hash representation
    #
    # @return [Hash] hash representation of the PASSporT
    def to_h
      {
        header: header,
        payload: payload,
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        origination_id: origination_id,
        issued_at: issued_at,
        certificate_url: certificate_url
      }
    end

    private

    ##
    # Validate the JWT header
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
    # Validate the JWT payload
    def validate_payload!
      raise PassportValidationError, 'Missing payload' unless payload

      # Validate required claims
      unless payload['attest']
        raise PassportValidationError, 'Missing attest'
      end

      unless payload['dest']
        raise PassportValidationError, 'Missing dest'
      end

      unless payload['iat']
        raise PassportValidationError, 'Missing iat'
      end

      unless payload['orig']
        raise PassportValidationError, 'Missing orig'
      end

      unless payload['origid']
        raise PassportValidationError, 'Missing origid'
      end

      # Validate attestation level
      Attestation.validate!(payload['attest'])

      # Validate phone numbers
      validate_phone_number!(originating_number) if originating_number
      destination_numbers.each { |num| validate_phone_number!(num) }
    end

    ##
    # Validate phone number format
    #
    # @param number [String] phone number to validate
    # @raise [InvalidPhoneNumberError] if invalid
    def self.validate_phone_number!(number)
      # Strict E.164 format validation
      # Must start with +, followed by 1-15 digits, first digit cannot be 0
      unless number.match?(/^\+[1-9]\d{1,14}$/)
        raise InvalidPhoneNumberError, "Invalid phone number format: #{number}"
      end
    end

    def validate_phone_number!(number)
      self.class.validate_phone_number!(number)
    end
  end
end 