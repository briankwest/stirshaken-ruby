# frozen_string_literal: true

module StirShaken
  ##
  # Authentication Service for creating STIR/SHAKEN PASSporT tokens and SIP Identity headers
  #
  # This service handles the creation and signing of PASSporT tokens for call authentication.
  class AuthenticationService
    attr_reader :private_key, :certificate_url, :certificate

    ##
    # Initialize the authentication service
    #
    # @param private_key [OpenSSL::PKey::EC] private key for signing
    # @param certificate_url [String] URL to the certificate
    # @param certificate [OpenSSL::X509::Certificate] the certificate (optional)
    def initialize(private_key:, certificate_url:, certificate: nil)
      @private_key = validate_private_key!(private_key)
      @certificate_url = certificate_url
      @certificate = certificate
    end

    ##
    # Sign a call and create a SIP Identity header
    #
    # @param originating_number [String] the calling number
    # @param destination_number [String, Array<String>] the called number(s)
    # @param attestation [String] attestation level (A, B, or C)
    # @param origination_id [String] unique origination identifier (optional)
    # @param additional_info [Hash] additional SIP header parameters (optional)
    # @return [String] the complete SIP Identity header
    def sign_call(originating_number:, destination_number:, attestation:, 
                 origination_id: nil, additional_info: {})

      begin
        # Validate inputs
        Attestation.validate!(attestation)
        
        # Ensure destination is an array
        destination_numbers = Array(destination_number)
        
        # Create PASSporT token
        passport_token = Passport.create(
          originating_number: originating_number,
          destination_numbers: destination_numbers,
          attestation: attestation,
          origination_id: origination_id,
          certificate_url: certificate_url,
          private_key: private_key
        )

        # Create SIP Identity header
        identity_header = SipIdentity.create(
          passport_token: passport_token,
          certificate_url: certificate_url,
          algorithm: Passport::ALGORITHM,
          extension: Passport::EXTENSION,
          additional_info: additional_info
        )

        # Log successful authentication
        SecurityLogger.log_authentication_success(originating_number, destination_numbers, attestation)

        identity_header
      rescue => error
        # Log authentication failure
        SecurityLogger.log_security_failure(:authentication_failure, error, {
          originating_number: SecurityLogger.send(:mask_phone_number, originating_number),
          destination_count: Array(destination_number).size,
          attestation: attestation
        })
        raise
      end
    end

    ##
    # Create a PASSporT token without the SIP Identity header wrapper
    #
    # @param originating_number [String] the calling number
    # @param destination_numbers [Array<String>] the called number(s)
    # @param attestation [String] attestation level (A, B, or C)
    # @param origination_id [String] unique origination identifier (optional)
    # @return [String] the PASSporT JWT token
    def create_passport(originating_number:, destination_numbers:, attestation:, origination_id: nil)
      Passport.create(
        originating_number: originating_number,
        destination_numbers: destination_numbers,
        attestation: attestation,
        origination_id: origination_id,
        certificate_url: certificate_url,
        private_key: private_key
      )
    end

    ##
    # Create a DIV PASSporT token for call diversion/forwarding
    #
    # @param original_passport [Passport] the original SHAKEN PASSporT
    # @param new_destination [String, Array<String>] where call is being diverted to
    # @param original_destination [String] where call was originally going
    # @param diversion_reason [String] reason for diversion (default: 'forwarding')
    # @param origination_id [String] unique origination identifier (optional)
    # @return [String] the DIV PASSporT JWT token
    def create_div_passport(original_passport:, new_destination:, original_destination:,
                           diversion_reason: 'forwarding', origination_id: nil)
      begin
        div_token = DivPassport.create_div(
          original_passport: original_passport,
          new_destination: new_destination,
          original_destination: original_destination,
          diversion_reason: diversion_reason,
          origination_id: origination_id,
          certificate_url: certificate_url,
          private_key: private_key
        )

        # Log successful DIV PASSporT creation
        SecurityLogger.log_security_event(:div_passport_created, {
          originating_number: SecurityLogger.send(:mask_phone_number, original_passport.originating_number),
          original_destination: SecurityLogger.send(:mask_phone_number, original_destination),
          new_destination_count: Array(new_destination).size,
          diversion_reason: diversion_reason,
          attestation: original_passport.attestation
        }, severity: :low)

        div_token
      rescue => error
        # Log DIV PASSporT creation failure
        SecurityLogger.log_security_failure(:div_passport_creation_failure, error, {
          originating_number: SecurityLogger.send(:mask_phone_number, original_passport.originating_number),
          original_destination: SecurityLogger.send(:mask_phone_number, original_destination),
          diversion_reason: diversion_reason
        })
        raise
      end
    end

    ##
    # Create a DIV PASSporT from an existing SHAKEN Identity header
    #
    # @param shaken_identity_header [String] the original SHAKEN Identity header
    # @param new_destination [String, Array<String>] where call is being diverted to
    # @param original_destination [String] where call was originally going
    # @param diversion_reason [String] reason for diversion (default: 'forwarding')
    # @param verify_original [Boolean] whether to verify the original PASSporT signature
    # @return [String] the DIV PASSporT JWT token
    def create_div_passport_from_header(shaken_identity_header:, new_destination:, original_destination:,
                                       diversion_reason: 'forwarding', verify_original: false)
      begin
        # Determine public key for verification if requested
        public_key = verify_original ? CertificateManager.extract_public_key(certificate) : nil

        div_token = DivPassport.create_from_identity_header(
          shaken_identity_header: shaken_identity_header,
          new_destination: new_destination,
          original_destination: original_destination,
          diversion_reason: diversion_reason,
          certificate_url: certificate_url,
          private_key: private_key,
          public_key: public_key
        )

        # Log successful DIV PASSporT creation from header
        SecurityLogger.log_security_event(:div_passport_from_header_created, {
          original_destination: SecurityLogger.send(:mask_phone_number, original_destination),
          new_destination_count: Array(new_destination).size,
          diversion_reason: diversion_reason,
          verified_original: verify_original
        }, severity: :low)

        div_token
      rescue => error
        # Log DIV PASSporT creation failure
        SecurityLogger.log_security_failure(:div_passport_from_header_failure, error, {
          original_destination: SecurityLogger.send(:mask_phone_number, original_destination),
          diversion_reason: diversion_reason
        })
        raise
      end
    end

    ##
    # Sign a diverted call and create both SHAKEN and DIV SIP Identity headers
    #
    # @param shaken_identity_header [String] the original SHAKEN Identity header
    # @param new_destination [String, Array<String>] where call is being diverted to
    # @param original_destination [String] where call was originally going
    # @param diversion_reason [String] reason for diversion (default: 'forwarding')
    # @param verify_original [Boolean] whether to verify the original PASSporT signature
    # @param additional_info [Hash] additional SIP header parameters for DIV header
    # @return [Hash] hash with :shaken_header and :div_header
    def sign_diverted_call(shaken_identity_header:, new_destination:, original_destination:,
                          diversion_reason: 'forwarding', verify_original: false, additional_info: {})
      begin
        # Create DIV PASSporT token
        div_token = create_div_passport_from_header(
          shaken_identity_header: shaken_identity_header,
          new_destination: new_destination,
          original_destination: original_destination,
          diversion_reason: diversion_reason,
          verify_original: verify_original
        )

        # Create DIV SIP Identity header
        div_header = SipIdentity.create(
          passport_token: div_token,
          certificate_url: certificate_url,
          algorithm: DivPassport::ALGORITHM,
          extension: DivPassport::EXTENSION,
          additional_info: additional_info
        )

        # Log successful diverted call signing
        SecurityLogger.log_security_event(:diverted_call_signed, {
          original_destination: SecurityLogger.send(:mask_phone_number, original_destination),
          new_destination_count: Array(new_destination).size,
          diversion_reason: diversion_reason
        }, severity: :low)

        {
          shaken_header: shaken_identity_header,
          div_header: div_header
        }
      rescue => error
        # Log diverted call signing failure
        SecurityLogger.log_security_failure(:diverted_call_signing_failure, error, {
          original_destination: SecurityLogger.send(:mask_phone_number, original_destination),
          diversion_reason: diversion_reason
        })
        raise
      end
    end

    ##
    # Create a complete call forwarding scenario with proper attestation handling
    #
    # @param original_call_info [Hash] original call information
    # @param forwarding_info [Hash] forwarding information
    # @return [Hash] complete forwarding headers and metadata
    def create_call_forwarding(original_call_info:, forwarding_info:)
      begin
        # Extract original call information
        originating_number = original_call_info[:originating_number]
        original_destination = original_call_info[:destination_number]
        original_attestation = original_call_info[:attestation] || 'A'

        # Extract forwarding information
        new_destination = forwarding_info[:new_destination]
        diversion_reason = forwarding_info[:reason] || 'forwarding'
        
        # Determine appropriate attestation for forwarded call
        # Generally reduce attestation level for forwarded calls unless explicitly specified
        forwarded_attestation = forwarding_info[:attestation] || determine_forwarding_attestation(original_attestation)

        # Create original SHAKEN header (if not provided)
        shaken_header = original_call_info[:identity_header] || sign_call(
          originating_number: originating_number,
          destination_number: original_destination,
          attestation: original_attestation,
          origination_id: original_call_info[:origination_id]
        )

        # Create new SHAKEN header for forwarded destination with reduced attestation
        forwarded_shaken_header = sign_call(
          originating_number: originating_number,
          destination_number: new_destination,
          attestation: forwarded_attestation,
          origination_id: original_call_info[:origination_id] # Keep same origination ID
        )

        # Create DIV PASSporT to indicate forwarding
        div_result = sign_diverted_call(
          shaken_identity_header: shaken_header,
          new_destination: new_destination,
          original_destination: original_destination,
          diversion_reason: diversion_reason
        )

        # Log successful call forwarding setup
        SecurityLogger.log_security_event(:call_forwarding_created, {
          originating_number: SecurityLogger.send(:mask_phone_number, originating_number),
          original_destination: SecurityLogger.send(:mask_phone_number, original_destination),
          new_destination_count: Array(new_destination).size,
          original_attestation: original_attestation,
          forwarded_attestation: forwarded_attestation,
          diversion_reason: diversion_reason
        }, severity: :low)

        {
          original_shaken_header: shaken_header,
          forwarded_shaken_header: forwarded_shaken_header,
          div_header: div_result[:div_header],
          metadata: {
            originating_number: originating_number,
            original_destination: original_destination,
            new_destination: new_destination,
            original_attestation: original_attestation,
            forwarded_attestation: forwarded_attestation,
            diversion_reason: diversion_reason,
            origination_id: original_call_info[:origination_id]
          }
        }
      rescue => error
        # Log call forwarding failure
        SecurityLogger.log_security_failure(:call_forwarding_failure, error, {
          originating_number: SecurityLogger.send(:mask_phone_number, original_call_info[:originating_number]),
          original_destination: SecurityLogger.send(:mask_phone_number, original_call_info[:destination_number])
        })
        raise
      end
    end

    ##
    # Validate that the service can sign for a given telephone number
    #
    # @param telephone_number [String] the telephone number to validate
    # @return [Boolean] true if authorized
    def authorized_for_number?(telephone_number)
      return true unless certificate # Skip validation if no certificate provided

      CertificateManager.validate_certificate(certificate, telephone_number: telephone_number)
    end

    ##
    # Get information about this authentication service
    #
    # @return [Hash] service information
    def info
      {
        certificate_url: certificate_url,
        algorithm: Passport::ALGORITHM,
        extension: Passport::EXTENSION,
        has_certificate: !certificate.nil?,
        certificate_valid: certificate ? certificate_valid? : nil
      }
    end

    ##
    # Load the certificate from the configured URL
    #
    # @param force_refresh [Boolean] whether to bypass cache
    # @return [OpenSSL::X509::Certificate] the certificate
    def load_certificate(force_refresh: false)
      begin
        @certificate = CertificateManager.fetch_certificate(certificate_url, force_refresh: force_refresh)
        SecurityLogger.log_certificate_fetch(certificate_url, true)
        @certificate
      rescue => error
        SecurityLogger.log_certificate_fetch(certificate_url, false)
        SecurityLogger.log_security_failure(:certificate_fetch, error, { url: certificate_url })
        raise
      end
    end

    ##
    # Check if the loaded certificate is valid
    #
    # @return [Boolean] true if valid
    def certificate_valid?
      return false unless certificate
      CertificateManager.validate_certificate(certificate)
    end

    ##
    # Generate a new key pair for testing purposes
    #
    # @return [Hash] hash containing private_key and public_key
    def self.generate_key_pair
      # Use OpenSSL 3.0 compatible key generation
      private_key = OpenSSL::PKey::EC.generate('prime256v1')
      
      # Create a proper public key object from the private key
      public_key_pem = private_key.public_to_pem
      public_key = OpenSSL::PKey::EC.new(public_key_pem)

      {
        private_key: private_key,
        public_key: public_key
      }
    end

    ##
    # Create a self-signed certificate for testing purposes
    #
    # @param private_key [OpenSSL::PKey::EC] the private key
    # @param subject [String] the certificate subject
    # @param telephone_numbers [Array<String>] telephone numbers to include in SAN
    # @return [OpenSSL::X509::Certificate] the certificate
    def self.create_test_certificate(private_key, subject: '/CN=Test STIR Certificate', telephone_numbers: [])
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = OpenSSL::X509::Name.parse(subject)
      cert.issuer = cert.subject # Self-signed
      
      # Set the public key - handle different OpenSSL versions
      begin
        cert.public_key = private_key
      rescue TypeError
        # For older OpenSSL versions, extract the public key differently
        cert.public_key = private_key.public_key
      end
      
      cert.not_before = Time.now
      cert.not_after = Time.now + (365 * 24 * 60 * 60) # 1 year

      # Add extensions
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = cert

      # Key usage for digital signatures
      cert.add_extension(ef.create_extension('keyUsage', 'digitalSignature', true))
      
      # Subject Alternative Name with telephone numbers
      if telephone_numbers.any?
        san_values = telephone_numbers.map { |num| "URI:tel:#{num}" }
        cert.add_extension(ef.create_extension('subjectAltName', san_values.join(','), false))
      end

      # Sign the certificate
      cert.sign(private_key, OpenSSL::Digest::SHA256.new)
      cert
    end

    private

    ##
    # Validate the private key
    #
    # @param key [OpenSSL::PKey::EC, String] the private key to validate
    # @return [OpenSSL::PKey::EC] the validated key
    # @raise [ConfigurationError] if the key is invalid
    def validate_private_key!(key)
      # Handle string input by attempting to parse as PEM
      if key.is_a?(String)
        begin
          key = OpenSSL::PKey::EC.new(key)
        rescue OpenSSL::PKey::ECError, OpenSSL::PKey::PKeyError => e
          raise ConfigurationError, "Invalid private key format: #{e.message}"
        end
      end

      unless key.is_a?(OpenSSL::PKey::EC)
        raise ConfigurationError, 'Private key must be an EC key for STIR/SHAKEN'
      end

      unless key.group.curve_name == 'prime256v1'
        raise ConfigurationError, 'Private key must use P-256 curve for ES256 algorithm'
      end

      unless key.private_key?
        raise ConfigurationError, 'Provided key must be a private key'
      end

      key
    end

    ##
    # Determine appropriate attestation level for forwarded calls
    #
    # @param original_attestation [String] the original attestation level
    # @return [String] appropriate attestation for forwarded call
    def determine_forwarding_attestation(original_attestation)
      case original_attestation
      when 'A'
        'B' # Reduce from Full to Partial due to forwarding
      when 'B'
        'C' # Reduce from Partial to Gateway due to forwarding
      when 'C'
        'C' # Keep Gateway level (can't reduce further)
      else
        'C' # Default to Gateway for unknown attestation
      end
    end
  end
end 