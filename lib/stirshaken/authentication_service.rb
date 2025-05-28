# frozen_string_literal: true

module StirShaken
  ##
  # Authentication Service for STIR/SHAKEN
  #
  # This class implements RFC 8224 for creating and signing PASSporT tokens
  # and generating SIP Identity headers for call authentication.
  class AuthenticationService
    attr_reader :private_key, :certificate_url, :certificate

    ##
    # Initialize the authentication service
    #
    # @param private_key [OpenSSL::PKey::EC] the private key for signing
    # @param certificate_url [String] URL to the public certificate
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
    # @param destination_number [String] the called number
    # @param attestation [String] attestation level (A, B, or C)
    # @param origination_id [String] unique origination identifier (optional)
    # @param additional_info [Hash] additional information for the header (optional)
    # @return [String] the complete SIP Identity header value
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
        destination_numbers: Array(destination_numbers),
        attestation: attestation,
        origination_id: origination_id,
        certificate_url: certificate_url,
        private_key: private_key
      )
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
    # @param key [OpenSSL::PKey::EC] the private key to validate
    # @return [OpenSSL::PKey::EC] the validated key
    # @raise [ConfigurationError] if the key is invalid
    def validate_private_key!(key)
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
  end
end 