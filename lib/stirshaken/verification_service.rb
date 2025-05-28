# frozen_string_literal: true

module StirShaken
  ##
  # Verification result structure
  class VerificationResult
    attr_reader :valid, :passport, :certificate, :attestation, :reason, :confidence_level

    def initialize(valid:, passport: nil, certificate: nil, attestation: nil, reason: nil, confidence_level: nil)
      @valid = valid
      @passport = passport
      @certificate = certificate
      @attestation = attestation
      @reason = reason
      @confidence_level = confidence_level || (attestation ? Attestation.confidence_level(attestation) : 0)
    end

    def valid?
      valid
    end

    def invalid?
      !valid
    end
  end

  ##
  # Verification Service for STIR/SHAKEN
  #
  # This class implements call verification by validating PASSporT tokens
  # and checking certificate authenticity.
  class VerificationService
    def initialize
      @verification_stats = {
        total_verifications: 0,
        successful_verifications: 0,
        failed_verifications: 0
      }
    end

    ##
    # Verify a call using a SIP Identity header
    #
    # @param identity_header [String] the SIP Identity header value
    # @param originating_number [String] expected originating number (optional)
    # @param destination_number [String] expected destination number (optional)
    # @param max_age [Integer] maximum age of token in seconds (default: 60)
    # @return [VerificationResult] verification result
    def verify_call(identity_header, originating_number: nil, destination_number: nil, max_age: 60)
      @verification_stats[:total_verifications] += 1
      
      # Handle nil or empty input
      if identity_header.nil? || identity_header.empty?
        @verification_stats[:failed_verifications] += 1
        return VerificationResult.new(
          valid: false,
          reason: 'Invalid Identity header: header cannot be nil or empty',
          confidence_level: 0
        )
      end
      
      begin
        # Parse the SIP Identity header
        sip_identity = SipIdentity.parse(identity_header)
        sip_identity.validate!

        # Fetch and validate certificate
        certificate = CertificateManager.fetch_certificate(sip_identity.info_url)
        
        unless CertificateManager.validate_certificate(certificate)
          @verification_stats[:failed_verifications] += 1
          return VerificationResult.new(
            valid: false,
            reason: 'Certificate validation failed',
            confidence_level: 0
          )
        end

        # Extract public key from certificate
        public_key = CertificateManager.extract_public_key(certificate)

        # Parse and verify PASSporT
        passport = sip_identity.parse_passport(public_key: public_key, verify_signature: true)

        # Check token age
        if passport.expired?(max_age: max_age)
          @verification_stats[:failed_verifications] += 1
          return VerificationResult.new(
            valid: false,
            passport: passport,
            certificate: certificate,
            attestation: passport.attestation,
            reason: 'Token expired',
            confidence_level: 0
          )
        end

        # Validate originating number if provided
        if originating_number && passport.originating_number != normalize_phone_number(originating_number)
          @verification_stats[:failed_verifications] += 1
          return VerificationResult.new(
            valid: false,
            passport: passport,
            certificate: certificate,
            attestation: passport.attestation,
            reason: 'Originating number mismatch',
            confidence_level: 0
          )
        end

        # Validate destination number if provided
        if destination_number
          normalized_dest = normalize_phone_number(destination_number)
          unless passport.destination_numbers.any? { |num| normalize_phone_number(num) == normalized_dest }
            @verification_stats[:failed_verifications] += 1
            return VerificationResult.new(
              valid: false,
              passport: passport,
              certificate: certificate,
              attestation: passport.attestation,
              reason: 'Destination number not found',
              confidence_level: 0
            )
          end
        end

        # Check if certificate authorizes the originating number
        if passport.originating_number && 
           !CertificateManager.validate_certificate(certificate, telephone_number: passport.originating_number)
          @verification_stats[:failed_verifications] += 1
          return VerificationResult.new(
            valid: false,
            passport: passport,
            certificate: certificate,
            attestation: passport.attestation,
            reason: 'Certificate not authorized for originating number',
            confidence_level: Attestation.confidence_level(passport.attestation) / 2
          )
        end

        # Successful verification
        @verification_stats[:successful_verifications] += 1
        VerificationResult.new(
          valid: true,
          passport: passport,
          certificate: certificate,
          attestation: passport.attestation,
          reason: nil,
          confidence_level: Attestation.confidence_level(passport.attestation)
        )

      rescue InvalidIdentityHeaderError => e
        @verification_stats[:failed_verifications] += 1
        VerificationResult.new(
          valid: false,
          reason: "Invalid Identity header: #{e.message}",
          confidence_level: 0
        )
      rescue CertificateFetchError => e
        @verification_stats[:failed_verifications] += 1
        VerificationResult.new(
          valid: false,
          reason: "Certificate fetch failed: #{e.message}",
          confidence_level: 0
        )
      rescue CertificateValidationError => e
        @verification_stats[:failed_verifications] += 1
        VerificationResult.new(
          valid: false,
          reason: "Certificate validation failed: #{e.message}",
          confidence_level: 0
        )
      rescue SignatureVerificationError, JWT::VerificationError => e
        @verification_stats[:failed_verifications] += 1
        VerificationResult.new(
          valid: false,
          reason: "Signature verification failed: #{e.message}",
          confidence_level: 0
        )
      rescue PassportValidationError => e
        @verification_stats[:failed_verifications] += 1
        VerificationResult.new(
          valid: false,
          reason: "PASSporT validation failed: #{e.message}",
          confidence_level: 0
        )
      rescue StandardError => e
        @verification_stats[:failed_verifications] += 1
        VerificationResult.new(
          valid: false,
          reason: "Verification error: #{e.message}",
          confidence_level: 0
        )
      end
    end

    ##
    # Verify a PASSporT token directly
    #
    # @param passport_token [String] the PASSporT JWT token
    # @param certificate_url [String] URL to the certificate
    # @param max_age [Integer] maximum age of token in seconds (default: 60)
    # @return [VerificationResult] verification result
    def verify_passport(passport_token, certificate_url, max_age: 60)
      begin
        # Fetch certificate
        certificate = CertificateManager.fetch_certificate(certificate_url)
        
        unless CertificateManager.validate_certificate(certificate)
          return VerificationResult.new(
            valid: false,
            reason: 'Certificate validation failed',
            confidence_level: 0
          )
        end

        # Extract public key
        public_key = CertificateManager.extract_public_key(certificate)

        # Parse and verify PASSporT
        passport = Passport.parse(passport_token, public_key: public_key, verify_signature: true)

        # Check token age
        if passport.expired?(max_age: max_age)
          return VerificationResult.new(
            valid: false,
            passport: passport,
            certificate: certificate,
            attestation: passport.attestation,
            reason: 'Token expired',
            confidence_level: 0
          )
        end

        # Check certificate authorization
        if passport.originating_number && 
           !CertificateManager.validate_certificate(certificate, telephone_number: passport.originating_number)
          return VerificationResult.new(
            valid: false,
            passport: passport,
            certificate: certificate,
            attestation: passport.attestation,
            reason: 'Certificate not authorized for originating number',
            confidence_level: Attestation.confidence_level(passport.attestation) / 2
          )
        end

        # Successful verification
        VerificationResult.new(
          valid: true,
          passport: passport,
          certificate: certificate,
          attestation: passport.attestation,
          reason: nil,
          confidence_level: Attestation.confidence_level(passport.attestation)
        )

      rescue CertificateFetchError => e
        VerificationResult.new(
          valid: false,
          reason: "Certificate fetch failed: #{e.message}",
          confidence_level: 0
        )
      rescue CertificateValidationError => e
        VerificationResult.new(
          valid: false,
          reason: "Certificate validation failed: #{e.message}",
          confidence_level: 0
        )
      rescue InvalidTokenError => e
        VerificationResult.new(
          valid: false,
          reason: "Invalid token format: #{e.message}",
          confidence_level: 0
        )
      rescue SignatureVerificationError, JWT::VerificationError => e
        VerificationResult.new(
          valid: false,
          reason: "Signature verification failed: #{e.message}",
          confidence_level: 0
        )
      rescue PassportValidationError => e
        VerificationResult.new(
          valid: false,
          reason: "PASSporT validation failed: #{e.message}",
          confidence_level: 0
        )
      rescue StandardError => e
        VerificationResult.new(
          valid: false,
          reason: "Verification error: #{e.message}",
          confidence_level: 0
        )
      end
    end

    ##
    # Get verification statistics
    #
    # @return [Hash] verification statistics
    def stats
      success_rate = if @verification_stats[:total_verifications] > 0
                       (@verification_stats[:successful_verifications].to_f / @verification_stats[:total_verifications]) * 100
                     else
                       0.0
                     end

      @verification_stats.merge(
        success_rate: success_rate,
        certificate_cache_stats: CertificateManager.cache_stats,
        configuration: {
          certificate_cache_ttl: StirShaken.configuration.certificate_cache_ttl,
          http_timeout: StirShaken.configuration.http_timeout
        }
      )
    end

    ##
    # Validate a call without full verification (for testing/debugging)
    #
    # @param identity_header [String] the SIP Identity header value
    # @return [Hash] validation information
    def validate_structure(identity_header)
      begin
        sip_identity = SipIdentity.parse(identity_header)
        sip_identity.validate!
        
        passport = sip_identity.parse_passport(verify_signature: false)
        
        {
          valid_structure: true,
          sip_identity: sip_identity.to_h,
          passport: passport.to_h,
          attestation: passport.attestation,
          originating_number: passport.originating_number,
          destination_numbers: passport.destination_numbers,
          certificate_url: passport.certificate_url,
          algorithm: passport.header['alg'],
          extension: passport.header['ppt'],
          issued_at: passport.issued_at,
          origination_id: passport.origination_id,
          attestation_description: Attestation.description(passport.attestation),
          confidence_level: Attestation.confidence_level(passport.attestation)
        }
      rescue InvalidTokenError => e
        {
          valid_structure: false,
          error: "Invalid token format: #{e.message}",
          error_class: e.class.name
        }
      rescue StandardError => e
        {
          valid_structure: false,
          error: e.message,
          error_class: e.class.name
        }
      end
    end

    private

    ##
    # Normalize phone number for comparison
    #
    # @param number [String] the phone number
    # @return [String] normalized number
    def normalize_phone_number(number)
      # Remove all non-digit characters except leading +
      normalized = number.gsub(/[^\d+]/, '')
      
      # Ensure it starts with +
      normalized = "+#{normalized}" unless normalized.start_with?('+')
      
      normalized
    end
  end
end 