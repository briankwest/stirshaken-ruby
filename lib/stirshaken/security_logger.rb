# frozen_string_literal: true

module StirShaken
  ##
  # Security Logger for STIR/SHAKEN operations
  #
  # This module provides centralized security event logging for audit trails
  # and security monitoring in STIR/SHAKEN implementations.
  module SecurityLogger
    # Security event types
    EVENTS = {
      authentication_success: 'AUTH_SUCCESS',
      authentication_failure: 'AUTH_FAILURE',
      verification_success: 'VERIFY_SUCCESS',
      verification_failure: 'VERIFY_FAILURE',
      certificate_fetch: 'CERT_FETCH',
      certificate_validation_failure: 'CERT_INVALID',
      rate_limit_exceeded: 'RATE_LIMIT',
      invalid_input: 'INVALID_INPUT',
      configuration_error: 'CONFIG_ERROR',
      network_error: 'NETWORK_ERROR'
    }.freeze

    # Severity levels
    SEVERITY = {
      low: 'LOW',
      medium: 'MEDIUM',
      high: 'HIGH',
      critical: 'CRITICAL'
    }.freeze

    class << self
      ##
      # Log a security event
      #
      # @param event_type [Symbol] type of security event
      # @param details [Hash] additional event details
      # @param severity [Symbol] severity level (:low, :medium, :high, :critical)
      def log_security_event(event_type, details = {}, severity: nil)
        return unless enabled?
        
        severity ||= determine_severity(event_type)
        
        event = {
          timestamp: Time.now.iso8601,
          event_type: EVENTS[event_type] || event_type.to_s.upcase,
          severity: SEVERITY[severity] || severity.to_s.upcase,
          details: sanitize_details(details),
          library_version: StirShaken::VERSION,
          process_id: Process.pid
        }
        
        write_log_entry(event)
      end

      ##
      # Log authentication success
      #
      # @param originating_number [String] the calling number
      # @param destination_numbers [Array<String>] the called numbers
      # @param attestation [String] attestation level
      def log_authentication_success(originating_number, destination_numbers, attestation)
        log_security_event(:authentication_success, {
          originating_number: mask_phone_number(originating_number),
          destination_count: destination_numbers.size,
          attestation: attestation
        }, severity: :low)
      end

      ##
      # Log verification success
      #
      # @param identity_header [String] the SIP Identity header
      # @param result [Hash] verification result details
      def log_verification_success(identity_header, result)
        log_security_event(:verification_success, {
          header_length: identity_header.length,
          attestation: result[:attestation],
          certificate_url: mask_url(result[:certificate_url])
        }, severity: :low)
      end

      ##
      # Log security failure events
      #
      # @param event_type [Symbol] type of failure
      # @param error [Exception] the error that occurred
      # @param context [Hash] additional context
      def log_security_failure(event_type, error, context = {})
        log_security_event(event_type, {
          error_class: error.class.name,
          error_message: error.message,
          context: context
        }, severity: determine_failure_severity(error))
      end

      ##
      # Log certificate fetch events
      #
      # @param url [String] certificate URL
      # @param success [Boolean] whether fetch was successful
      # @param cache_hit [Boolean] whether result came from cache
      def log_certificate_fetch(url, success, cache_hit: false)
        log_security_event(:certificate_fetch, {
          url: mask_url(url),
          success: success,
          cache_hit: cache_hit
        }, severity: success ? :low : :medium)
      end

      ##
      # Log rate limiting events
      #
      # @param url [String] the URL that was rate limited
      # @param current_count [Integer] current request count
      def log_rate_limit_exceeded(url, current_count)
        log_security_event(:rate_limit_exceeded, {
          url: mask_url(url),
          request_count: current_count
        }, severity: :high)
      end

      ##
      # Check if security logging is enabled
      #
      # @return [Boolean] true if logging is enabled
      def enabled?
        # Enable by default, can be disabled via environment variable
        ENV['STIRSHAKEN_SECURITY_LOGGING'] != 'false'
      end

      private

      ##
      # Determine severity based on event type
      #
      # @param event_type [Symbol] the event type
      # @return [Symbol] severity level
      def determine_severity(event_type)
        case event_type
        when :authentication_success, :verification_success, :certificate_fetch
          :low
        when :authentication_failure, :verification_failure, :certificate_validation_failure
          :medium
        when :rate_limit_exceeded, :configuration_error
          :high
        when :network_error, :invalid_input
          :medium
        else
          :medium
        end
      end

      ##
      # Determine severity for failure events
      #
      # @param error [Exception] the error
      # @return [Symbol] severity level
      def determine_failure_severity(error)
        case error
        when StirShaken::ConfigurationError
          :critical
        when StirShaken::CertificateFetchError
          :high
        when StirShaken::SignatureVerificationError
          :high
        when StirShaken::InvalidPhoneNumberError, StirShaken::InvalidAttestationError
          :medium
        else
          :medium
        end
      end

      ##
      # Sanitize sensitive details from log entries
      #
      # @param details [Hash] raw details
      # @return [Hash] sanitized details
      def sanitize_details(details)
        sanitized = details.dup
        
        # Remove or mask sensitive information
        sanitized.delete(:private_key) if sanitized[:private_key]
        sanitized.delete(:jwt_token) if sanitized[:jwt_token]
        
        # Mask phone numbers
        if sanitized[:originating_number]
          sanitized[:originating_number] = mask_phone_number(sanitized[:originating_number])
        end
        
        sanitized
      end

      ##
      # Mask phone number for logging (keep country code + last 4 digits)
      #
      # @param phone_number [String] the phone number
      # @return [String] masked phone number
      def mask_phone_number(phone_number)
        return phone_number unless phone_number.is_a?(String) && phone_number.length > 6
        
        # Keep country code and last 4 digits: +1***1234
        country_code = phone_number[0..2]  # +1 or +44, etc.
        last_digits = phone_number[-4..-1]
        masked_middle = '*' * (phone_number.length - 6)
        
        "#{country_code}#{masked_middle}#{last_digits}"
      end

      ##
      # Mask URL for logging (keep domain, mask path)
      #
      # @param url [String] the URL
      # @return [String] masked URL
      def mask_url(url)
        return url unless url.is_a?(String)
        
        begin
          uri = URI.parse(url)
          "#{uri.scheme}://#{uri.host}#{uri.port != 80 && uri.port != 443 ? ":#{uri.port}" : ''}/***"
        rescue URI::InvalidURIError
          '***'
        end
      end

      ##
      # Write log entry to appropriate destination
      #
      # @param event [Hash] the log event
      def write_log_entry(event)
        log_message = "[STIRSHAKEN-SECURITY] #{event.to_json}"
        
        # Try to use Rails logger if available, otherwise use standard output
        if defined?(Rails) && Rails.logger
          case event[:severity]
          when 'CRITICAL', 'HIGH'
            Rails.logger.error(log_message)
          when 'MEDIUM'
            Rails.logger.warn(log_message)
          else
            Rails.logger.info(log_message)
          end
        else
          # Fallback to standard error for security events
          $stderr.puts log_message
        end
      end
    end
  end
end 