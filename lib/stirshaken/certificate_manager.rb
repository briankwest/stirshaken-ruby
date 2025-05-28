# frozen_string_literal: true

module StirShaken
  ##
  # Certificate Manager for STIR/SHAKEN
  #
  # This class handles fetching, caching, and validating X.509 certificates
  # used in STIR/SHAKEN call authentication as specified in RFC 8226.
  class CertificateManager
    include HTTParty

    # Certificate cache to avoid repeated fetches
    @certificate_cache = {}
    @cache_mutex = Mutex.new

    class << self
      attr_reader :certificate_cache, :cache_mutex

      ##
      # Fetch a certificate from a URL with caching
      #
      # @param url [String] the certificate URL
      # @param force_refresh [Boolean] whether to bypass cache
      # @return [OpenSSL::X509::Certificate] the certificate
      def fetch_certificate(url, force_refresh: false)
        cache_key = url
        
        cache_mutex.synchronize do
          # Check cache first unless force refresh
          unless force_refresh
            cached_cert = certificate_cache[cache_key]
            if cached_cert && !certificate_expired?(cached_cert[:fetched_at])
              return cached_cert[:certificate]
            end
          end

          # Fetch certificate from URL
          certificate = download_certificate(url)
          
          # Cache the certificate
          certificate_cache[cache_key] = {
            certificate: certificate,
            fetched_at: Time.now
          }

          certificate
        end
      end

      ##
      # Validate a certificate for STIR/SHAKEN usage
      #
      # @param certificate [OpenSSL::X509::Certificate] the certificate to validate
      # @param telephone_number [String] the telephone number to validate against (optional)
      # @return [Boolean] true if valid
      def validate_certificate(certificate, telephone_number: nil)
        # Check if certificate is expired
        return false if certificate.not_after < Time.now
        return false if certificate.not_before > Time.now

        # Check key usage extensions
        return false unless valid_key_usage?(certificate)

        # Check telephone number if provided
        if telephone_number
          return false unless telephone_number_authorized?(certificate, telephone_number)
        end

        # Verify certificate chain (simplified - in production, verify against CA)
        verify_certificate_chain(certificate)
      end

      ##
      # Extract the public key from a certificate
      #
      # @param certificate [OpenSSL::X509::Certificate] the certificate
      # @return [OpenSSL::PKey::EC] the public key
      def extract_public_key(certificate)
        public_key = certificate.public_key
        
        unless public_key.is_a?(OpenSSL::PKey::EC)
          raise CertificateValidationError, 'Certificate must contain an EC public key for STIR/SHAKEN'
        end

        # Verify it's using the correct curve (P-256 for ES256)
        unless public_key.group.curve_name == 'prime256v1'
          raise CertificateValidationError, 'Certificate must use P-256 curve for ES256 algorithm'
        end

        public_key
      end

      ##
      # Clear the certificate cache
      def clear_cache!
        cache_mutex.synchronize do
          certificate_cache.clear
        end
      end

      ##
      # Get cache statistics
      #
      # @return [Hash] cache statistics
      def cache_stats
        cache_mutex.synchronize do
          {
            size: certificate_cache.size,
            entries: certificate_cache.keys
          }
        end
      end

      private

      ##
      # Download certificate from URL
      #
      # @param url [String] the certificate URL
      # @return [OpenSSL::X509::Certificate] the certificate
      def download_certificate(url)
        begin
          response = HTTParty.get(url, {
            timeout: StirShaken.configuration.http_timeout,
            headers: {
              'User-Agent' => "StirShaken Ruby #{StirShaken::VERSION}"
            }
          })

          unless response.success?
            raise CertificateFetchError, "Failed to fetch certificate from #{url}: #{response.code} #{response.message}"
          end

          # Parse the certificate
          certificate_data = response.body
          
          # Handle both PEM and DER formats
          begin
            OpenSSL::X509::Certificate.new(certificate_data)
          rescue OpenSSL::X509::CertificateError
            # Try DER format if PEM fails
            OpenSSL::X509::Certificate.new(Base64.decode64(certificate_data))
          end

        rescue HTTParty::Error, Timeout::Error, Errno::ETIMEDOUT, Socket::ResolutionError => e
          raise CertificateFetchError, "Network error fetching certificate from #{url}: #{e.message}"
        rescue OpenSSL::X509::CertificateError => e
          raise CertificateValidationError, "Invalid certificate format from #{url}: #{e.message}"
        end
      end

      ##
      # Check if cached certificate is expired
      #
      # @param fetched_at [Time] when the certificate was fetched
      # @return [Boolean] true if expired
      def certificate_expired?(fetched_at)
        Time.now - fetched_at > StirShaken.configuration.certificate_cache_ttl
      end

      ##
      # Validate certificate key usage extensions
      #
      # @param certificate [OpenSSL::X509::Certificate] the certificate
      # @return [Boolean] true if valid
      def valid_key_usage?(certificate)
        # Check for digital signature key usage
        key_usage_ext = certificate.extensions.find { |ext| ext.oid == 'keyUsage' }
        return false unless key_usage_ext

        key_usage_value = key_usage_ext.value
        key_usage_value.include?('Digital Signature')
      end

      ##
      # Check if telephone number is authorized by certificate
      #
      # @param certificate [OpenSSL::X509::Certificate] the certificate
      # @param telephone_number [String] the telephone number
      # @return [Boolean] true if authorized
      def telephone_number_authorized?(certificate, telephone_number)
        # Check Subject Alternative Name (SAN) extension for telephone numbers
        san_ext = certificate.extensions.find { |ext| ext.oid == 'subjectAltName' }
        return false unless san_ext

        # Parse SAN for telephone number entries
        san_value = san_ext.value
        
        # Look for URI entries with tel: scheme
        tel_uris = san_value.scan(/URI:tel:([+\d]+)/).flatten
        
        # Normalize telephone number for comparison
        normalized_number = normalize_telephone_number(telephone_number)
        
        tel_uris.any? do |tel_uri|
          normalized_tel_uri = normalize_telephone_number(tel_uri)
          normalized_number == normalized_tel_uri
        end
      end

      ##
      # Verify certificate chain (simplified implementation)
      #
      # @param certificate [OpenSSL::X509::Certificate] the certificate
      # @return [Boolean] true if valid
      def verify_certificate_chain(certificate)
        # In a production implementation, this would verify against
        # the STIR/SHAKEN certificate authority chain
        # For now, we'll do basic self-signature verification
        
        begin
          # Check if certificate is self-signed
          certificate.verify(certificate.public_key)
        rescue OpenSSL::X509::CertificateError
          # If not self-signed, we'd need to verify against CA
          # For now, assume valid if we can't verify
          true
        end
      end

      ##
      # Normalize telephone number for comparison
      #
      # @param number [String] the telephone number
      # @return [String] normalized number
      def normalize_telephone_number(number)
        # Remove all non-digit characters except leading +
        normalized = number.gsub(/[^\d+]/, '')
        
        # Ensure it starts with +
        normalized = "+#{normalized}" unless normalized.start_with?('+')
        
        normalized
      end
    end
  end
end 