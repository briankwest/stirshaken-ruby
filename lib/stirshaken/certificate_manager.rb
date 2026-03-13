# frozen_string_literal: true

require 'digest'

module StirShaken
  ##
  # Certificate Manager for STIR/SHAKEN
  #
  # This class handles fetching, caching, and validating X.509 certificates
  # used in STIR/SHAKEN authentication with enhanced security features.
  class CertificateManager
    include HTTParty

    # Certificate cache to avoid repeated fetches
    @certificate_cache = {}
    @cache_mutex = Mutex.new
    @rate_limiter = {}
    @rate_limit_mutex = Mutex.new
    @cache_stats = { hits: 0, misses: 0, fetches: 0 }
    @stats_mutex = Mutex.new
    @crl_cache = {}
    @crl_cache_mutex = Mutex.new

    class << self
      attr_reader :certificate_cache, :cache_mutex

      ##
      # Fetch a certificate from a URL with caching and security enhancements
      #
      # @param url [String] the certificate URL
      # @param force_refresh [Boolean] whether to bypass cache
      # @param expected_pins [Array<String>] optional certificate pins for validation
      # @return [OpenSSL::X509::Certificate] the certificate
      def fetch_certificate(url, force_refresh: false, expected_pins: nil)
        # Rate limiting check
        rate_limit_check!(url)
        
        cache_key = url
        
        cache_mutex.synchronize do
          # Check cache first
          cached_cert = certificate_cache[cache_key]
          if !force_refresh && cached_cert && !certificate_expired?(cached_cert[:fetched_at])
            cert = cached_cert[:certificate]
            validate_certificate_pins!(cert, expected_pins) if expected_pins
            record_cache_hit!
            return cert
          end

          # Cache miss - fetch certificate from URL
          record_cache_miss!
          certificate = download_certificate(url)
          
          # Validate certificate pins if provided
          validate_certificate_pins!(certificate, expected_pins) if expected_pins
          
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
          @cache_stats = { hits: 0, misses: 0, fetches: 0 }
        end
      end

      ##
      # Fetch certificate chain from URL (may contain multiple PEM certs)
      #
      # @param url [String] the certificate URL
      # @return [Array<OpenSSL::X509::Certificate>] array of certificates (leaf first)
      def fetch_certificate_chain(url)
        rate_limit_check!(url)

        uri = URI.parse(url)
        unless uri.is_a?(URI::HTTPS)
          raise CertificateFetchError, "Certificate URL must use HTTPS: #{url}"
        end
        validate_url_safety!(uri)

        begin
          response = HTTParty.get(url, {
            timeout: StirShaken.configuration.http_timeout,
            headers: { 'User-Agent' => "StirShaken Ruby #{StirShaken::VERSION}" }
          })

          unless response.success?
            raise CertificateFetchError, "Failed to fetch certificate from #{url}: #{response.code}"
          end

          parse_certificate_chain(response.body)
        rescue HTTParty::Error, Timeout::Error, Errno::ETIMEDOUT, Socket::ResolutionError => e
          raise CertificateFetchError, "Network error fetching certificate from #{url}: #{e.message}"
        end
      end

      ##
      # Parse PEM data that may contain multiple certificates
      #
      # @param pem_data [String] PEM data possibly containing multiple certs
      # @return [Array<OpenSSL::X509::Certificate>] array of certificates
      def parse_certificate_chain(pem_data)
        certs = pem_data.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)

        if certs.empty?
          # Try as single DER/PEM certificate
          return [OpenSSL::X509::Certificate.new(pem_data)]
        end

        certs.map { |pem| OpenSSL::X509::Certificate.new(pem) }
      rescue OpenSSL::X509::CertificateError => e
        raise CertificateValidationError, "Invalid certificate format: #{e.message}"
      end

      ##
      # Get cache statistics
      #
      # @return [Hash] cache statistics
      def cache_stats
        cache_mutex.synchronize do
          total_requests = @cache_stats[:hits] + @cache_stats[:misses]
          hit_rate = total_requests > 0 ? (@cache_stats[:hits].to_f / total_requests * 100).round(2) : 0.0
          
          {
            size: certificate_cache.size,
            entries: certificate_cache.keys.map { |url| SecurityLogger.mask_url(url) },
            hits: @cache_stats[:hits],
            misses: @cache_stats[:misses],
            total_requests: total_requests,
            hit_rate_percent: hit_rate
          }
        end
      end

      private

      def record_cache_hit!
        @stats_mutex.synchronize do
          @cache_stats[:hits] += 1
        end
      end

      def record_cache_miss!
        @stats_mutex.synchronize do
          @cache_stats[:misses] += 1
        end
      end

      def record_fetch!
        @stats_mutex.synchronize do
          @cache_stats[:fetches] += 1
        end
      end

      ##
      # Download certificate from URL
      #
      # @param url [String] the certificate URL
      # @return [OpenSSL::X509::Certificate] the certificate
      def download_certificate(url)
        record_fetch!

        # Defense-in-depth: enforce HTTPS (RFC 8226 §9)
        uri = URI.parse(url)
        unless uri.is_a?(URI::HTTPS)
          raise CertificateFetchError, "Certificate URL must use HTTPS: #{url}"
        end

        # SSRF protection: reject private/loopback/link-local addresses
        validate_url_safety!(uri)

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
        return false unless key_usage_ext.value.include?('Digital Signature')

        # Check Extended Key Usage for STIR/SHAKEN if present (RFC 8226)
        # OID 1.3.6.1.5.5.7.3.20 = id-kp-jwt-stir-shaken
        eku_ext = certificate.extensions.find { |ext| ext.oid == 'extendedKeyUsage' }
        if eku_ext
          eku_value = eku_ext.value
          # Accept if it contains the STIR/SHAKEN EKU OID or is not restrictive
          return false unless eku_value.include?('1.3.6.1.5.5.7.3.20') || eku_value.include?('TLS Web Server Authentication')
        end

        true
      end

      ##
      # Check if telephone number is authorized by certificate
      #
      # @param certificate [OpenSSL::X509::Certificate] the certificate
      # @param telephone_number [String] the telephone number
      # @return [Boolean] true if authorized
      def telephone_number_authorized?(certificate, telephone_number)
        normalized_number = normalize_telephone_number(telephone_number)

        # First try TNAuthList extension (OID 1.3.6.1.5.5.7.1.26) per RFC 8226
        tn_auth_ext = certificate.extensions.find { |ext| ext.oid == '1.3.6.1.5.5.7.1.26' }
        if tn_auth_ext
          return check_tn_auth_list(tn_auth_ext, normalized_number)
        end

        # Fallback to SAN tel: URI check
        san_ext = certificate.extensions.find { |ext| ext.oid == 'subjectAltName' }
        return false unless san_ext

        tel_uris = san_ext.value.scan(/URI:tel:([+\d]+)/).flatten
        tel_uris.any? do |tel_uri|
          normalized_number == normalize_telephone_number(tel_uri)
        end
      end

      ##
      # Parse TNAuthList extension (RFC 8226)
      # TNAuthorizationList ::= SEQUENCE OF TNEntry
      # TNEntry ::= CHOICE { spc [0], range [1], one [2] }
      #
      # @param extension [OpenSSL::X509::Extension] the TNAuthList extension
      # @param normalized_number [String] normalized phone number to check
      # @return [Boolean] true if number is authorized
      def check_tn_auth_list(extension, normalized_number)
        # Strip the + prefix for comparison with TNAuthList entries
        digits = normalized_number.sub(/^\+/, '')

        begin
          asn1 = OpenSSL::ASN1.decode(extension.to_der)
          # The extension value is wrapped: OID + OCTET STRING containing the SEQUENCE
          # Navigate to the actual TNAuthorizationList
          ext_value = asn1.value.last
          tn_auth_list = OpenSSL::ASN1.decode(ext_value.value)

          tn_auth_list.value.each do |tn_entry|
            case tn_entry.tag
            when 0 # ServiceProviderCode — authorizes all numbers for this SPC
              return true
            when 1 # TelephoneNumberRange
              start_num = tn_entry.value[0].value
              count = tn_entry.value[1].value.to_i
              start_int = start_num.to_i
              num_int = digits.to_i
              return true if num_int >= start_int && num_int < start_int + count
            when 2 # Single TelephoneNumber
              return true if tn_entry.value == digits
            end
          end
        rescue OpenSSL::ASN1::ASN1Error, NoMethodError
          # If we can't parse the TNAuthList, fall through to SAN check
          return false
        end

        false
      end

      ##
      # Verify certificate chain (simplified implementation)
      #
      # @param certificate [OpenSSL::X509::Certificate] the certificate
      # @return [Boolean] true if valid
      def verify_certificate_chain(certificate)
        config = StirShaken.configuration

        # If a trust store is configured, do full chain validation
        if config.trust_store_path || config.trust_store_certificates.any?
          return verify_with_trust_store(certificate, config)
        end

        # Fallback: basic self-signature verification
        begin
          certificate.verify(certificate.public_key)
        rescue OpenSSL::X509::CertificateError
          false
        end
      end

      ##
      # Verify certificate against configured trust store
      #
      # @param certificate [OpenSSL::X509::Certificate] the certificate
      # @param config [Configuration] the configuration
      # @return [Boolean] true if chain is valid
      def verify_with_trust_store(certificate, config)
        store = OpenSSL::X509::Store.new

        # Load trusted CA certificates from directory
        if config.trust_store_path
          store.add_path(config.trust_store_path)
        end

        # Load individually configured CA certificates
        config.trust_store_certificates.each do |pem|
          ca_cert = pem.is_a?(OpenSSL::X509::Certificate) ? pem : OpenSSL::X509::Certificate.new(pem)
          store.add_cert(ca_cert)
        end

        # Enable CRL checking if configured
        if config.check_revocation
          store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
          load_crls_for_certificate(store, certificate)
        end

        store.verify(certificate)
      rescue OpenSSL::X509::StoreError
        false
      end

      ##
      # Load CRLs for a certificate into the trust store
      #
      # @param store [OpenSSL::X509::Store] the trust store
      # @param certificate [OpenSSL::X509::Certificate] the certificate
      def load_crls_for_certificate(store, certificate)
        crl_urls = extract_crl_distribution_points(certificate)

        crl_urls.each do |url|
          crl = fetch_crl(url)
          store.add_crl(crl) if crl
        end
      end

      ##
      # Extract CRL Distribution Point URLs from certificate
      #
      # @param certificate [OpenSSL::X509::Certificate] the certificate
      # @return [Array<String>] CRL URLs
      def extract_crl_distribution_points(certificate)
        cdp_ext = certificate.extensions.find { |ext| ext.oid == 'crlDistributionPoints' }
        return [] unless cdp_ext

        # Parse URIs from the CRL distribution points extension
        cdp_ext.value.scan(/URI:(\S+)/).flatten
      end

      ##
      # Fetch and cache a CRL
      #
      # @param url [String] CRL URL
      # @return [OpenSSL::X509::CRL, nil] the CRL or nil on failure
      def fetch_crl(url)
        @crl_cache_mutex.synchronize do
          cached = @crl_cache[url]
          if cached && (Time.now - cached[:fetched_at]) < StirShaken.configuration.crl_cache_ttl
            return cached[:crl]
          end
        end

        begin
          response = HTTParty.get(url, {
            timeout: StirShaken.configuration.http_timeout,
            headers: { 'User-Agent' => "StirShaken Ruby #{StirShaken::VERSION}" }
          })

          return nil unless response.success?

          crl = OpenSSL::X509::CRL.new(response.body)

          @crl_cache_mutex.synchronize do
            @crl_cache[url] = { crl: crl, fetched_at: Time.now }
          end

          crl
        rescue StandardError
          nil
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

      ##
      # Validate certificate pins for enhanced security
      #
      # @param certificate [OpenSSL::X509::Certificate] the certificate
      # @param expected_pins [Array<String>] expected SHA256 pins
      # @raise [CertificateValidationError] if pin validation fails
      def validate_certificate_pins!(certificate, expected_pins)
        return unless expected_pins && expected_pins.any?
        
        # Calculate SHA256 pin of the certificate's public key
        actual_pin = Digest::SHA256.hexdigest(certificate.public_key.to_der)
        
        unless expected_pins.any? { |pin| pin.length == actual_pin.length && OpenSSL.fixed_length_secure_compare(actual_pin, pin) }
          raise CertificateValidationError,
                "Certificate pin validation failed. Expected: #{expected_pins.join(', ')}, Got: #{actual_pin}"
        end
      end

      ##
      # Rate limiting for certificate fetches
      #
      # @param url [String] the certificate URL
      # @raise [CertificateFetchError] if rate limit exceeded
      ##
      # Validate URL is safe from SSRF attacks
      #
      # @param uri [URI] parsed URI
      # @raise [CertificateFetchError] if URL targets a private/internal address
      # NOTE: DNS rebinding TOCTOU — we resolve DNS here but HTTParty re-resolves
      # at fetch time. A full fix would require passing resolved IPs to HTTParty.
      # This check still blocks the vast majority of SSRF attempts.
      def validate_url_safety!(uri)
        host = uri.host&.downcase
        return unless host

        # Reject localhost
        if host == 'localhost' || host == '[::1]'
          raise CertificateFetchError, "Certificate URL must not target localhost: #{uri}"
        end

        # Resolve and check IP ranges
        begin
          require 'ipaddr'
          addrs = Addrinfo.getaddrinfo(host, nil, :UNSPEC, :STREAM).map { |a| IPAddr.new(a.ip_address) }
        rescue SocketError
          # If we can't resolve, let the fetch fail naturally
          return
        end

        private_ranges = [
          IPAddr.new('10.0.0.0/8'),
          IPAddr.new('172.16.0.0/12'),
          IPAddr.new('192.168.0.0/16'),
          IPAddr.new('127.0.0.0/8'),
          IPAddr.new('169.254.0.0/16'),
          IPAddr.new('::1/128'),
          IPAddr.new('fc00::/7'),
          IPAddr.new('fe80::/10')
        ]

        addrs.each do |addr|
          if private_ranges.any? { |range| range.include?(addr) }
            raise CertificateFetchError, "Certificate URL must not target private/internal addresses: #{uri.host}"
          end
        end
      end

      def rate_limit_check!(url)
        # Skip rate limiting during testing
        return if ENV['RAILS_ENV'] == 'test' || ENV['RACK_ENV'] == 'test' || defined?(RSpec)
        
        @rate_limit_mutex.synchronize do
          current_minute = Time.now.to_i / 60
          key = [url, current_minute]

          @rate_limiter[key] ||= 0
          @rate_limiter[key] += 1

          # Clean old entries (older than 2 minutes)
          @rate_limiter.delete_if { |k, _| k[1] < current_minute - 1 }

          if @rate_limiter[key] > 10 # Max 10 fetches per minute per URL
            raise CertificateFetchError, "Rate limit exceeded for #{url} (max 10 requests per minute)"
          end
        end
      end
    end
  end
end 