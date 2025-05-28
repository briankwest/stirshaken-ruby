# frozen_string_literal: true

module StirShaken
  ##
  # SIP Identity Header implementation
  #
  # This class implements the SIP Identity header format as specified in RFC 8224
  # for carrying PASSporT tokens in SIP messages.
  class SipIdentity
    attr_reader :passport_token, :info_url, :algorithm, :extension

    ##
    # Initialize a SIP Identity object
    #
    # @param passport_token [String] the PASSporT JWT token
    # @param info_url [String] URL to certificate information
    # @param algorithm [String] the signing algorithm
    # @param extension [String] the PASSporT extension
    def initialize(passport_token:, info_url:, algorithm:, extension:)
      @passport_token = passport_token
      @info_url = info_url
      @algorithm = algorithm
      @extension = extension
    end

    ##
    # Create a SIP Identity header value
    #
    # @param passport_token [String] the PASSporT JWT token
    # @param certificate_url [String] URL to the certificate
    # @param algorithm [String] the signing algorithm (default: ES256)
    # @param extension [String] the extension (default: shaken)
    # @param additional_info [Hash] additional parameters
    # @return [String] the complete SIP Identity header value
    def self.create(passport_token:, certificate_url:, algorithm: 'ES256', 
                   extension: 'shaken', additional_info: {})
      
      # Build the header value
      header_parts = [passport_token]
      
      # Add required parameters
      params = []
      params << "info=<#{certificate_url}>"
      params << "alg=#{algorithm}"
      params << "ppt=#{extension}"
      
      # Add any additional parameters
      additional_info.each do |key, value|
        params << "#{key}=#{value}"
      end
      
      # Combine token and parameters
      "#{passport_token};#{params.join(';')}"
    end

    ##
    # Parse a SIP Identity header value
    #
    # @param header_value [String] the SIP Identity header value
    # @return [SipIdentity] parsed SIP Identity object
    def self.parse(header_value)
      # Split token from parameters
      parts = header_value.split(';', 2)
      
      unless parts.length >= 2
        raise InvalidIdentityHeaderError, 'SIP Identity header must contain token and parameters'
      end
      
      passport_token = parts[0].strip
      parameters_string = parts[1]
      
      # Parse parameters
      parameters = parse_parameters(parameters_string)
      
      # Extract required parameters
      info_url = extract_info_url(parameters['info'])
      algorithm = parameters['alg']
      extension = parameters['ppt']
      
      # Validate required parameters
      unless info_url
        raise InvalidIdentityHeaderError, 'Missing info parameter in SIP Identity header'
      end
      
      unless algorithm
        raise InvalidIdentityHeaderError, 'Missing alg parameter in SIP Identity header'
      end
      
      unless extension
        raise InvalidIdentityHeaderError, 'Missing ppt parameter in SIP Identity header'
      end
      
      new(
        passport_token: passport_token,
        info_url: info_url,
        algorithm: algorithm,
        extension: extension
      )
    end

    ##
    # Convert to SIP header string
    #
    # @return [String] the SIP Identity header value
    def to_header
      self.class.create(
        passport_token: passport_token,
        certificate_url: info_url,
        algorithm: algorithm,
        extension: extension
      )
    end

    ##
    # Parse the embedded PASSporT token
    #
    # @param public_key [OpenSSL::PKey::EC] public key for verification (optional)
    # @param verify_signature [Boolean] whether to verify the signature
    # @return [Passport] parsed PASSporT object
    def parse_passport(public_key: nil, verify_signature: true)
      Passport.parse(passport_token, public_key: public_key, verify_signature: verify_signature)
    end

    ##
    # Validate the SIP Identity header structure
    #
    # @raise [InvalidIdentityHeaderError] if validation fails
    def validate!
      # Validate algorithm
      unless algorithm == 'ES256'
        raise InvalidIdentityHeaderError, "Unsupported algorithm: #{algorithm}"
      end
      
      # Validate extension
      unless extension == 'shaken'
        raise InvalidIdentityHeaderError, "Unsupported extension: #{extension}"
      end
      
      # Validate info URL format
      unless valid_url?(info_url)
        raise InvalidIdentityHeaderError, "Invalid info URL: #{info_url}"
      end
      
      # Validate PASSporT token format (basic check)
      unless passport_token && passport_token.count('.') == 2
        raise InvalidIdentityHeaderError, 'Invalid PASSporT token format'
      end
    end

    ##
    # Get information about this SIP Identity
    #
    # @return [Hash] information hash
    def info
      {
        algorithm: algorithm,
        extension: extension,
        info_url: info_url,
        token_present: !passport_token.nil?,
        token_length: passport_token&.length
      }
    end

    ##
    # Convert to hash representation
    #
    # @return [Hash] hash representation
    def to_h
      {
        passport_token: passport_token,
        info_url: info_url,
        algorithm: algorithm,
        extension: extension
      }
    end

    private

    ##
    # Parse parameter string into hash
    #
    # @param parameters_string [String] the parameters string
    # @return [Hash] parsed parameters
    def self.parse_parameters(parameters_string)
      parameters = {}
      
      # Split by semicolon, but be careful with quoted values
      param_parts = parameters_string.split(';')
      
      param_parts.each do |part|
        part = part.strip
        next if part.empty?
        
        # Split on first equals sign
        key_value = part.split('=', 2)
        next unless key_value.length == 2
        
        key = key_value[0].strip
        value = key_value[1].strip
        
        parameters[key] = value
      end
      
      parameters
    end

    ##
    # Extract URL from info parameter (remove angle brackets)
    #
    # @param info_param [String] the info parameter value
    # @return [String] the extracted URL
    def self.extract_info_url(info_param)
      return nil unless info_param
      
      # Remove angle brackets if present
      if info_param.start_with?('<') && info_param.end_with?('>')
        info_param[1..-2]
      else
        info_param
      end
    end

    ##
    # Validate URL format
    #
    # @param url [String] the URL to validate
    # @return [Boolean] true if valid
    def valid_url?(url)
      return false if url.nil? || url.empty?
      
      uri = URI.parse(url)
      
      # Must be HTTP or HTTPS
      return false unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
      
      # Must have a scheme (http/https)
      return false if uri.scheme.nil?
      
      # Must have a host
      return false if uri.host.nil? || uri.host.empty?
      
      # Scheme must be http or https specifically
      return false unless ['http', 'https'].include?(uri.scheme.downcase)
      
      true
    rescue URI::InvalidURIError
      false
    end
  end
end 