# frozen_string_literal: true

require 'jwt'
require 'openssl'
require 'base64'
require 'json'
require 'httparty'
require 'uri'
require 'time'

require_relative 'stirshaken/version'
require_relative 'stirshaken/errors'
require_relative 'stirshaken/passport'
require_relative 'stirshaken/certificate_manager'
require_relative 'stirshaken/authentication_service'
require_relative 'stirshaken/verification_service'
require_relative 'stirshaken/sip_identity'
require_relative 'stirshaken/attestation'

##
# STIR/SHAKEN Ruby Implementation
#
# This library provides a complete implementation of the STIR/SHAKEN protocols
# for caller ID authentication in telecommunications systems.
#
# @example Basic usage
#   # Create an authentication service
#   auth_service = StirShaken::AuthenticationService.new(
#     private_key: private_key,
#     certificate_url: 'https://example.com/cert.pem'
#   )
#
#   # Sign a call
#   identity_header = auth_service.sign_call(
#     originating_number: '+15551234567',
#     destination_number: '+15559876543',
#     attestation: 'A'
#   )
#
#   # Verify a call
#   verification_service = StirShaken::VerificationService.new
#   result = verification_service.verify_call(identity_header)
#
module StirShaken
  class << self
    ##
    # Configure the STIR/SHAKEN library
    #
    # @yield [Configuration] configuration object
    def configure
      yield(configuration)
    end

    ##
    # Get the current configuration
    #
    # @return [Configuration] current configuration
    def configuration
      @configuration ||= Configuration.new
    end

    ##
    # Reset configuration to defaults
    def reset_configuration!
      @configuration = Configuration.new
    end
  end

  ##
  # Configuration class for STIR/SHAKEN library
  class Configuration
    attr_accessor :certificate_cache_ttl, :http_timeout, :default_attestation

    def initialize
      @certificate_cache_ttl = 3600 # 1 hour
      @http_timeout = 30 # 30 seconds
      @default_attestation = 'C' # Gateway attestation
    end
  end
end 