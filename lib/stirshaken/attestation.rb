# frozen_string_literal: true

module StirShaken
  ##
  # Attestation levels for STIR/SHAKEN
  #
  # This module defines the three levels of attestation as specified in RFC 8588:
  # - A: Full Attestation
  # - B: Partial Attestation  
  # - C: Gateway Attestation
  module Attestation
    # Full Attestation - The service provider has authenticated the calling party
    # and they are authorized to use the calling number
    FULL = 'A'

    # Partial Attestation - The service provider has authenticated the call origination,
    # but cannot verify the call source is authorized to use the calling number
    PARTIAL = 'B'

    # Gateway Attestation - The service provider has authenticated from where it
    # received the call, but cannot authenticate the call source
    GATEWAY = 'C'

    # All valid attestation levels
    VALID_LEVELS = [FULL, PARTIAL, GATEWAY].freeze

    class << self
      ##
      # Validate an attestation level
      #
      # @param level [String] the attestation level to validate
      # @return [Boolean] true if valid, false otherwise
      def valid?(level)
        VALID_LEVELS.include?(level)
      end

      ##
      # Validate an attestation level and raise an error if invalid
      #
      # @param level [String] the attestation level to validate
      # @raise [InvalidAttestationError] if the level is invalid
      # @return [String] the validated level
      def validate!(level)
        unless valid?(level)
          raise InvalidAttestationError, 
                "Invalid attestation level: #{level}. Must be one of: #{VALID_LEVELS.join(', ')}"
        end
        level
      end

      ##
      # Get a human-readable description of an attestation level
      #
      # @param level [String] the attestation level
      # @return [String] human-readable description
      def description(level)
        case level
        when FULL
          'Full Attestation - Service provider has authenticated the calling party and verified authorization'
        when PARTIAL
          'Partial Attestation - Service provider has authenticated call origination but cannot verify caller authorization'
        when GATEWAY
          'Gateway Attestation - Service provider has authenticated the gateway but cannot authenticate the call source'
        else
          'Unknown attestation level'
        end
      end

      ##
      # Get the confidence level for an attestation
      #
      # @param level [String] the attestation level
      # @return [Integer] confidence level (0-100)
      def confidence_level(level)
        case level
        when FULL
          100
        when PARTIAL
          75
        when GATEWAY
          50
        else
          0
        end
      end
    end
  end
end 