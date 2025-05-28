# frozen_string_literal: true

module StirShaken
  ##
  # Base error class for all STIR/SHAKEN related errors
  class Error < StandardError; end

  ##
  # Error raised when PASSporT validation fails
  class PassportValidationError < Error; end

  ##
  # Error raised when certificate operations fail
  class CertificateError < Error; end

  ##
  # Error raised when certificate cannot be fetched
  class CertificateFetchError < CertificateError; end

  ##
  # Error raised when certificate validation fails
  class CertificateValidationError < CertificateError; end

  ##
  # Error raised when signature verification fails
  class SignatureVerificationError < Error; end

  ##
  # Error raised when attestation level is invalid
  class InvalidAttestationError < Error; end

  ##
  # Error raised when phone number format is invalid
  class InvalidPhoneNumberError < Error; end

  ##
  # Error raised when SIP Identity header is malformed
  class InvalidIdentityHeaderError < Error; end

  ##
  # Error raised when JWT token is malformed or invalid
  class InvalidTokenError < Error; end

  ##
  # Error raised when required configuration is missing
  class ConfigurationError < Error; end
end 