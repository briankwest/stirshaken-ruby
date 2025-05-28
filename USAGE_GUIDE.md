# STIR/SHAKEN Ruby Library - Comprehensive Usage Guide

## Table of Contents

1. [Installation and Setup](#installation-and-setup)
2. [Basic Concepts](#basic-concepts)
3. [Authentication Service](#authentication-service)
4. [Verification Service](#verification-service)
5. [Certificate Management](#certificate-management)
6. [PASSporT Tokens](#passport-tokens)
7. [SIP Identity Headers](#sip-identity-headers)
8. [Attestation Levels](#attestation-levels)
9. [Configuration](#configuration)
10. [Error Handling](#error-handling)
11. [Advanced Usage](#advanced-usage)
12. [Production Deployment](#production-deployment)
13. [Troubleshooting](#troubleshooting)

## Installation and Setup

### Requirements

- Ruby 3.0+ (tested with Ruby 3.4.4)
- OpenSSL 3.0+
- Bundler 2.0+

### Installation

Add to your Gemfile:

```ruby
gem 'stirshaken'
```

Or install directly:

```bash
gem install stirshaken
```

### Basic Setup

```ruby
require 'stirshaken'

# Configure the library (optional - uses sensible defaults)
StirShaken.configure do |config|
  config.certificate_cache_ttl = 3600  # 1 hour cache
  config.http_timeout = 30             # 30 second timeout
end
```

## Basic Concepts

### STIR/SHAKEN Overview

STIR/SHAKEN is a framework for caller ID authentication:
- **STIR** (Secure Telephone Identity Revisited): The standards
- **SHAKEN** (Signature-based Handling of Asserted information using toKENs): The implementation

### Key Components

1. **PASSporT**: Personal Assertion Token (JWT-based)
2. **SIP Identity Header**: Carries PASSporT in SIP messages
3. **Certificates**: X.509 certificates for signing/verification
4. **Attestation Levels**: A (Full), B (Partial), C (Gateway)

## Authentication Service

The Authentication Service signs calls and creates PASSporT tokens.

### Creating an Authentication Service

```ruby
# Generate a key pair
key_pair = StirShaken::AuthenticationService.generate_key_pair
private_key = key_pair[:private_key]
public_key = key_pair[:public_key]

# Create a test certificate (for development)
certificate = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=My Telecom Company/O=Example Corp',
  telephone_numbers: ['+15551234567', '+15559876543']
)

# Initialize the service
auth_service = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: 'https://certs.example.com/stirshaken.pem',
  certificate: certificate  # Optional: provide certificate directly
)
```

### Signing Calls

#### Basic Call Signing

```ruby
# Sign a single call
identity_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

puts identity_header
# Output: eyJ0eXAiOiJwYXNzcG9ydCIsImFsZyI6IkVTMjU2IiwicHB0Ijoic2hha2VuIiwieDV1IjoiaHR0cHM6Ly9jZXJ0cy5leGFtcGxlLmNvbS9zdGlyc2hha2VuLnBlbSJ9.eyJhdHRlc3QiOiJBIiwiZGVzdCI6eyJ0biI6WyIrMTU1NTk4NzY1NDMiXX0sImlhdCI6MTcwMzI2ODAwMCwib3JpZyI6eyJ0biI6IisxNTU1MTIzNDU2NyJ9LCJvcmlnaWQiOiI1ZjIzNGE4Zi0xMjM0LTQ1NjctODkwMS0yMzQ1Njc4OTAxMjMifQ.signature;info=<https://certs.example.com/stirshaken.pem>;alg=ES256;ppt=shaken
```

#### Multiple Destination Numbers

```ruby
identity_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: ['+15559876543', '+15551111111', '+15552222222'],
  attestation: 'A'
)
```

#### Custom Origination ID

```ruby
identity_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A',
  origination_id: 'call-session-12345'
)
```

#### Additional SIP Header Parameters

```ruby
identity_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A',
  additional_info: {
    'custom' => 'value',
    'session-id' => '98765'
  }
)
```

### Creating PASSporT Tokens Directly

```ruby
passport_token = auth_service.create_passport(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A',
  origination_id: 'custom-id-123'  # Optional
)

puts passport_token
# Output: eyJ0eXAiOiJwYXNzcG9ydCIsImFsZyI6IkVTMjU2IiwicHB0Ijoic2hha2VuIiwieDV1IjoiaHR0cHM6Ly9jZXJ0cy5leGFtcGxlLmNvbS9zdGlyc2hha2VuLnBlbSJ9.eyJhdHRlc3QiOiJBIiwiZGVzdCI6eyJ0biI6WyIrMTU1NTk4NzY1NDMiXX0sImlhdCI6MTcwMzI2ODAwMCwib3JpZyI6eyJ0biI6IisxNTU1MTIzNDU2NyJ9LCJvcmlnaWQiOiJjdXN0b20taWQtMTIzIn0.signature
```

### Service Information and Validation

```ruby
# Get service information
info = auth_service.info
puts info
# Output: {
#   :certificate_url => "https://certs.example.com/stirshaken.pem",
#   :algorithm => "ES256",
#   :extension => "shaken",
#   :has_certificate => true,
#   :certificate_valid => true
# }

# Check if service is authorized for a number
authorized = auth_service.authorized_for_number?('+15551234567')
puts authorized  # true or false

# Check certificate validity
valid = auth_service.certificate_valid?
puts valid  # true or false
```

## Verification Service

The Verification Service validates incoming calls and PASSporT tokens.

### Creating a Verification Service

```ruby
verification_service = StirShaken::VerificationService.new
```

### Verifying Calls

#### Basic Call Verification

```ruby
# Verify using SIP Identity header
result = verification_service.verify_call(identity_header)

if result.valid?
  puts "Call verified successfully!"
  puts "Attestation: #{result.attestation}"
  puts "Confidence: #{result.confidence_level}%"
  puts "Originating: #{result.passport.originating_number}"
  puts "Destinations: #{result.passport.destination_numbers}"
else
  puts "Verification failed: #{result.reason}"
end
```

#### Verification with Expected Numbers

```ruby
# Verify with expected originating number
result = verification_service.verify_call(
  identity_header,
  originating_number: '+15551234567'
)

# Verify with expected destination number
result = verification_service.verify_call(
  identity_header,
  destination_number: '+15559876543'
)

# Verify with both
result = verification_service.verify_call(
  identity_header,
  originating_number: '+15551234567',
  destination_number: '+15559876543'
)
```

#### Custom Token Age Validation

```ruby
# Allow tokens up to 2 minutes old
result = verification_service.verify_call(
  identity_header,
  max_age: 120
)
```

### Verifying PASSporT Tokens Directly

```ruby
result = verification_service.verify_passport(
  passport_token,
  'https://certs.example.com/stirshaken.pem',
  max_age: 60
)

if result.valid?
  puts "Token verified!"
  puts "Attestation: #{result.attestation}"
else
  puts "Token invalid: #{result.reason}"
end
```

### Structure Validation (Debug Mode)

```ruby
# Validate structure without full cryptographic verification
info = verification_service.validate_structure(identity_header)

if info[:valid_structure]
  puts "Structure is valid"
  puts "Attestation: #{info[:attestation]}"
  puts "Algorithm: #{info[:algorithm]}"
  puts "Certificate URL: #{info[:certificate_url]}"
  puts "Originating: #{info[:originating_number]}"
  puts "Destinations: #{info[:destination_numbers]}"
else
  puts "Structure invalid: #{info[:error]}"
end
```

### Verification Statistics

```ruby
# Get verification statistics
stats = verification_service.stats

puts "Total verifications: #{stats[:total_verifications]}"
puts "Successful: #{stats[:successful_verifications]}"
puts "Failed: #{stats[:failed_verifications]}"
puts "Success rate: #{stats[:success_rate]}%"
puts "Cache stats: #{stats[:certificate_cache_stats]}"
```

## Certificate Management

### Fetching Certificates

```ruby
# Fetch certificate from URL
certificate = StirShaken::CertificateManager.fetch_certificate(
  'https://certs.example.com/stirshaken.pem'
)

# Force refresh (bypass cache)
certificate = StirShaken::CertificateManager.fetch_certificate(
  'https://certs.example.com/stirshaken.pem',
  force_refresh: true
)
```

### Certificate Validation

```ruby
# Basic certificate validation
valid = StirShaken::CertificateManager.validate_certificate(certificate)

# Validate with telephone number authorization
valid = StirShaken::CertificateManager.validate_certificate(
  certificate,
  telephone_number: '+15551234567'
)
```

### Extracting Public Keys

```ruby
public_key = StirShaken::CertificateManager.extract_public_key(certificate)
puts public_key.class  # OpenSSL::PKey::EC
```

### Cache Management

```ruby
# Get cache statistics
stats = StirShaken::CertificateManager.cache_stats
puts "Cache size: #{stats[:size]}"
puts "Cached URLs: #{stats[:entries]}"

# Clear cache
StirShaken::CertificateManager.clear_cache!
```

## PASSporT Tokens

### Creating PASSporT Tokens

```ruby
# Create token directly
token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A',
  certificate_url: 'https://certs.example.com/stirshaken.pem',
  private_key: private_key,
  origination_id: 'custom-id'  # Optional
)
```

### Parsing PASSporT Tokens

```ruby
# Parse without signature verification
passport = StirShaken::Passport.parse(token, verify_signature: false)

# Parse with signature verification
passport = StirShaken::Passport.parse(
  token,
  public_key: public_key,
  verify_signature: true
)

# Access token data
puts passport.originating_number      # "+15551234567"
puts passport.destination_numbers     # ["+15559876543"]
puts passport.attestation            # "A"
puts passport.origination_id         # "custom-id"
puts passport.issued_at              # Unix timestamp
puts passport.certificate_url        # "https://certs.example.com/stirshaken.pem"
```

### Token Validation

```ruby
# Check if token is expired
expired = passport.expired?           # Default: 60 seconds
expired = passport.expired?(max_age: 120)  # Custom age

# Validate token structure
begin
  passport.validate!
  puts "Token is valid"
rescue StirShaken::PassportValidationError => e
  puts "Token invalid: #{e.message}"
end

# Convert to hash
hash = passport.to_h
puts hash[:originating_number]
puts hash[:attestation]
```

### Phone Number Validation

```ruby
# Validate phone numbers
begin
  StirShaken::Passport.validate_phone_number!('+15551234567')
  puts "Valid phone number"
rescue StirShaken::InvalidPhoneNumberError => e
  puts "Invalid: #{e.message}"
end
```

## SIP Identity Headers

### Creating SIP Identity Headers

```ruby
# Create header
header = StirShaken::SipIdentity.create(
  passport_token: passport_token,
  certificate_url: 'https://certs.example.com/stirshaken.pem',
  algorithm: 'ES256',      # Optional: defaults to ES256
  extension: 'shaken',     # Optional: defaults to shaken
  additional_info: {       # Optional
    'custom' => 'value'
  }
)
```

### Parsing SIP Identity Headers

```ruby
# Parse header
sip_identity = StirShaken::SipIdentity.parse(header)

puts sip_identity.passport_token
puts sip_identity.info_url
puts sip_identity.algorithm
puts sip_identity.extension

# Extract PASSporT from header
passport = sip_identity.parse_passport(verify_signature: false)

# Extract and verify PASSporT
passport = sip_identity.parse_passport(
  public_key: public_key,
  verify_signature: true
)
```

### SIP Identity Validation

```ruby
begin
  sip_identity.validate!
  puts "SIP Identity is valid"
rescue StirShaken::InvalidIdentityHeaderError => e
  puts "Invalid: #{e.message}"
end

# Get information
info = sip_identity.info
puts info[:algorithm]        # "ES256"
puts info[:extension]        # "shaken"
puts info[:token_present]    # true/false
puts info[:token_length]     # Token length

# Convert to hash
hash = sip_identity.to_h
puts hash[:passport_token]
puts hash[:info_url]
```

### Converting Back to Header

```ruby
# Convert SIP Identity object back to header string
header_string = sip_identity.to_header
```

## Attestation Levels

### Understanding Attestation Levels

```ruby
# A = Full Attestation (100% confidence)
# B = Partial Attestation (75% confidence)  
# C = Gateway Attestation (50% confidence)

# Validate attestation level
begin
  StirShaken::Attestation.validate!('A')
  puts "Valid attestation"
rescue StirShaken::InvalidAttestationError => e
  puts "Invalid: #{e.message}"
end

# Check if valid
valid = StirShaken::Attestation.valid?('A')  # true
valid = StirShaken::Attestation.valid?('X')  # false

# Get confidence level
confidence = StirShaken::Attestation.confidence_level('A')  # 100
confidence = StirShaken::Attestation.confidence_level('B')  # 75
confidence = StirShaken::Attestation.confidence_level('C')  # 50

# Get description
desc = StirShaken::Attestation.description('A')  # "Full Attestation"
desc = StirShaken::Attestation.description('B')  # "Partial Attestation"
desc = StirShaken::Attestation.description('C')  # "Gateway Attestation"
```

### Using Attestation in Practice

```ruby
# Choose attestation based on your verification level
attestation = if fully_verified_call?
                'A'  # You verified the caller completely
              elsif partially_verified_call?
                'B'  # You verified some aspects
              else
                'C'  # Gateway/transit scenario
              end

identity_header = auth_service.sign_call(
  originating_number: originating_number,
  destination_number: destination_number,
  attestation: attestation
)
```

## Configuration

### Global Configuration

```ruby
StirShaken.configure do |config|
  # Certificate cache TTL in seconds (default: 3600)
  config.certificate_cache_ttl = 7200
  
  # HTTP timeout for certificate fetching (default: 30)
  config.http_timeout = 60
end

# Get current configuration
config = StirShaken.configuration
puts config.certificate_cache_ttl
puts config.http_timeout

# Reset to defaults
StirShaken.reset_configuration!
```

### Environment-Specific Configuration

```ruby
# Development
if Rails.env.development?
  StirShaken.configure do |config|
    config.certificate_cache_ttl = 300   # 5 minutes
    config.http_timeout = 10
  end
end

# Production
if Rails.env.production?
  StirShaken.configure do |config|
    config.certificate_cache_ttl = 3600  # 1 hour
    config.http_timeout = 30
  end
end
```

## Error Handling

### Exception Types

```ruby
begin
  # Your STIR/SHAKEN operations
rescue StirShaken::ConfigurationError => e
  # Invalid configuration (wrong key type, etc.)
  puts "Configuration error: #{e.message}"
  
rescue StirShaken::InvalidTokenError => e
  # Invalid PASSporT token format
  puts "Token error: #{e.message}"
  
rescue StirShaken::PassportValidationError => e
  # PASSporT validation failed
  puts "PASSporT validation error: #{e.message}"
  
rescue StirShaken::InvalidIdentityHeaderError => e
  # SIP Identity header format error
  puts "SIP Identity error: #{e.message}"
  
rescue StirShaken::CertificateFetchError => e
  # Failed to fetch certificate
  puts "Certificate fetch error: #{e.message}"
  
rescue StirShaken::CertificateValidationError => e
  # Certificate validation failed
  puts "Certificate validation error: #{e.message}"
  
rescue StirShaken::InvalidAttestationError => e
  # Invalid attestation level
  puts "Attestation error: #{e.message}"
  
rescue StirShaken::InvalidPhoneNumberError => e
  # Invalid phone number format
  puts "Phone number error: #{e.message}"
  
rescue StirShaken::SignatureVerificationError => e
  # Signature verification failed
  puts "Signature error: #{e.message}"
end
```

### Graceful Error Handling

```ruby
def verify_call_safely(identity_header)
  result = verification_service.verify_call(identity_header)
  
  if result.valid?
    {
      status: :verified,
      attestation: result.attestation,
      confidence: result.confidence_level,
      originating_number: result.passport.originating_number
    }
  else
    {
      status: :failed,
      reason: result.reason,
      confidence: 0
    }
  end
rescue => e
  {
    status: :error,
    error: e.message,
    confidence: 0
  }
end
```

## Advanced Usage

### Custom Certificate Handling

```ruby
# Load certificate from file
cert_data = File.read('/path/to/certificate.pem')
certificate = OpenSSL::X509::Certificate.new(cert_data)

auth_service = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: 'https://certs.example.com/stirshaken.pem',
  certificate: certificate
)
```

### Batch Operations

```ruby
# Sign multiple calls efficiently
calls_to_sign = [
  { orig: '+15551234567', dest: '+15559876543', att: 'A' },
  { orig: '+15551234567', dest: '+15551111111', att: 'B' },
  { orig: '+15551234567', dest: '+15552222222', att: 'A' }
]

signed_calls = calls_to_sign.map do |call|
  auth_service.sign_call(
    originating_number: call[:orig],
    destination_number: call[:dest],
    attestation: call[:att]
  )
end

# Verify multiple calls
verification_results = signed_calls.map do |header|
  verification_service.verify_call(header)
end
```

### Custom Key Generation

```ruby
# Generate key with specific parameters
key = OpenSSL::PKey::EC.generate('prime256v1')

# Or load from existing key material
key_data = File.read('/path/to/private_key.pem')
key = OpenSSL::PKey::EC.new(key_data)

# Validate key before use
unless key.private_key?
  raise "Key must be a private key"
end

unless key.group.curve_name == 'prime256v1'
  raise "Key must use P-256 curve"
end
```

### Integration with SIP Servers

```ruby
class SipCallHandler
  def initialize
    @auth_service = create_auth_service
    @verification_service = StirShaken::VerificationService.new
  end
  
  def handle_outbound_call(originating_number, destination_number)
    # Sign outbound call
    identity_header = @auth_service.sign_call(
      originating_number: originating_number,
      destination_number: destination_number,
      attestation: determine_attestation(originating_number)
    )
    
    # Add to SIP INVITE
    sip_headers = {
      'Identity' => identity_header
    }
    
    send_sip_invite(destination_number, sip_headers)
  end
  
  def handle_inbound_call(sip_headers)
    identity_header = sip_headers['Identity']
    return handle_unverified_call unless identity_header
    
    result = @verification_service.verify_call(identity_header)
    
    if result.valid?
      handle_verified_call(result)
    else
      handle_failed_verification(result)
    end
  end
  
  private
  
  def determine_attestation(number)
    if fully_authorized?(number)
      'A'
    elsif partially_authorized?(number)
      'B'
    else
      'C'
    end
  end
end
```

## Production Deployment

### Security Considerations

```ruby
# 1. Secure key storage
# Store private keys securely (HSM, encrypted storage, etc.)
private_key = load_key_from_secure_storage

# 2. Certificate validation
# Always validate certificates in production
StirShaken.configure do |config|
  config.certificate_cache_ttl = 3600  # Reasonable cache time
  config.http_timeout = 30             # Reasonable timeout
end

# 3. Error monitoring
# Log verification failures for analysis
def verify_with_monitoring(identity_header)
  result = verification_service.verify_call(identity_header)
  
  unless result.valid?
    logger.warn "STIR/SHAKEN verification failed: #{result.reason}"
    metrics.increment('stirshaken.verification.failed')
  end
  
  result
end
```

### Performance Optimization

```ruby
# 1. Connection pooling for certificate fetching
# Configure HTTP client with connection pooling

# 2. Certificate caching
# Use appropriate cache TTL based on certificate lifetime
StirShaken.configure do |config|
  config.certificate_cache_ttl = 3600  # 1 hour
end

# 3. Batch processing
# Process multiple calls in batches when possible

# 4. Async verification
# Verify calls asynchronously when real-time isn't required
def verify_async(identity_header)
  Thread.new do
    result = verification_service.verify_call(identity_header)
    store_verification_result(result)
  end
end
```

### Monitoring and Metrics

```ruby
class StirShakenMetrics
  def initialize
    @verification_service = StirShaken::VerificationService.new
  end
  
  def collect_metrics
    stats = @verification_service.stats
    
    {
      total_verifications: stats[:total_verifications],
      success_rate: stats[:success_rate],
      cache_hit_rate: calculate_cache_hit_rate,
      average_verification_time: measure_verification_time
    }
  end
  
  private
  
  def calculate_cache_hit_rate
    cache_stats = StirShaken::CertificateManager.cache_stats
    # Calculate based on cache statistics
  end
  
  def measure_verification_time
    # Measure average verification time
  end
end
```

## Troubleshooting

### Common Issues

#### 1. Certificate Fetch Failures

```ruby
# Problem: Certificate URL returns 404
# Solution: Verify certificate URL and ensure it's accessible

begin
  cert = StirShaken::CertificateManager.fetch_certificate(cert_url)
rescue StirShaken::CertificateFetchError => e
  puts "Certificate fetch failed: #{e.message}"
  # Check URL, network connectivity, certificate availability
end
```

#### 2. Signature Verification Failures

```ruby
# Problem: Signature verification fails
# Solution: Ensure correct public key and token integrity

begin
  passport = StirShaken::Passport.parse(token, public_key: public_key, verify_signature: true)
rescue StirShaken::InvalidTokenError => e
  puts "Signature verification failed: #{e.message}"
  # Check: correct public key, token not modified, correct algorithm
end
```

#### 3. Phone Number Format Issues

```ruby
# Problem: Phone number validation fails
# Solution: Ensure E.164 format

begin
  StirShaken::Passport.validate_phone_number!('+15551234567')  # Correct
  StirShaken::Passport.validate_phone_number!('15551234567')   # Wrong - missing +
rescue StirShaken::InvalidPhoneNumberError => e
  puts "Invalid phone number: #{e.message}"
  # Ensure format: +[country code][number] (e.g., +15551234567)
end
```

#### 4. Token Expiration

```ruby
# Problem: Tokens expire too quickly
# Solution: Adjust max_age parameter

result = verification_service.verify_call(
  identity_header,
  max_age: 300  # Allow 5 minutes instead of default 60 seconds
)
```

### Debug Mode

```ruby
# Enable detailed logging
require 'logger'
logger = Logger.new(STDOUT)
logger.level = Logger::DEBUG

# Validate structure without full verification
info = verification_service.validate_structure(identity_header)
logger.debug "Structure validation: #{info}"

# Check certificate details
cert = StirShaken::CertificateManager.fetch_certificate(cert_url)
logger.debug "Certificate subject: #{cert.subject}"
logger.debug "Certificate valid from: #{cert.not_before}"
logger.debug "Certificate valid until: #{cert.not_after}"
```

### Testing Utilities

```ruby
# Generate test data for development
def create_test_scenario
  key_pair = StirShaken::AuthenticationService.generate_key_pair
  private_key = key_pair[:private_key]
  
  certificate = StirShaken::AuthenticationService.create_test_certificate(
    private_key,
    telephone_numbers: ['+15551234567']
  )
  
  auth_service = StirShaken::AuthenticationService.new(
    private_key: private_key,
    certificate_url: 'https://test.example.com/cert.pem',
    certificate: certificate
  )
  
  {
    auth_service: auth_service,
    private_key: private_key,
    public_key: key_pair[:public_key],
    certificate: certificate
  }
end

# Test end-to-end flow
test_data = create_test_scenario
identity_header = test_data[:auth_service].sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

verification_service = StirShaken::VerificationService.new
result = verification_service.verify_call(identity_header)
puts "Test verification: #{result.valid? ? 'PASS' : 'FAIL'}"
```

This comprehensive guide covers all aspects of the STIR/SHAKEN Ruby library. For additional support, refer to the test files in the `spec/` directory for more examples and edge cases. 