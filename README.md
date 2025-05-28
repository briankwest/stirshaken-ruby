# STIR/SHAKEN Ruby Implementation

A comprehensive Ruby library implementing STIR (Secure Telephone Identity Revisited) and SHAKEN (Signature-based Handling of Asserted information using toKENs) protocols for combating caller ID spoofing in telecommunications.

## Overview

STIR/SHAKEN is a suite of protocols designed to authenticate caller ID information and combat robocalls and caller ID spoofing. This Ruby implementation provides:

- **PASSporT (Personal Assertion Token)** creation and validation (RFC 8225)
- **SIP Identity Header** generation and parsing (RFC 8224)
- **SHAKEN Extension** support (RFC 8588)
- **Certificate Management** with caching and validation (RFC 8226)
- **Authentication Service** for signing calls
- **Verification Service** for validating calls

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'stirshaken'
```

And then execute:

```bash
$ bundle install
```

Or install it yourself as:

```bash
$ gem install stirshaken
```

## Quick Start

### Signing a Call (Authentication Service)

```ruby
require 'stirshaken'

# Generate a key pair for testing
key_pair = StirShaken::AuthenticationService.generate_key_pair
private_key = key_pair[:private_key]

# Create an authentication service
auth_service = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: 'https://example.com/cert.pem'
)

# Sign a call
identity_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'  # Full attestation
)

puts identity_header
# Output: eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9jZXJ0LnBlbSJ9...
```

### Verifying a Call (Verification Service)

```ruby
# Create a verification service
verification_service = StirShaken::VerificationService.new

# Verify a call
result = verification_service.verify_call(identity_header)

if result.valid?
  puts "Call verified! Attestation: #{result.attestation}"
  puts "Confidence: #{result.confidence_level}%"
else
  puts "Verification failed: #{result.reason}"
end
```

## Attestation Levels

STIR/SHAKEN defines three levels of attestation:

- **Full Attestation (A)** - Service provider has authenticated the calling party (100% confidence)
- **Partial Attestation (B)** - Call origination authenticated but caller authorization unverified (75% confidence)
- **Gateway Attestation (C)** - Only gateway authentication available (50% confidence)

```ruby
# Get attestation description
StirShaken::Attestation.description('A')
# "Full Attestation - Service provider has authenticated the calling party and verified authorization"

# Get confidence level
StirShaken::Attestation.confidence_level('A')  # 100
```

## Configuration

Configure the library globally:

```ruby
StirShaken.configure do |config|
  config.certificate_cache_ttl = 3600    # 1 hour cache TTL
  config.http_timeout = 30               # 30 second HTTP timeout
end
```

## Documentation

For comprehensive documentation, examples, and advanced usage patterns, see:

📖 **[USAGE_GUIDE.md](USAGE_GUIDE.md)** - Complete usage guide with all features and examples
🔒 **[SECURITY.md](SECURITY.md)** - Security policy, audit results, and best practices

The usage guide covers:
- Installation and setup
- All core components (Authentication, Verification, Certificates, PASSporT, SIP Identity)
- Attestation levels and configuration
- Error handling strategies
- Advanced usage patterns
- Production deployment considerations
- Troubleshooting and debugging

## Features

### Core Components

- **PASSporT Tokens**: JWT-based tokens with cryptographic signatures
- **SIP Identity Headers**: RFC 8224 compliant header generation and parsing
- **Certificate Management**: Automatic fetching, caching, and validation
- **Attestation Levels**: Full support for A, B, and C attestation levels
- **Phone Number Validation**: E.164 format validation and normalization

### Security

- ES256 algorithm enforcement (P-256 elliptic curve)
- Certificate chain validation
- Token expiration checking
- Phone number authorization verification
- Comprehensive input validation
- **Certificate Pinning**: SHA256 public key pinning support
- **Rate Limiting**: Built-in rate limiting for certificate fetches (10 requests/minute/URL)
- **Security Event Logging**: Comprehensive audit trail for all security events
- **Configuration Validation**: Security-enforced configuration constraints
- **Thread Safety**: Mutex-protected operations for concurrent access

### Performance

- Certificate caching with configurable TTL
- Thread-safe operations
- Efficient cryptographic operations
- Configurable HTTP timeouts

## Standards Compliance

This implementation follows these RFCs and standards:

- **RFC 8224** - Authenticated Identity Management in SIP
- **RFC 8225** - PASSporT: Personal Assertion Token
- **RFC 8226** - Secure Telephone Identity Credentials: Certificates
- **RFC 8588** - PASSporT Extension for SHAKEN
- **ATIS-1000074** - SHAKEN Framework

## Requirements

- Ruby 3.0+ (tested with Ruby 3.4.4)
- OpenSSL 3.0+
- Network access for certificate fetching

## Testing

The library includes a comprehensive test suite with 100% test coverage:

```bash
# Run all tests
bundle exec rspec

# Run with coverage
bundle exec rspec --format documentation
```

## Error Handling

The library provides comprehensive error handling with specific exception types:

```ruby
begin
  result = verification_service.verify_call(identity_header)
rescue StirShaken::CertificateFetchError => e
  puts "Certificate fetch failed: #{e.message}"
rescue StirShaken::SignatureVerificationError => e
  puts "Signature verification failed: #{e.message}"
rescue StirShaken::PassportValidationError => e
  puts "PASSporT validation failed: #{e.message}"
rescue StirShaken::Error => e
  puts "STIR/SHAKEN error: #{e.message}"
end
```

## Development

### Generate Test Certificates

```ruby
# Generate a key pair
key_pair = StirShaken::AuthenticationService.generate_key_pair
private_key = key_pair[:private_key]

# Create a test certificate
certificate = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Test STIR Certificate',
  telephone_numbers: ['+15551234567', '+15559876543']
)
```

### Structure Validation (Debug Mode)

For testing and debugging, you can validate structure without cryptographic verification:

```ruby
verification_service = StirShaken::VerificationService.new
info = verification_service.validate_structure(identity_header)

puts info[:valid_structure]           # true/false
puts info[:attestation_description]   # Human-readable attestation description
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -am 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions, issues, or contributions:

- 📖 Read the [comprehensive usage guide](USAGE_GUIDE.md)
- 🐛 Report issues on GitHub
- 💬 Join discussions in GitHub Discussions
- 📧 Contact the maintainers

## Acknowledgments

- ATIS SHAKEN Working Group for the standards
- IETF SIP Working Group for the RFCs
- The Ruby community for excellent cryptographic libraries 