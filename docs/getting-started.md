# Getting Started with stirshaken-ruby

This guide walks you through installing the `stirshaken` gem and using it to sign and verify calls with STIR/SHAKEN.

## Prerequisites

- **Ruby >= 3.4.0**
- Runtime dependencies (installed automatically with the gem):
  - `jwt` ~> 2.7
  - `httparty` ~> 0.21
  - `openssl` (stdlib)

## Installation

### Bundler

Add the gem to your `Gemfile`:

```ruby
gem 'stirshaken'
```

Then install:

```bash
bundle install
```

### Manual

```bash
gem install stirshaken
```

## Quick Start

The example below demonstrates the full STIR/SHAKEN flow: generating keys, signing a call, and verifying it.

### 1. Generate a Key Pair

`AuthenticationService.generate_key_pair` creates an ES256 (P-256 elliptic curve) key pair suitable for STIR/SHAKEN signing.

```ruby
require 'stirshaken'

key_pair = StirShaken::AuthenticationService.generate_key_pair
private_key = key_pair[:private_key]
public_key  = key_pair[:public_key]
```

### 2. Create a Test Certificate

For development and testing you can create a self-signed certificate. In production you would obtain a certificate from an authorized STI-CA (Certificate Authority).

```ruby
certificate = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Test STIR Certificate',
  telephone_numbers: ['+15551234567']
)
```

The `telephone_numbers` option embeds the specified numbers as `tel:` URIs in the certificate's Subject Alternative Name extension.

### 3. Create an AuthenticationService

The authentication service needs a private key and the HTTPS URL where verifiers can fetch the certificate.

```ruby
certificate_url = 'https://example.com/cert.pem'

auth_service = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: certificate_url,
  certificate: certificate
)
```

### 4. Sign a Call

`sign_call` creates a PASSporT token and wraps it in a SIP Identity header (per RFC 8224).

```ruby
identity_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)
```

The returned `identity_header` is a string you attach to the SIP INVITE as the `Identity` header value.

### 5. Create a VerificationService

The verification service takes no constructor arguments.

```ruby
verification_service = StirShaken::VerificationService.new
```

### 6. Mock the Certificate Fetch

During verification, the `VerificationService` fetches the signing certificate from the URL embedded in the PASSporT token (`x5u` header). In a test or development scenario, the URL does not serve a real certificate, so you need to pre-populate the certificate cache.

```ruby
# Seed the CertificateManager cache so verification does not make an HTTP request.
StirShaken::CertificateManager.cache_mutex.synchronize do
  StirShaken::CertificateManager.certificate_cache[certificate_url] = {
    certificate: certificate,
    fetched_at: Time.now
  }
end
```

In production this step is unnecessary -- the `VerificationService` fetches the certificate automatically over HTTPS.

### 7. Verify the Call

Pass the identity header to `verify_call`. The service parses the header, fetches (or cache-hits) the certificate, and validates the signature.

```ruby
result = verification_service.verify_call(identity_header)
```

### 8. Check the Result

`verify_call` returns a `VerificationResult` object.

```ruby
if result.valid?
  puts "Verification succeeded"
  puts "Attestation: #{result.attestation}"          # "A", "B", or "C"
  puts "Confidence:  #{result.confidence_level}%"     # 100, 75, or 50
else
  puts "Verification failed: #{result.reason}"
end
```

### Complete Example

```ruby
require 'stirshaken'

# 1. Generate keys
key_pair    = StirShaken::AuthenticationService.generate_key_pair
private_key = key_pair[:private_key]

# 2. Create test certificate
certificate = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  telephone_numbers: ['+15551234567']
)

# 3. Build authentication service
certificate_url = 'https://example.com/cert.pem'
auth_service = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: certificate_url,
  certificate: certificate
)

# 4. Sign the call
identity_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

# 5. Prepare for verification (mock the certificate fetch)
StirShaken::CertificateManager.cache_mutex.synchronize do
  StirShaken::CertificateManager.certificate_cache[certificate_url] = {
    certificate: certificate,
    fetched_at: Time.now
  }
end

# 6. Verify the call
verification_service = StirShaken::VerificationService.new
result = verification_service.verify_call(identity_header)

puts result.valid?           # => true
puts result.attestation      # => "A"
puts result.confidence_level # => 100
```

## Phone Number Format

All phone numbers must be in **E.164 format**:

- Begins with `+`
- Followed by 1 to 15 digits
- The first digit after `+` must be non-zero (1-9)

Valid examples: `+15551234567`, `+442071234567`, `+81312345678`

Invalid examples: `5551234567` (missing `+`), `+05551234567` (leading zero after `+`)

Passing an invalid number raises `StirShaken::InvalidPhoneNumberError`.

## Attestation Levels

STIR/SHAKEN defines three attestation levels (RFC 8588):

| Level | Name | Confidence | Description |
|-------|------|------------|-------------|
| **A** | Full Attestation | 100% | The service provider has authenticated the calling party and verified they are authorized to use the calling number. |
| **B** | Partial Attestation | 75% | The service provider has authenticated the call origination but cannot verify the caller is authorized to use the calling number. |
| **C** | Gateway Attestation | 50% | The service provider has authenticated the gateway but cannot authenticate the call source. |

Use the `StirShaken::Attestation` module for validation and lookup:

```ruby
StirShaken::Attestation.valid?('A')        # => true
StirShaken::Attestation.description('B')   # => "Partial Attestation - ..."
StirShaken::Attestation.confidence_level('C') # => 50
```

## Next Steps

- [Configuration Reference](configuration.md) -- all configuration options, defaults, and constraints.
