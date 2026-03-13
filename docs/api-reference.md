# API Reference

Complete API reference for the `stirshaken` Ruby gem (v0.1.0).

All classes and modules live under the `StirShaken` namespace. The gem uses ES256 (P-256 elliptic curve) signatures with JWT-based PASSporT tokens per RFC 8224/8225/8226/8588.

---

## Table of Contents

- [StirShaken Module](#stirshaken-module)
- [StirShaken::Configuration](#stirshakenconfiguration)
- [StirShaken::AuthenticationService](#stirshakenauthenticationservice)
- [StirShaken::VerificationService](#stirshakenverificationservice)
- [StirShaken::VerificationResult](#stirshakenverificationresult)
- [StirShaken::Passport](#stirshakenpassport)
- [StirShaken::DivPassport](#stirshakendivpassport)
- [StirShaken::SipIdentity](#stirshakensipidentity)
- [StirShaken::CertificateManager](#stirshakencertificatemanager)
- [StirShaken::Attestation](#stirshakenattestation)
- [StirShaken::SecurityLogger](#stirshakensecuritylogger)
- [StirShaken::SignatureUtils](#stirshakensignatureutils)
- [Error Classes](#error-classes)

---

## StirShaken Module

Top-level module providing global configuration.

### `.configure { |config| ... }`

Configure the library globally. Yields a `Configuration` object. Calls `validate_security!` after the block completes (security validation is skipped in test environments).

```ruby
StirShaken.configure do |config|
  config.certificate_cache_ttl = 3600
  config.http_timeout = 30
  config.default_attestation = 'C'
  config.default_max_age = 60
end
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `config` (yielded) | `Configuration` | Configuration object |

**Returns:** Result of `validate_security!`

---

### `.configuration`

Returns the current configuration, initializing a new `Configuration` with defaults if none exists.

```ruby
config = StirShaken.configuration
```

**Returns:** `StirShaken::Configuration`

---

### `.reset_configuration!`

Resets configuration to default values by creating a new `Configuration` instance.

```ruby
StirShaken.reset_configuration!
```

**Returns:** `StirShaken::Configuration` (the new default instance)

---

## StirShaken::Configuration

Holds all library configuration with security validation.

### Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `certificate_cache_ttl` | `Numeric` | `3600` | Certificate cache TTL in seconds (valid range: 300-86400) |
| `http_timeout` | `Numeric` | `30` | HTTP request timeout in seconds (valid range: 5-120) |
| `default_attestation` | `String` | `'C'` | Default attestation level (`'A'`, `'B'`, or `'C'`) |
| `default_max_age` | `Numeric` | `60` | Default max token age in seconds (valid range: 1-900) |
| `trust_store_path` | `String, nil` | `nil` | Path to directory of trusted CA certificates |
| `trust_store_certificates` | `Array<String>` | `[]` | Array of PEM strings for trusted CA certificates |
| `check_revocation` | `Boolean` | `false` | Enable CRL/OCSP revocation checking |
| `crl_cache_ttl` | `Numeric` | `3600` | CRL cache TTL in seconds |

---

## StirShaken::AuthenticationService

Service for creating STIR/SHAKEN PASSporT tokens and SIP Identity headers.

### Class Methods

#### `.generate_key_pair`

Generate a new ES256 (P-256) key pair. Primarily intended for testing.

```ruby
keys = StirShaken::AuthenticationService.generate_key_pair
private_key = keys[:private_key]
public_key = keys[:public_key]
```

**Returns:** `Hash` with keys:
| Key | Type | Description |
|-----|------|-------------|
| `:private_key` | `OpenSSL::PKey::EC` | P-256 private key |
| `:public_key` | `OpenSSL::PKey::EC` | Corresponding public key |

---

#### `.create_test_certificate(private_key, subject:, telephone_numbers:)`

Create a self-signed X.509 certificate for testing. The certificate is valid for 1 year, includes a `digitalSignature` key usage extension, and optionally includes telephone numbers as `tel:` URIs in the Subject Alternative Name extension.

```ruby
cert = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Test STIR Certificate',
  telephone_numbers: ['+15551234567']
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `private_key` | `OpenSSL::PKey::EC` | (required) | EC private key for signing the certificate |
| `subject:` | `String` | `'/CN=Test STIR Certificate'` | X.509 subject distinguished name |
| `telephone_numbers:` | `Array<String>` | `[]` | Phone numbers to include in SAN as `URI:tel:` entries |

**Returns:** `OpenSSL::X509::Certificate`

---

### Instance Methods

#### `#initialize(private_key:, certificate_url:, certificate:)`

Create a new authentication service instance.

```ruby
auth = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: 'https://example.com/cert.pem',
  certificate: cert  # optional
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `private_key:` | `OpenSSL::PKey::EC, String` | (required) | EC private key (P-256) or PEM string |
| `certificate_url:` | `String` | (required) | URL where the signing certificate is hosted |
| `certificate:` | `OpenSSL::X509::Certificate` | `nil` | The certificate itself (optional) |

**Raises:** `ConfigurationError` if the private key is invalid, not EC, not P-256, or not a private key.

**Attributes (readers):** `private_key`, `certificate_url`, `certificate`

---

#### `#sign_call(originating_number:, destination_number:, attestation:, origination_id:, additional_info:)`

Sign a call by creating a PASSporT token and wrapping it in a SIP Identity header.

```ruby
header = auth.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A',
  origination_id: 'uuid-value',
  additional_info: { 'custom' => 'value' }
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `originating_number:` | `String` | (required) | Calling number in E.164 format (e.g., `+15551234567`) |
| `destination_number:` | `String, Array<String>` | (required) | Called number(s) in E.164 format |
| `attestation:` | `String` | (required) | Attestation level: `'A'`, `'B'`, or `'C'` |
| `origination_id:` | `String` | `nil` | Unique origination identifier (UUID auto-generated if omitted) |
| `additional_info:` | `Hash` | `{}` | Additional SIP header parameters |

**Returns:** `String` -- complete SIP Identity header value.

**Raises:** `InvalidAttestationError`, `InvalidPhoneNumberError`

---

#### `#create_passport(originating_number:, destination_numbers:, attestation:, origination_id:)`

Create a PASSporT JWT token without the SIP Identity header wrapper.

```ruby
token = auth.create_passport(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A'
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `originating_number:` | `String` | (required) | Calling number in E.164 format |
| `destination_numbers:` | `Array<String>` | (required) | Called number(s) in E.164 format |
| `attestation:` | `String` | (required) | Attestation level: `'A'`, `'B'`, or `'C'` |
| `origination_id:` | `String` | `nil` | Unique origination identifier |

**Returns:** `String` -- encoded PASSporT JWT token.

---

#### `#create_div_passport(original_passport:, new_destination:, original_destination:, diversion_reason:, origination_id:)`

Create a DIV PASSporT token for call diversion/forwarding.

```ruby
div_token = auth.create_div_passport(
  original_passport: passport,
  new_destination: '+15553334444',
  original_destination: '+15559876543',
  diversion_reason: 'forwarding'
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `original_passport:` | `StirShaken::Passport` | (required) | The original SHAKEN PASSporT |
| `new_destination:` | `String, Array<String>` | (required) | Number(s) where call is diverted to |
| `original_destination:` | `String` | (required) | Number where call was originally going |
| `diversion_reason:` | `String` | `'forwarding'` | Reason for diversion (see `DivPassport::VALID_DIVERSION_REASONS`) |
| `origination_id:` | `String` | `nil` | Uses original passport's origination_id if omitted |

**Returns:** `String` -- encoded DIV PASSporT JWT token.

**Raises:** `InvalidDiversionReasonError`, `InvalidPhoneNumberError`

---

#### `#create_div_passport_from_header(shaken_identity_header:, new_destination:, original_destination:, diversion_reason:, verify_original:)`

Create a DIV PASSporT directly from an existing SHAKEN Identity header string.

```ruby
div_token = auth.create_div_passport_from_header(
  shaken_identity_header: identity_header,
  new_destination: '+15553334444',
  original_destination: '+15559876543',
  diversion_reason: 'no-answer',
  verify_original: false
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `shaken_identity_header:` | `String` | (required) | Original SHAKEN SIP Identity header |
| `new_destination:` | `String, Array<String>` | (required) | Number(s) where call is diverted to |
| `original_destination:` | `String` | (required) | Number where call was originally going |
| `diversion_reason:` | `String` | `'forwarding'` | Reason for diversion |
| `verify_original:` | `Boolean` | `false` | Whether to verify the original PASSporT signature |

**Returns:** `String` -- encoded DIV PASSporT JWT token.

---

#### `#sign_diverted_call(shaken_identity_header:, new_destination:, original_destination:, diversion_reason:, verify_original:, additional_info:)`

Sign a diverted call, returning both the original SHAKEN header and a new DIV Identity header.

```ruby
result = auth.sign_diverted_call(
  shaken_identity_header: original_header,
  new_destination: '+15553334444',
  original_destination: '+15559876543',
  diversion_reason: 'forwarding'
)
# result[:shaken_header]  -- original SHAKEN Identity header (passed through)
# result[:div_header]     -- new DIV Identity header
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `shaken_identity_header:` | `String` | (required) | Original SHAKEN SIP Identity header |
| `new_destination:` | `String, Array<String>` | (required) | Number(s) where call is diverted to |
| `original_destination:` | `String` | (required) | Number where call was originally going |
| `diversion_reason:` | `String` | `'forwarding'` | Reason for diversion |
| `verify_original:` | `Boolean` | `false` | Whether to verify the original PASSporT signature |
| `additional_info:` | `Hash` | `{}` | Additional SIP header parameters for the DIV header |

**Returns:** `Hash` with keys:
| Key | Type | Description |
|-----|------|-------------|
| `:shaken_header` | `String` | The original SHAKEN Identity header (passed through) |
| `:div_header` | `String` | The new DIV SIP Identity header |

---

#### `#create_call_forwarding(original_call_info:, forwarding_info:)`

Create a complete call forwarding scenario with proper attestation reduction and all necessary headers.

```ruby
result = auth.create_call_forwarding(
  original_call_info: {
    originating_number: '+15551234567',
    destination_number: '+15559876543',
    attestation: 'A',
    origination_id: 'some-uuid'       # optional
    # identity_header: existing_header # optional, created if omitted
  },
  forwarding_info: {
    new_destination: '+15553334444',
    reason: 'no-answer',
    attestation: nil                   # optional override; auto-reduced if omitted
  }
)
```

**Parameters:**

`original_call_info:` (`Hash`):
| Key | Type | Description |
|-----|------|-------------|
| `:originating_number` | `String` | Calling number in E.164 format |
| `:destination_number` | `String` | Original destination number |
| `:attestation` | `String` | Original attestation level (default: `'A'`) |
| `:origination_id` | `String` | Optional origination identifier |
| `:identity_header` | `String` | Optional existing SHAKEN header (created if omitted) |

`forwarding_info:` (`Hash`):
| Key | Type | Description |
|-----|------|-------------|
| `:new_destination` | `String, Array<String>` | Where call is being forwarded to |
| `:reason` | `String` | Diversion reason (default: `'forwarding'`) |
| `:attestation` | `String` | Optional attestation override (auto-reduced if omitted) |

**Returns:** `Hash` with keys:
| Key | Type | Description |
|-----|------|-------------|
| `:original_shaken_header` | `String` | SHAKEN Identity header for the original call |
| `:forwarded_shaken_header` | `String` | SHAKEN Identity header for the forwarded leg (reduced attestation) |
| `:div_header` | `String` | DIV SIP Identity header indicating diversion |
| `:metadata` | `Hash` | Metadata including numbers, attestation levels, diversion reason, origination_id |

**Attestation reduction rules** (when `forwarding_info[:attestation]` is not set):
- `'A'` reduces to `'B'`
- `'B'` reduces to `'C'`
- `'C'` remains `'C'`

---

#### `#authorized_for_number?(telephone_number)`

Check whether the service's certificate authorizes signing for a given telephone number.

```ruby
auth.authorized_for_number?('+15551234567')
# => true
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `telephone_number` | `String` | Phone number to check |

**Returns:** `Boolean` -- `true` if authorized (also returns `true` if no certificate is loaded).

---

#### `#load_certificate(force_refresh:)`

Fetch and cache the certificate from the configured URL.

```ruby
cert = auth.load_certificate(force_refresh: true)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `force_refresh:` | `Boolean` | `false` | Bypass the certificate cache |

**Returns:** `OpenSSL::X509::Certificate`

**Raises:** `CertificateFetchError`, `CertificateValidationError`

---

#### `#certificate_valid?`

Check whether the loaded certificate is currently valid.

```ruby
auth.certificate_valid?
# => true
```

**Returns:** `Boolean` -- `false` if no certificate is loaded.

---

#### `#info`

Get a summary of the authentication service configuration.

```ruby
auth.info
# => { certificate_url: "...", algorithm: "ES256", extension: "shaken",
#      has_certificate: true, certificate_valid: true }
```

**Returns:** `Hash` with keys: `:certificate_url`, `:algorithm`, `:extension`, `:has_certificate`, `:certificate_valid`.

---

## StirShaken::VerificationService

Service for verifying STIR/SHAKEN calls. Thread-safe: tracks verification statistics using a mutex.

### `#initialize`

Create a new verification service instance with zeroed statistics.

```ruby
verifier = StirShaken::VerificationService.new
```

---

### `#verify_call(identity_header, originating_number:, destination_number:, max_age:)`

Verify a call using a SIP Identity header. Fetches the certificate, validates it, verifies the PASSporT signature, checks token age, and optionally validates originating/destination numbers.

```ruby
result = verifier.verify_call(
  identity_header,
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  max_age: 60
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `identity_header` | `String` | (required) | SIP Identity header value |
| `originating_number:` | `String` | `nil` | Expected originating number (skipped if nil) |
| `destination_number:` | `String` | `nil` | Expected destination number (skipped if nil) |
| `max_age:` | `Integer` | `StirShaken.configuration.default_max_age` | Maximum token age in seconds |

**Returns:** `StirShaken::VerificationResult`

Verification steps performed:
1. Parse the SIP Identity header
2. Fetch and validate the certificate from the `info` URL
3. Extract the public key from the certificate
4. Parse and verify the PASSporT signature
5. Check token expiration
6. Validate originating number match (if provided)
7. Validate destination number match (if provided)
8. Check certificate authorization for the originating number

---

### `#verify_passport(passport_token, certificate_url, max_age:)`

Verify a PASSporT JWT token directly (without a SIP Identity header wrapper).

```ruby
result = verifier.verify_passport(token, 'https://example.com/cert.pem', max_age: 60)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `passport_token` | `String` | (required) | PASSporT JWT token |
| `certificate_url` | `String` | (required) | URL to the signing certificate |
| `max_age:` | `Integer` | `StirShaken.configuration.default_max_age` | Maximum token age in seconds |

**Returns:** `StirShaken::VerificationResult`

---

### `#verify_multiple(identity_headers, originating_number:, destination_number:, max_age:)`

Verify multiple SIP Identity headers (RFC 8224 section 4.1). Calls `verify_call` for each header.

```ruby
results = verifier.verify_multiple(
  [header1, header2],
  originating_number: '+15551234567'
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `identity_headers` | `Array<String>` | (required) | Array of SIP Identity header values |
| `originating_number:` | `String` | `nil` | Expected originating number |
| `destination_number:` | `String` | `nil` | Expected destination number |
| `max_age:` | `Integer` | `StirShaken.configuration.default_max_age` | Maximum token age in seconds |

**Returns:** `Array<StirShaken::VerificationResult>`

---

### `#validate_structure(identity_header)`

Validate the structure of a SIP Identity header without full cryptographic verification. Useful for testing and debugging.

```ruby
info = verifier.validate_structure(identity_header)
# => { valid_structure: true, sip_identity: {...}, passport: {...},
#      attestation: "A", originating_number: "+15551234567", ... }
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `identity_header` | `String` | SIP Identity header value |

**Returns:** `Hash` -- On success, contains `:valid_structure` (`true`), `:sip_identity`, `:passport`, `:attestation`, `:originating_number`, `:destination_numbers`, `:certificate_url`, `:algorithm`, `:extension`, `:issued_at`, `:origination_id`, `:attestation_description`, `:confidence_level`. On failure, contains `:valid_structure` (`false`), `:error`, `:error_class`.

---

### `#stats`

Get verification statistics. Thread-safe.

```ruby
verifier.stats
# => { total_verifications: 10, successful_verifications: 8, failed_verifications: 2,
#      success_rate: 80.0, certificate_cache_stats: {...}, configuration: {...} }
```

**Returns:** `Hash` with keys:
| Key | Type | Description |
|-----|------|-------------|
| `:total_verifications` | `Integer` | Total verification attempts |
| `:successful_verifications` | `Integer` | Successful verifications |
| `:failed_verifications` | `Integer` | Failed verifications |
| `:success_rate` | `Float` | Success percentage (0.0-100.0) |
| `:certificate_cache_stats` | `Hash` | Certificate cache statistics |
| `:configuration` | `Hash` | Current cache TTL and HTTP timeout |

---

## StirShaken::VerificationResult

Immutable result object returned by verification methods.

### Constructor

```ruby
result = StirShaken::VerificationResult.new(
  valid: true,
  passport: passport,
  certificate: cert,
  attestation: 'A',
  reason: nil,
  confidence_level: 100
)
```

### Methods

#### `#valid?`

**Returns:** `Boolean` -- `true` if verification passed.

#### `#invalid?`

**Returns:** `Boolean` -- `true` if verification failed.

#### `#valid`

**Returns:** `Boolean` -- raw validity value (same as `valid?`).

#### `#passport`

**Returns:** `StirShaken::Passport, nil` -- the parsed PASSporT (nil if parsing failed).

#### `#certificate`

**Returns:** `OpenSSL::X509::Certificate, nil` -- the certificate used for verification.

#### `#attestation`

**Returns:** `String, nil` -- the attestation level from the PASSporT (`'A'`, `'B'`, or `'C'`).

#### `#reason`

**Returns:** `String, nil` -- human-readable reason for failure (nil on success).

#### `#confidence_level`

**Returns:** `Integer` -- confidence score (0-100). Derived from attestation level: A=100, B=75, C=50. Set to 0 on failure.

---

## StirShaken::Passport

PASSporT (Personal Assertion Token) implementation per RFC 8225.

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ALGORITHM` | `'ES256'` | Required signing algorithm |
| `TOKEN_TYPE` | `'passport'` | JWT `typ` header value |
| `EXTENSION` | `'shaken'` | JWT `ppt` header value |

### Class Methods

#### `.create(originating_number:, destination_numbers:, attestation:, origination_id:, certificate_url:, private_key:, destination_uris:)`

Create and sign a new PASSporT JWT token. Payload keys are sorted lexicographically per RFC 8588.

```ruby
token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A',
  origination_id: 'optional-uuid',
  certificate_url: 'https://example.com/cert.pem',
  private_key: private_key,
  destination_uris: nil
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `originating_number:` | `String` | (required) | Calling number in E.164 format |
| `destination_numbers:` | `Array<String>` | (required) | Called number(s) in E.164 format |
| `attestation:` | `String` | (required) | Attestation level (`'A'`, `'B'`, or `'C'`) |
| `origination_id:` | `String` | `nil` | UUID (auto-generated via `SecureRandom.uuid` if omitted) |
| `certificate_url:` | `String` | (required) | URL to the signing certificate |
| `private_key:` | `OpenSSL::PKey::EC` | (required) | P-256 private key for signing |
| `destination_uris:` | `Array<String>` | `nil` | Optional destination URIs for the `dest` claim |

**Returns:** `String` -- encoded JWT token.

**Raises:** `InvalidAttestationError`, `InvalidPhoneNumberError`

---

#### `.parse(token, public_key:, verify_signature:)`

Parse and optionally verify a PASSporT JWT token.

```ruby
passport = StirShaken::Passport.parse(token, public_key: pub_key, verify_signature: true)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `token` | `String` | (required) | JWT token to parse |
| `public_key:` | `OpenSSL::PKey::EC` | `nil` | Public key for signature verification |
| `verify_signature:` | `Boolean` | `true` | Whether to verify the signature (requires `public_key` when `true`) |

**Returns:** `StirShaken::Passport` -- parsed and validated PASSporT.

**Raises:** `InvalidTokenError` (decode failure), `PassportValidationError` (structural validation failure)

---

#### `.validate_phone_number!(number)`

Validate a phone number against strict E.164 format: must start with `+`, followed by 1-15 digits, first digit cannot be `0`.

```ruby
StirShaken::Passport.validate_phone_number!('+15551234567')
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `number` | `String` | Phone number to validate |

**Returns:** `nil` (no return value on success)

**Raises:** `InvalidPhoneNumberError` if the number does not match `/^\+[1-9]\d{1,14}$/`

---

### Instance Methods

#### `#validate!`

Validate the PASSporT header and payload structure. Checks for required fields (`alg`, `typ`, `ppt`, `x5u`, `attest`, `dest`, `iat`, `orig`, `origid`), valid attestation, and valid phone numbers.

**Raises:** `PassportValidationError`

---

#### `#originating_number`

**Returns:** `String` -- the originating telephone number from `orig.tn`.

#### `#destination_numbers`

**Returns:** `Array<String>` -- the destination telephone numbers from `dest.tn` (empty array if absent).

#### `#destination_uris`

**Returns:** `Array<String>` -- the destination URIs from `dest.uri` (empty array if absent).

#### `#attestation`

**Returns:** `String` -- the attestation level from the `attest` claim.

#### `#origination_id`

**Returns:** `String` -- the origination identifier from the `origid` claim.

#### `#issued_at`

**Returns:** `Integer` -- Unix timestamp from the `iat` claim.

#### `#certificate_url`

**Returns:** `String` -- certificate URL from the `x5u` header.

---

#### `#expired?(max_age:)`

Check whether the token is expired. Considers both age and future-dated tokens (allows 60 seconds of clock skew).

```ruby
passport.expired?(max_age: 60)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_age:` | `Integer` | `60` | Maximum age in seconds |

**Returns:** `Boolean` -- `true` if the token's `iat` is older than `max_age` seconds or more than 60 seconds in the future.

---

#### `#to_h`

**Returns:** `Hash` with keys: `:header`, `:payload`, `:originating_number`, `:destination_numbers`, `:destination_uris`, `:attestation`, `:origination_id`, `:issued_at`, `:certificate_url`.

---

## StirShaken::DivPassport

DIV PASSporT (Diversion Personal Assertion Token) per RFC 8946. Inherits from `Passport`.

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `EXTENSION` | `'div'` | JWT `ppt` header value (overrides parent's `'shaken'`) |
| `ALGORITHM` | `'ES256'` | Inherited from `Passport` |
| `TOKEN_TYPE` | `'passport'` | Inherited from `Passport` |
| `VALID_DIVERSION_REASONS` | (see below) | Frozen array of 10 valid diversion reason strings |

**Valid diversion reasons:** `forwarding`, `deflection`, `follow-me`, `time-of-day`, `user-busy`, `no-answer`, `unavailable`, `unconditional`, `away`, `unknown`

### Class Methods

#### `.create_div(original_passport:, new_destination:, original_destination:, diversion_reason:, origination_id:, certificate_url:, private_key:)`

Create a DIV PASSporT token from an existing parsed PASSporT.

```ruby
div_token = StirShaken::DivPassport.create_div(
  original_passport: passport,
  new_destination: '+15553334444',
  original_destination: '+15559876543',
  diversion_reason: 'forwarding',
  origination_id: nil,
  certificate_url: 'https://example.com/cert.pem',
  private_key: private_key
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `original_passport:` | `StirShaken::Passport` | (required) | The original SHAKEN PASSporT |
| `new_destination:` | `String, Array<String>` | (required) | Diversion target number(s) |
| `original_destination:` | `String` | (required) | Original destination number |
| `diversion_reason:` | `String` | `'forwarding'` | Reason for diversion |
| `origination_id:` | `String` | `nil` | Uses original passport's origination_id if omitted |
| `certificate_url:` | `String` | (required) | URL to signing certificate |
| `private_key:` | `OpenSSL::PKey::EC` | (required) | P-256 private key for signing |

**Returns:** `String` -- encoded DIV PASSporT JWT token.

**Raises:** `InvalidDiversionReasonError`, `InvalidPhoneNumberError`

---

#### `.create_from_identity_header(shaken_identity_header:, new_destination:, original_destination:, diversion_reason:, certificate_url:, private_key:, public_key:)`

Create a DIV PASSporT from an existing SHAKEN SIP Identity header string. Parses the header, extracts the PASSporT, and creates the DIV token.

```ruby
div_token = StirShaken::DivPassport.create_from_identity_header(
  shaken_identity_header: header_string,
  new_destination: '+15553334444',
  original_destination: '+15559876543',
  diversion_reason: 'user-busy',
  certificate_url: 'https://example.com/cert.pem',
  private_key: private_key,
  public_key: nil  # set to verify original signature
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `shaken_identity_header:` | `String` | (required) | Original SHAKEN SIP Identity header |
| `new_destination:` | `String, Array<String>` | (required) | Diversion target number(s) |
| `original_destination:` | `String` | (required) | Original destination number |
| `diversion_reason:` | `String` | `'forwarding'` | Reason for diversion |
| `certificate_url:` | `String` | (required) | URL to signing certificate |
| `private_key:` | `OpenSSL::PKey::EC` | (required) | P-256 private key for signing |
| `public_key:` | `OpenSSL::PKey::EC` | `nil` | Public key to verify original PASSporT (signature verified only if provided) |

**Returns:** `String` -- encoded DIV PASSporT JWT token.

---

#### `.parse(token, public_key:, verify_signature:)`

Parse and optionally verify a DIV PASSporT JWT token. Validates both standard PASSporT claims and DIV-specific claims (`div.tn`, `div.reason`).

```ruby
div_passport = StirShaken::DivPassport.parse(token, public_key: pub_key, verify_signature: true)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `token` | `String` | (required) | JWT token to parse |
| `public_key:` | `OpenSSL::PKey::EC` | `nil` | Public key for verification |
| `verify_signature:` | `Boolean` | `true` | Whether to verify the signature |

**Returns:** `StirShaken::DivPassport`

**Raises:** `InvalidTokenError`, `PassportValidationError`, `InvalidDiversionReasonError`

---

#### `.verify_chain(div_token:, shaken_token:, div_public_key:, shaken_public_key:)`

Verify that a DIV PASSporT correctly chains back to an original SHAKEN PASSporT. Checks originating number match, origination ID match, and that the DIV original destination appears in the SHAKEN destinations.

```ruby
result = StirShaken::DivPassport.verify_chain(
  div_token: div_jwt,
  shaken_token: shaken_jwt,
  div_public_key: div_pub_key,
  shaken_public_key: shaken_pub_key  # optional
)
# result[:valid]           => true/false
# result[:div_passport]    => DivPassport (on success)
# result[:shaken_passport] => Passport (on success)
# result[:reason]          => String (on failure)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `div_token:` | `String` | (required) | DIV PASSporT JWT token |
| `shaken_token:` | `String` | (required) | Original SHAKEN PASSporT JWT token |
| `div_public_key:` | `OpenSSL::PKey::EC` | (required) | Public key for DIV token verification |
| `shaken_public_key:` | `OpenSSL::PKey::EC` | `nil` | Public key for SHAKEN token verification (unverified if nil) |

**Returns:** `Hash` -- On success: `{ valid: true, div_passport: DivPassport, shaken_passport: Passport }`. On failure: `{ valid: false, reason: String }`.

---

#### `.validate_diversion_reason!(reason)`

Validate a diversion reason string against `VALID_DIVERSION_REASONS`.

```ruby
StirShaken::DivPassport.validate_diversion_reason!('forwarding')
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `reason` | `String` | Diversion reason to validate |

**Raises:** `InvalidDiversionReasonError` if the reason is not in the valid list.

---

### Instance Methods

#### `#original_destination`

**Returns:** `String` -- the original destination number from `div.tn`.

#### `#diversion_reason`

**Returns:** `String` -- the reason for diversion from `div.reason`.

#### `#div_passport?`

**Returns:** `Boolean` -- `true` if the `ppt` header equals `'div'`.

#### `#to_h`

**Returns:** `Hash` -- parent `Passport#to_h` merged with `:original_destination`, `:diversion_reason`, and `:div_passport` (`true`).

---

## StirShaken::SipIdentity

SIP Identity header implementation per RFC 8224.

### Attributes (readers)

| Attribute | Type | Description |
|-----------|------|-------------|
| `passport_token` | `String` | The PASSporT JWT token |
| `info_url` | `String` | URL to certificate information |
| `algorithm` | `String` | Signing algorithm (e.g., `'ES256'`) |
| `extension` | `String` | PASSporT extension (e.g., `'shaken'` or `'div'`) |
| `canon` | `String, nil` | Optional canonicalization parameter |

### Class Methods

#### `.create(passport_token:, certificate_url:, algorithm:, extension:, additional_info:, canon:)`

Create a SIP Identity header value string.

```ruby
header = StirShaken::SipIdentity.create(
  passport_token: jwt_token,
  certificate_url: 'https://example.com/cert.pem',
  algorithm: 'ES256',
  extension: 'shaken',
  additional_info: {},
  canon: nil
)
# => "eyJ...;info=<https://example.com/cert.pem>;alg=ES256;ppt=shaken"
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `passport_token:` | `String` | (required) | PASSporT JWT token |
| `certificate_url:` | `String` | (required) | Certificate URL |
| `algorithm:` | `String` | `'ES256'` | Signing algorithm |
| `extension:` | `String` | `'shaken'` | PASSporT extension |
| `additional_info:` | `Hash` | `{}` | Additional parameters (sanitized for header injection) |
| `canon:` | `String` | `nil` | Optional canonicalization parameter |

**Returns:** `String` -- formatted SIP Identity header value.

**Raises:** `InvalidIdentityHeaderError` if additional_info keys or values contain illegal characters (`;`, `\r`, `\n`, `\0`).

---

#### `.parse(header_value)`

Parse a SIP Identity header value string into a `SipIdentity` object.

```ruby
sip_identity = StirShaken::SipIdentity.parse(header_string)
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `header_value` | `String` | SIP Identity header value |

**Returns:** `StirShaken::SipIdentity`

**Raises:** `InvalidIdentityHeaderError` if required parameters (`info`, `alg`, `ppt`) are missing or the header format is invalid.

---

#### `.parse_multiple(header_values)`

Parse one or more SIP Identity header values (RFC 8224 section 4.1).

```ruby
identities = StirShaken::SipIdentity.parse_multiple([header1, header2])
# Also accepts a single string:
identities = StirShaken::SipIdentity.parse_multiple(header_string)
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `header_values` | `String, Array<String>` | One or more Identity header values |

**Returns:** `Array<StirShaken::SipIdentity>`

---

### Instance Methods

#### `#to_header`

Reconstruct the SIP Identity header value string from this object's attributes.

**Returns:** `String`

---

#### `#parse_passport(public_key:, verify_signature:)`

Parse the embedded PASSporT token, delegating to `Passport.parse`.

```ruby
passport = sip_identity.parse_passport(public_key: pub_key, verify_signature: true)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `public_key:` | `OpenSSL::PKey::EC` | `nil` | Public key for verification |
| `verify_signature:` | `Boolean` | `true` | Whether to verify the signature |

**Returns:** `StirShaken::Passport`

---

#### `#validate!`

Validate the SIP Identity header structure. Checks that the algorithm is `'ES256'`, the extension is `'shaken'` or `'div'`, the `info` URL is a valid HTTPS URL, and the PASSporT token has the expected three-part JWT format.

**Raises:** `InvalidIdentityHeaderError`

---

#### `#info`

**Returns:** `Hash` with keys: `:algorithm`, `:extension`, `:info_url`, `:token_present`, `:token_length`.

---

#### `#to_h`

**Returns:** `Hash` with keys: `:passport_token`, `:info_url`, `:algorithm`, `:extension`. Includes `:canon` if present.

---

## StirShaken::CertificateManager

Fetches, caches, and validates X.509 certificates. All methods are class-level. Thread-safe via mutex. Includes rate limiting (max 10 fetches per URL per minute; skipped in test environments) and SSRF protection.

### Class Methods

#### `.fetch_certificate(url, force_refresh:, expected_pins:)`

Fetch a certificate from a URL with caching, rate limiting, and optional pin validation. Enforces HTTPS. Rejects private/loopback/link-local addresses (SSRF protection).

```ruby
cert = StirShaken::CertificateManager.fetch_certificate(
  'https://example.com/cert.pem',
  force_refresh: false,
  expected_pins: ['abc123...']  # optional SHA256 hex pins
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `String` | (required) | Certificate URL (must be HTTPS) |
| `force_refresh:` | `Boolean` | `false` | Bypass the certificate cache |
| `expected_pins:` | `Array<String>` | `nil` | SHA256 hex digest pins for public key pinning |

**Returns:** `OpenSSL::X509::Certificate`

**Raises:** `CertificateFetchError` (network/rate limit/SSRF), `CertificateValidationError` (invalid format/pin mismatch)

---

#### `.fetch_certificate_chain(url)`

Fetch a certificate chain from a URL. The response may contain multiple PEM-encoded certificates.

```ruby
chain = StirShaken::CertificateManager.fetch_certificate_chain('https://example.com/chain.pem')
# => [leaf_cert, intermediate_cert, ...]
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | `String` | Certificate URL (must be HTTPS) |

**Returns:** `Array<OpenSSL::X509::Certificate>` -- certificates in order (leaf first).

**Raises:** `CertificateFetchError`, `CertificateValidationError`

---

#### `.parse_certificate_chain(pem_data)`

Parse PEM data that may contain multiple certificates.

```ruby
certs = StirShaken::CertificateManager.parse_certificate_chain(pem_string)
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `pem_data` | `String` | PEM-encoded certificate data |

**Returns:** `Array<OpenSSL::X509::Certificate>`

**Raises:** `CertificateValidationError` if the data cannot be parsed.

---

#### `.validate_certificate(certificate, telephone_number:)`

Validate a certificate for STIR/SHAKEN usage. Checks expiration, key usage (`digitalSignature`), optional Extended Key Usage (STIR/SHAKEN OID `1.3.6.1.5.5.7.3.20`), telephone number authorization (via TNAuthList or SAN `tel:` URIs), and certificate chain verification.

```ruby
StirShaken::CertificateManager.validate_certificate(cert, telephone_number: '+15551234567')
# => true
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `certificate` | `OpenSSL::X509::Certificate` | (required) | Certificate to validate |
| `telephone_number:` | `String` | `nil` | Phone number to validate authorization for |

**Returns:** `Boolean`

---

#### `.extract_public_key(certificate)`

Extract the EC public key from a certificate. Validates it is an EC key on the P-256 curve.

```ruby
pub_key = StirShaken::CertificateManager.extract_public_key(cert)
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `certificate` | `OpenSSL::X509::Certificate` | The certificate |

**Returns:** `OpenSSL::PKey::EC` -- the P-256 public key.

**Raises:** `CertificateValidationError` if the key is not EC or not P-256.

---

#### `.clear_cache!`

Clear the certificate cache and reset cache statistics.

```ruby
StirShaken::CertificateManager.clear_cache!
```

---

#### `.cache_stats`

Get certificate cache statistics.

```ruby
StirShaken::CertificateManager.cache_stats
# => { size: 2, entries: ["https://example.com/***", ...],
#      hits: 15, misses: 3, total_requests: 18, hit_rate_percent: 83.33 }
```

**Returns:** `Hash` with keys:
| Key | Type | Description |
|-----|------|-------------|
| `:size` | `Integer` | Number of cached certificates |
| `:entries` | `Array<String>` | Masked URLs of cached certificates |
| `:hits` | `Integer` | Cache hit count |
| `:misses` | `Integer` | Cache miss count |
| `:total_requests` | `Integer` | Total requests (hits + misses) |
| `:hit_rate_percent` | `Float` | Hit rate as percentage |

---

## StirShaken::Attestation

Module defining attestation level constants and utilities per RFC 8588.

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `FULL` | `'A'` | Full Attestation |
| `PARTIAL` | `'B'` | Partial Attestation |
| `GATEWAY` | `'C'` | Gateway Attestation |
| `VALID_LEVELS` | `['A', 'B', 'C']` | Frozen array of valid levels |

### Class Methods

#### `.valid?(level)`

Check if an attestation level is valid.

```ruby
StirShaken::Attestation.valid?('A') # => true
StirShaken::Attestation.valid?('D') # => false
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `level` | `String` | Attestation level to check |

**Returns:** `Boolean`

---

#### `.validate!(level)`

Validate an attestation level, raising an error if invalid.

```ruby
StirShaken::Attestation.validate!('A') # => 'A'
StirShaken::Attestation.validate!('X') # raises InvalidAttestationError
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `level` | `String` | Attestation level to validate |

**Returns:** `String` -- the validated level.

**Raises:** `InvalidAttestationError`

---

#### `.description(level)`

Get a human-readable description of an attestation level.

```ruby
StirShaken::Attestation.description('A')
# => "Full Attestation - Service provider has authenticated the calling party and verified authorization"
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `level` | `String` | Attestation level |

**Returns:** `String` -- descriptions:
- `'A'`: "Full Attestation - Service provider has authenticated the calling party and verified authorization"
- `'B'`: "Partial Attestation - Service provider has authenticated call origination but cannot verify caller authorization"
- `'C'`: "Gateway Attestation - Service provider has authenticated the gateway but cannot authenticate the call source"
- Other: "Unknown attestation level"

---

#### `.confidence_level(level)`

Get the numeric confidence level for an attestation.

```ruby
StirShaken::Attestation.confidence_level('A') # => 100
StirShaken::Attestation.confidence_level('B') # => 75
StirShaken::Attestation.confidence_level('C') # => 50
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `level` | `String` | Attestation level |

**Returns:** `Integer` -- `A`=100, `B`=75, `C`=50, other=0.

---

## StirShaken::SecurityLogger

Centralized security event logging module for audit trails and monitoring. All methods are class-level.

Logging can be disabled by setting the `STIRSHAKEN_SECURITY_LOGGING` environment variable to `'false'`.

Log output goes to `Rails.logger` if available (severity-mapped), otherwise to `$stderr`. Log entries are JSON formatted with a `[STIRSHAKEN-SECURITY]` prefix.

### Class Methods

#### `.log_security_event(event_type, details, severity:)`

Log a security event.

```ruby
StirShaken::SecurityLogger.log_security_event(:authentication_success, {
  originating_number: '+15551234567',
  attestation: 'A'
}, severity: :low)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `event_type` | `Symbol` | (required) | Event type (see `EVENTS` constant) |
| `details` | `Hash` | `{}` | Additional event details (sensitive data auto-sanitized) |
| `severity:` | `Symbol` | auto-determined | Severity: `:low`, `:medium`, `:high`, `:critical` |

Known event types: `:authentication_success`, `:authentication_failure`, `:verification_success`, `:verification_failure`, `:certificate_fetch`, `:certificate_validation_failure`, `:rate_limit_exceeded`, `:invalid_input`, `:configuration_error`, `:network_error`.

---

#### `.log_authentication_success(originating_number, destination_numbers, attestation)`

Log a successful authentication event.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `originating_number` | `String` | Calling number (auto-masked in log) |
| `destination_numbers` | `Array<String>` | Called numbers (only count is logged) |
| `attestation` | `String` | Attestation level |

---

#### `.log_verification_success(identity_header, result)`

Log a successful verification event.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `identity_header` | `String` | SIP Identity header (only length is logged) |
| `result` | `Hash` | Result details with `:attestation` and `:certificate_url` keys |

---

#### `.log_security_failure(event_type, error, context)`

Log a security failure event. Severity is automatically determined from the error class.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `event_type` | `Symbol` | Type of failure |
| `error` | `Exception` | The error that occurred |
| `context` | `Hash` | Additional context |

Severity mapping:
- `ConfigurationError` -> `:critical`
- `CertificateFetchError`, `SignatureVerificationError` -> `:high`
- `InvalidPhoneNumberError`, `InvalidAttestationError` -> `:medium`
- All others -> `:medium`

---

#### `.log_certificate_fetch(url, success, cache_hit:)`

Log a certificate fetch event.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `String` | (required) | Certificate URL (auto-masked in log) |
| `success` | `Boolean` | (required) | Whether fetch was successful |
| `cache_hit:` | `Boolean` | `false` | Whether result came from cache |

---

#### `.log_rate_limit_exceeded(url, current_count)`

Log a rate limiting event.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | `String` | Rate-limited URL (auto-masked) |
| `current_count` | `Integer` | Current request count |

---

#### `.enabled?`

Check if security logging is enabled.

**Returns:** `Boolean` -- `true` unless `ENV['STIRSHAKEN_SECURITY_LOGGING'] == 'false'`.

---

#### `.mask_url(url)`

Mask a URL for safe logging. Keeps the scheme and host, replaces the path with `/***`.

```ruby
StirShaken::SecurityLogger.mask_url('https://example.com/certs/leaf.pem')
# => "https://example.com/***"
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | `String` | URL to mask |

**Returns:** `String` -- masked URL. Returns `'***'` on parse error.

---

#### `.mask_phone_number(phone_number)`

Mask a phone number for safe logging. Keeps the `+` prefix, first digit, and last 4 digits.

```ruby
StirShaken::SecurityLogger.mask_phone_number('+15551234567')
# => "+1*****4567"
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `phone_number` | `String` | Phone number to mask |

**Returns:** `String` -- masked number. Returns the input unchanged if shorter than 7 characters or not a String.

---

## StirShaken::SignatureUtils

Utilities for ECDSA signature format conversion between JWT's R||S format and OpenSSL's DER format. All methods are class-level (module functions).

### Class Methods

#### `.jwt_to_der_signature(jwt_signature)`

Convert an ECDSA signature from JWT's raw R||S format (64 bytes) to DER-encoded ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`.

```ruby
der_sig = StirShaken::SignatureUtils.jwt_to_der_signature(raw_64_byte_signature)
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `jwt_signature` | `String` | 64-byte R\|\|S signature (binary) |

**Returns:** `String` -- DER-encoded signature (binary).

**Raises:** `ArgumentError` if the input is not exactly 64 bytes.

---

#### `.der_to_jwt_signature(der_signature)`

Convert a DER-encoded ECDSA signature back to JWT's raw R||S format (64 bytes).

```ruby
raw_sig = StirShaken::SignatureUtils.der_to_jwt_signature(der_encoded_signature)
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `der_signature` | `String` | DER-encoded signature (binary) |

**Returns:** `String` -- 64-byte R||S signature (binary).

**Raises:** `ArgumentError` if the DER data is not a valid SEQUENCE of exactly 2 INTEGERs.

---

#### `.verify_jwt_signature(public_key, jwt_signature, message, digest:)`

Verify an ECDSA signature in JWT R||S format against a message using OpenSSL.

```ruby
valid = StirShaken::SignatureUtils.verify_jwt_signature(
  public_key,
  raw_64_byte_signature,
  'message to verify',
  digest: 'SHA256'
)
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `public_key` | `OpenSSL::PKey::EC` | (required) | EC public key |
| `jwt_signature` | `String` | (required) | 64-byte R\|\|S signature |
| `message` | `String` | (required) | Message that was signed |
| `digest:` | `String` | `'SHA256'` | Digest algorithm |

**Returns:** `Boolean` -- `true` if the signature is valid, `false` otherwise (never raises on verification failure).

---

#### `.create_jwt_signature(private_key, message, digest:)`

Create an ECDSA signature in JWT R||S format by signing with OpenSSL and converting from DER.

```ruby
sig = StirShaken::SignatureUtils.create_jwt_signature(private_key, 'message to sign')
# => 64-byte binary string
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `private_key` | `OpenSSL::PKey::EC` | (required) | EC private key |
| `message` | `String` | (required) | Message to sign |
| `digest:` | `String` | `'SHA256'` | Digest algorithm |

**Returns:** `String` -- 64-byte R||S signature (binary).

---

## Error Classes

All errors inherit from `StirShaken::Error`, which inherits from `StandardError`.

| Error Class | Parent | Description |
|-------------|--------|-------------|
| `StirShaken::Error` | `StandardError` | Base error for all STIR/SHAKEN errors |
| `StirShaken::PassportValidationError` | `Error` | PASSporT structure or claim validation failure |
| `StirShaken::CertificateError` | `Error` | Base class for certificate-related errors |
| `StirShaken::CertificateFetchError` | `CertificateError` | Certificate download failure (network, rate limit, SSRF) |
| `StirShaken::CertificateValidationError` | `CertificateError` | Certificate validation failure (format, expiry, pin mismatch) |
| `StirShaken::CertificateRevocationError` | `CertificateError` | Certificate has been revoked |
| `StirShaken::SignatureVerificationError` | `Error` | Cryptographic signature verification failure |
| `StirShaken::InvalidAttestationError` | `Error` | Invalid attestation level |
| `StirShaken::InvalidPhoneNumberError` | `Error` | Phone number does not match E.164 format |
| `StirShaken::InvalidIdentityHeaderError` | `Error` | Malformed SIP Identity header |
| `StirShaken::InvalidTokenError` | `Error` | Malformed or invalid JWT token |
| `StirShaken::ConfigurationError` | `Error` | Missing or invalid configuration |
| `StirShaken::InvalidDiversionReasonError` | `Error` | Invalid diversion reason for DIV PASSporT |
