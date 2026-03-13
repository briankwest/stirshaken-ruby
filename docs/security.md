# Security Guide

## Security Architecture Overview

The stirshaken-ruby gem implements multiple layers of defense to protect STIR/SHAKEN operations against common attack vectors. Security controls are applied at every stage: certificate fetching, token creation, token verification, SIP header handling, logging, and configuration. The library follows a fail-secure design -- when validation is ambiguous or encounters errors, the operation is rejected.

## HTTPS Enforcement (RFC 8226 section 9)

All certificate URLs must use HTTPS. This is enforced in two places:

1. **CertificateManager** (`download_certificate`, `fetch_certificate_chain`): The parsed URI is checked with `uri.is_a?(URI::HTTPS)`. Non-HTTPS URLs raise `CertificateFetchError`.

2. **SipIdentity** (`validate!`): The `info` parameter URL is validated to ensure it uses the `https` scheme. Non-HTTPS URLs raise `InvalidIdentityHeaderError`.

This prevents man-in-the-middle attacks on certificate fetching, which could allow an attacker to substitute a certificate and forge PASSporT signatures.

## SSRF Protection

Before fetching a certificate, `CertificateManager.validate_url_safety!` resolves the hostname via `Addrinfo.getaddrinfo` and checks every resolved IP address against private and reserved ranges. Requests to the following ranges are rejected with a `CertificateFetchError`:

| Range | Type |
|---|---|
| `10.0.0.0/8` | RFC 1918 private |
| `172.16.0.0/12` | RFC 1918 private |
| `192.168.0.0/16` | RFC 1918 private |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local |
| `::1/128` | IPv6 loopback |
| `fc00::/7` | IPv6 unique local address |
| `fe80::/10` | IPv6 link-local |

The hostnames `localhost` and `[::1]` are explicitly rejected before DNS resolution.

**Known limitation:** There is a TOCTOU (time-of-check-time-of-use) window with DNS rebinding. The library resolves DNS for the SSRF check, but HTTParty re-resolves at fetch time. An attacker with control over DNS could potentially return a safe IP for the first resolution and a private IP for the second. This is documented in the source and acknowledged as blocking the vast majority of SSRF attempts.

## Header Injection Protection

`SipIdentity.sanitize_header_param!` validates all additional parameter keys and values passed to `SipIdentity.create`. The following characters are rejected, raising an `InvalidIdentityHeaderError`:

- Semicolons (`;`) -- prevents parameter injection
- Carriage returns (`\r`) -- prevents HTTP header injection
- Newlines (`\n`) -- prevents HTTP header injection
- Null bytes (`\0`) -- prevents null byte injection

The check uses the regex pattern `/[;\r\n\0]/` against both keys and values.

## JWT Algorithm Confusion Prevention

The `Passport` class enforces ES256 as the only accepted algorithm at multiple points:

1. **Token creation** (`Passport.create`): The header is hardcoded with `'alg' => 'ES256'`. No algorithm parameter is accepted from callers.

2. **Token parsing** (`Passport.parse`): When signature verification is enabled, `JWT.decode` is called with `{ algorithm: 'ES256' }`, which causes the `jwt` gem to reject tokens using any other algorithm.

3. **Header validation** (`validate_header!`): After decoding, the `alg` field is checked against the constant `ALGORITHM = 'ES256'`. Tokens with `alg: "none"`, `alg: "HS256"`, or any other value raise a `PassportValidationError`.

4. **SipIdentity validation** (`validate!`): The `alg` parameter in the SIP Identity header is verified to be `'ES256'`. Other values raise `InvalidIdentityHeaderError`.

This multi-layered approach prevents algorithm confusion attacks where an attacker might try to use `"none"` to bypass signature verification, or `"HS256"` to exploit the public key as an HMAC secret.

## Certificate Pin Validation

Certificate pinning provides an additional layer of trust beyond certificate chain validation. When `expected_pins` are provided to `fetch_certificate`, the SHA-256 digest of the certificate's public key (in DER encoding) is compared against each expected pin.

The comparison uses `OpenSSL.fixed_length_secure_compare` rather than Ruby's `==` operator:

```ruby
expected_pins.any? { |pin|
  pin.length == actual_pin.length &&
  OpenSSL.fixed_length_secure_compare(actual_pin, pin)
}
```

This constant-time comparison prevents timing side-channel attacks where an attacker could measure response times to incrementally guess valid pin values. The length check before `fixed_length_secure_compare` is required because that method raises an error if the strings differ in length.

## Future-Dated Token Rejection

The `Passport#expired?` method rejects tokens whose `iat` (issued-at) timestamp is more than 60 seconds in the future:

```ruby
return true if issued_at > now + 60
```

This 60-second clock skew tolerance allows for minor time differences between signing and verifying parties, while preventing attackers from creating tokens with far-future timestamps that would remain valid indefinitely.

## Fail-Secure Certificate Chain Verification

The `verify_with_trust_store` method wraps `OpenSSL::X509::Store#verify` in a rescue block:

```ruby
store.verify(certificate)
rescue OpenSSL::X509::StoreError
  false
```

If the trust store encounters any error during verification (malformed certificates, missing chain links, revocation failures), the result is `false` rather than an exception that could be mishandled as a successful verification. This is a fail-secure design: ambiguity is treated as failure.

## Rate Limiting

`CertificateManager.rate_limit_check!` enforces a maximum of 10 certificate fetch requests per minute per URL. The implementation:

- Tracks requests by `[url, current_minute_integer]` tuples
- Increments a counter on each request
- Automatically cleans up entries older than 2 minutes
- Raises `CertificateFetchError` when the limit is exceeded
- Is disabled in test environments (`RAILS_ENV=test`, `RACK_ENV=test`, or when `RSpec` is defined)

This prevents abuse scenarios where a malicious or buggy caller could flood upstream certificate authorities with requests.

## Thread Safety

The library uses `Mutex` instances to protect all shared mutable state:

**CertificateManager** uses four separate mutexes:
- `@cache_mutex` -- protects `@certificate_cache`
- `@rate_limit_mutex` -- protects `@rate_limiter`
- `@stats_mutex` -- protects `@cache_stats` (hits, misses, fetches)
- `@crl_cache_mutex` -- protects `@crl_cache`

**VerificationService** uses one mutex:
- `@stats_mutex` -- protects `@verification_stats` (total, successful, failed counts)

All public methods that read or write these structures synchronize on the appropriate mutex, making the library safe for use in multi-threaded environments such as Puma or Sidekiq.

## Security Logging

### The SecurityLogger Module

`StirShaken::SecurityLogger` provides centralized security event logging for audit trails and monitoring. It is enabled by default and can be disabled by setting the environment variable `STIRSHAKEN_SECURITY_LOGGING=false`.

### Event Types

| Constant Key | Log Code | Description |
|---|---|---|
| `:authentication_success` | `AUTH_SUCCESS` | A call was successfully signed |
| `:authentication_failure` | `AUTH_FAILURE` | Call signing failed |
| `:verification_success` | `VERIFY_SUCCESS` | A call was successfully verified |
| `:verification_failure` | `VERIFY_FAILURE` | Call verification failed |
| `:certificate_fetch` | `CERT_FETCH` | A certificate was fetched (success or failure) |
| `:certificate_validation_failure` | `CERT_INVALID` | Certificate validation failed |
| `:rate_limit_exceeded` | `RATE_LIMIT` | Rate limit was exceeded |
| `:invalid_input` | `INVALID_INPUT` | Invalid input was provided |
| `:configuration_error` | `CONFIG_ERROR` | Configuration validation failed |
| `:network_error` | `NETWORK_ERROR` | A network error occurred |

### Severity Levels

| Level | Log Code | Used For |
|---|---|---|
| `:low` | `LOW` | Successful operations (auth success, verification success, cert fetch) |
| `:medium` | `MEDIUM` | Validation failures (auth failure, verification failure, cert invalid, network error, invalid input) |
| `:high` | `HIGH` | Rate limit exceeded, configuration errors, cert fetch failures, signature verification failures |
| `:critical` | `CRITICAL` | Configuration errors (via `determine_failure_severity`) |

Failure severity is determined dynamically by error class:
- `ConfigurationError` -- CRITICAL
- `CertificateFetchError` -- HIGH
- `SignatureVerificationError` -- HIGH
- `InvalidPhoneNumberError`, `InvalidAttestationError` -- MEDIUM
- All other errors -- MEDIUM

### Phone Number Masking

`SecurityLogger.mask_phone_number` redacts phone numbers in log output to protect personally identifiable information. The first two characters (typically `+` and the country code digit) and the last four digits are preserved; everything between is replaced with `*`:

```
+15551234567 -> +1*****4567
```

Numbers with 6 or fewer characters are returned unmasked.

### URL Masking

`SecurityLogger.mask_url` redacts URL paths while preserving the scheme and host:

```
https://certs.example.com/path/to/cert.pem -> https://certs.example.com/***
```

Non-default ports are preserved. Invalid URIs are replaced with `***` entirely.

### Rails Logger Integration

`SecurityLogger` automatically detects Rails and routes log entries to `Rails.logger` with severity-appropriate methods:

- `CRITICAL` and `HIGH` severity -- `Rails.logger.error`
- `MEDIUM` severity -- `Rails.logger.warn`
- `LOW` severity -- `Rails.logger.info`

When Rails is not available, log entries are written to `$stderr`.

All log entries are prefixed with `[STIRSHAKEN-SECURITY]` and formatted as JSON, including:
- `timestamp` (ISO 8601)
- `event_type`
- `severity`
- `details` (sanitized)
- `library_version`
- `process_id`

### Detail Sanitization

Before logging, `sanitize_details` removes sensitive fields (`private_key`, `jwt_token`) and applies phone number masking to `originating_number` values.

## Configuration Security Validation

`StirShaken.configure` calls `validate_security!` after the configuration block runs. In non-test environments, the following constraints are enforced:

| Setting | Minimum | Maximum | Default |
|---|---|---|---|
| `http_timeout` | 5 seconds | 120 seconds | 30 seconds |
| `certificate_cache_ttl` | 300 seconds (5 min) | 86400 seconds (24 hr) | 3600 seconds (1 hr) |
| `default_max_age` | 1 second | 900 seconds (15 min) | 60 seconds |
| `default_attestation` | Must be `A`, `B`, or `C` | -- | `C` |

Violations raise `ConfigurationError`. These bounds prevent:
- Timeouts too low to complete legitimate requests, or too high to enable DoS
- Cache TTLs too low (excessive fetching / rate limit exhaustion) or too high (stale certificates)
- Token max ages too high (stale tokens accepted)

Security validation is skipped in test environments (`RAILS_ENV=test`, `RACK_ENV=test`, or when `RSpec` is defined).

## Error Hierarchy

All errors inherit from `StirShaken::Error`, which inherits from `StandardError`.

| Error Class | Parent | Triggered By |
|---|---|---|
| `StirShaken::Error` | `StandardError` | Base class; not raised directly |
| `PassportValidationError` | `Error` | Missing/invalid JWT header fields (`alg`, `typ`, `ppt`, `x5u`), missing payload claims (`attest`, `dest`, `iat`, `orig`, `origid`), invalid attestation level, invalid phone number format |
| `CertificateError` | `Error` | Base class for certificate errors; not raised directly |
| `CertificateFetchError` | `CertificateError` | Non-HTTPS URL, SSRF violation (private/loopback address), rate limit exceeded, HTTP error response, network timeout, DNS resolution failure |
| `CertificateValidationError` | `CertificateError` | Non-EC public key, wrong curve (not P-256), invalid certificate format (PEM/DER parse failure), certificate pin mismatch |
| `CertificateRevocationError` | `CertificateError` | Certificate has been revoked (reserved for CRL/OCSP checks) |
| `SignatureVerificationError` | `Error` | ECDSA signature does not match the token content and public key |
| `InvalidAttestationError` | `Error` | Attestation level is not `A`, `B`, or `C` |
| `InvalidPhoneNumberError` | `Error` | Phone number does not match E.164 format (`/^\+[1-9]\d{1,14}$/`) |
| `InvalidIdentityHeaderError` | `Error` | Malformed SIP Identity header (missing token/parameters separator, missing required `info`/`alg`/`ppt` parameters, unsupported algorithm or extension, invalid info URL, header injection characters in parameters) |
| `InvalidTokenError` | `Error` | JWT decode failure (malformed Base64, invalid JSON, corrupted token structure) |
| `ConfigurationError` | `Error` | Invalid configuration values (timeout, cache TTL, max age out of bounds; invalid attestation level) |
| `InvalidDiversionReasonError` | `Error` | Diversion reason in a div-PASSporT is not a recognized value |
