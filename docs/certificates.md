# Certificate Management Guide

## Overview

In STIR/SHAKEN, X.509 certificates are the foundation of caller ID authentication. When an originating service provider signs a call, the PASSporT token's JWT header includes an `x5u` field pointing to the certificate URL. The verifying party fetches that certificate to obtain the public key needed to validate the token's ES256 signature.

The `StirShaken::CertificateManager` class handles the full certificate lifecycle: fetching from remote URLs, caching for performance, validating for STIR/SHAKEN compliance, and checking revocation status. All operations are thread-safe.

## Fetching Certificates

### Basic Fetch

`CertificateManager.fetch_certificate` downloads a certificate from a URL and returns an `OpenSSL::X509::Certificate`:

```ruby
cert = StirShaken::CertificateManager.fetch_certificate(
  "https://certs.example.com/shaken.pem"
)
```

The method enforces HTTPS (per RFC 8226 section 9) and performs SSRF validation before making the request. Both PEM and DER certificate formats are supported -- if PEM parsing fails, the response body is Base64-decoded and parsed as DER.

### Automatic Caching with TTL

Fetched certificates are cached in memory, keyed by URL. On subsequent calls with the same URL, the cached certificate is returned without a network request, as long as the cache entry has not expired.

The cache TTL is controlled by the `certificate_cache_ttl` configuration option (default: 3600 seconds / 1 hour):

```ruby
StirShaken.configure do |c|
  c.certificate_cache_ttl = 1800 # 30 minutes
end
```

The TTL is enforced with security bounds: minimum 300 seconds (5 minutes), maximum 86400 seconds (24 hours). Values outside this range raise a `ConfigurationError` in non-test environments.

### Force Refresh

To bypass the cache and fetch a fresh certificate from the remote URL:

```ruby
cert = StirShaken::CertificateManager.fetch_certificate(
  "https://certs.example.com/shaken.pem",
  force_refresh: true
)
```

The newly fetched certificate replaces the existing cache entry.

### Certificate Pinning

You can pin certificates by providing expected SHA-256 hashes of the certificate's public key DER encoding. If the fetched certificate does not match any of the provided pins, a `CertificateValidationError` is raised:

```ruby
cert = StirShaken::CertificateManager.fetch_certificate(
  "https://certs.example.com/shaken.pem",
  expected_pins: [
    "a1b2c3d4e5f6...",  # SHA-256 hex digest of public key DER
    "f6e5d4c3b2a1..."   # backup pin
  ]
)
```

Pin comparison uses `OpenSSL.fixed_length_secure_compare` to prevent timing attacks. The pin is computed as:

```ruby
Digest::SHA256.hexdigest(certificate.public_key.to_der)
```

## Fetching Certificate Chains

### Multi-PEM Parsing

`fetch_certificate_chain` retrieves a URL that may contain multiple PEM-encoded certificates (e.g., leaf + intermediate + root):

```ruby
chain = StirShaken::CertificateManager.fetch_certificate_chain(
  "https://certs.example.com/chain.pem"
)
# => [<leaf cert>, <intermediate cert>, ...]
```

The method uses `parse_certificate_chain` internally, which scans the response body for all `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` blocks. If no PEM blocks are found, it attempts to parse the entire body as a single DER/PEM certificate.

`parse_certificate_chain` can also be called directly on PEM data:

```ruby
certs = StirShaken::CertificateManager.parse_certificate_chain(pem_string)
```

## Certificate Validation

`CertificateManager.validate_certificate` checks that a certificate is suitable for STIR/SHAKEN use:

```ruby
valid = StirShaken::CertificateManager.validate_certificate(certificate)

# With telephone number authorization check:
valid = StirShaken::CertificateManager.validate_certificate(
  certificate,
  telephone_number: "+15551234567"
)
```

The method performs the following checks in order:

### Expiration Checking

The certificate's `not_after` and `not_before` fields are checked against the current time. Expired certificates or certificates not yet valid are rejected.

### Key Usage

The certificate must have a `keyUsage` extension containing `Digital Signature`. This is required for ES256 signing operations in STIR/SHAKEN.

### Extended Key Usage

If an `extendedKeyUsage` extension is present, it must contain either:
- The STIR/SHAKEN EKU OID `1.3.6.1.5.5.7.3.20` (`id-kp-jwt-stir-shaken`), or
- `TLS Web Server Authentication`

If the extension is absent entirely, this check passes (the extension is not mandatory).

### Telephone Number Authorization

When a `telephone_number` is provided, the method checks whether the certificate authorizes that number. Two mechanisms are tried in order:

1. **TNAuthList extension** (OID `1.3.6.1.5.5.7.1.26`, per RFC 8226): The ASN.1-encoded extension is parsed for `TNEntry` values:
   - Tag 0 (ServiceProviderCode): authorizes all numbers for that SPC -- always returns true.
   - Tag 1 (TelephoneNumberRange): checks if the number falls within the start/count range.
   - Tag 2 (Single TelephoneNumber): exact match against the digits.

2. **SAN tel: URI fallback**: If no TNAuthList extension is present, the `subjectAltName` extension is scanned for `URI:tel:` entries. The phone numbers are normalized (non-digit characters removed, leading `+` ensured) before comparison.

### Certificate Chain Verification

After the above checks, `verify_certificate_chain` is called. Its behavior depends on configuration:

- If a trust store is configured, full chain validation is performed via `OpenSSL::X509::Store` (see below).
- Otherwise, a basic self-signature check is performed as a fallback.

## Trust Store Configuration

For production use, configure a trust store so that certificate chain validation verifies the full path from the leaf certificate to a trusted CA.

### Using `trust_store_path`

Point to a directory of CA certificate files (in the format expected by `OpenSSL::X509::Store#add_path`):

```ruby
StirShaken.configure do |c|
  c.trust_store_path = "/etc/ssl/stir-shaken/trusted-cas"
end
```

### Using `trust_store_certificates`

Provide CA certificates as PEM strings or `OpenSSL::X509::Certificate` objects:

```ruby
StirShaken.configure do |c|
  c.trust_store_certificates = [
    File.read("/path/to/ca1.pem"),
    File.read("/path/to/ca2.pem")
  ]
end
```

Both options can be used together. The trust store is built as an `OpenSSL::X509::Store`, with CA certificates added via `add_path` and `add_cert` respectively. Verification is performed by calling `store.verify(certificate)`.

If verification fails (including `OpenSSL::X509::StoreError` exceptions), the method returns `false` -- it is fail-secure.

## CRL Revocation Checking

### Enabling Revocation Checks

Enable CRL-based revocation checking:

```ruby
StirShaken.configure do |c|
  c.check_revocation = true
  c.trust_store_path = "/etc/ssl/stir-shaken/trusted-cas"
end
```

When enabled, `OpenSSL::X509::Store` is configured with `V_FLAG_CRL_CHECK` and `V_FLAG_CRL_CHECK_ALL` flags, which verify CRLs for every certificate in the chain.

### CRL Distribution Point Extraction

CRL URLs are automatically extracted from the certificate's `crlDistributionPoints` extension by scanning for `URI:` entries.

### CRL Caching

Fetched CRLs are cached with a separate TTL controlled by `crl_cache_ttl` (default: 3600 seconds / 1 hour):

```ruby
StirShaken.configure do |c|
  c.check_revocation = true
  c.crl_cache_ttl = 7200 # 2 hours
end
```

CRL fetching failures are handled gracefully -- if a CRL cannot be fetched or parsed, it is silently skipped (the `fetch_crl` method returns `nil` on any `StandardError`).

## Security Features

### HTTPS-Only Enforcement

Per RFC 8226 section 9, all certificate URLs must use HTTPS. HTTP URLs are rejected with a `CertificateFetchError`. This is enforced by checking that the parsed URI is an instance of `URI::HTTPS`.

### SSRF Protection

Before fetching a certificate, the URL's hostname is resolved via `Addrinfo.getaddrinfo` and each resulting IP address is checked against private and reserved ranges. Requests targeting the following ranges are rejected with a `CertificateFetchError`:

| Range | Description |
|---|---|
| `10.0.0.0/8` | Private (RFC 1918) |
| `172.16.0.0/12` | Private (RFC 1918) |
| `192.168.0.0/16` | Private (RFC 1918) |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local |
| `::1/128` | IPv6 loopback |
| `fc00::/7` | IPv6 unique local |
| `fe80::/10` | IPv6 link-local |

The hostnames `localhost` and `[::1]` are also explicitly rejected before DNS resolution.

Note: There is a known TOCTOU window with DNS rebinding, as documented in the source. The DNS is resolved for the SSRF check, but HTTParty re-resolves at fetch time. This check blocks the vast majority of SSRF attempts.

### Rate Limiting

Certificate fetches are rate-limited to 10 requests per minute per URL. The rate limiter tracks requests by `[url, current_minute]` tuples and automatically cleans up entries older than 2 minutes. Exceeding the limit raises a `CertificateFetchError`.

Rate limiting is disabled in test environments (when `RAILS_ENV=test`, `RACK_ENV=test`, or `RSpec` is defined).

### Constant-Time Pin Comparison

Certificate pin validation uses `OpenSSL.fixed_length_secure_compare` rather than `==` to prevent timing side-channel attacks when comparing pin digests.

## Cache Management

### Clearing the Cache

To clear all cached certificates and reset cache statistics:

```ruby
StirShaken::CertificateManager.clear_cache!
```

### Cache Statistics

Retrieve cache performance metrics:

```ruby
stats = StirShaken::CertificateManager.cache_stats
# => {
#   size: 3,
#   entries: ["https://example.com/***", ...],  # URLs are masked
#   hits: 42,
#   misses: 5,
#   total_requests: 47,
#   hit_rate_percent: 89.36
# }
```

Note that cache entry URLs are masked in the output (domain preserved, path replaced with `***`) via `SecurityLogger.mask_url` to avoid leaking full certificate paths in logs or monitoring.

## Thread Safety

`CertificateManager` uses separate `Mutex` instances to protect concurrent access to shared state:

- `@cache_mutex` -- protects the certificate cache (`@certificate_cache`)
- `@rate_limit_mutex` -- protects the rate limiter hash (`@rate_limiter`)
- `@stats_mutex` -- protects cache hit/miss/fetch counters (`@cache_stats`)
- `@crl_cache_mutex` -- protects the CRL cache (`@crl_cache`)

All public methods that read or write these structures synchronize on the appropriate mutex. This makes `CertificateManager` safe to use from multiple threads, such as in a multi-threaded web server (Puma) or background job processor.
