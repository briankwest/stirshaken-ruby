# Configuration Reference

The `stirshaken` gem is configured through a global `StirShaken.configure` block. All settings have sensible defaults and are validated automatically for security compliance.

## Basic Usage

```ruby
StirShaken.configure do |config|
  config.certificate_cache_ttl = 3600
  config.http_timeout = 30
  config.default_attestation = 'A'
end
```

The block yields a `StirShaken::Configuration` instance. After the block executes, `validate_security!` runs automatically to enforce the constraints listed below.

## Configuration Options

### `certificate_cache_ttl`

Time-to-live (in seconds) for cached certificates in the `CertificateManager`.

| Property | Value |
|----------|-------|
| **Default** | `3600` (1 hour) |
| **Minimum** | `300` (5 minutes) |
| **Maximum** | `86400` (24 hours) |
| **Type** | Numeric |

Setting the TTL too low causes excessive certificate fetching; setting it too high risks using stale or revoked certificates.

### `http_timeout`

Timeout (in seconds) for HTTP requests when fetching certificates or CRLs.

| Property | Value |
|----------|-------|
| **Default** | `30` |
| **Minimum** | `5` |
| **Maximum** | `120` |
| **Type** | Numeric |

A timeout that is too short may cause transient failures; one that is too long can leave connections open and enable denial-of-service conditions.

### `default_attestation`

The attestation level used when no explicit level is provided.

| Property | Value |
|----------|-------|
| **Default** | `'C'` (Gateway) |
| **Valid values** | `'A'`, `'B'`, `'C'` |
| **Type** | String |

See the [Getting Started guide](getting-started.md#attestation-levels) for a description of each level.

### `default_max_age`

Maximum age (in seconds) a PASSporT token is considered valid during verification.

| Property | Value |
|----------|-------|
| **Default** | `60` (1 minute) |
| **Minimum** | `1` |
| **Maximum** | `900` (15 minutes) |
| **Type** | Numeric |

Tokens older than this value are rejected as expired. A short max age reduces the window for replay attacks.

### `trust_store_path`

Path to a directory of trusted CA certificates for certificate chain validation.

| Property | Value |
|----------|-------|
| **Default** | `nil` |
| **Type** | String (filesystem path) or `nil` |

When set, the `CertificateManager` performs full chain validation against the certificates in this directory instead of basic self-signature verification. The directory should contain PEM-encoded CA certificates.

### `trust_store_certificates`

An array of PEM-encoded certificate strings for trusted CAs.

| Property | Value |
|----------|-------|
| **Default** | `[]` (empty array) |
| **Type** | Array of Strings |

Use this option to supply trusted CA certificates directly in code rather than pointing to a directory on disk. Each element should be a PEM-encoded certificate string. These certificates are loaded into the trust store alongside any certificates from `trust_store_path`.

### `check_revocation`

Enable Certificate Revocation List (CRL) checking during certificate chain validation.

| Property | Value |
|----------|-------|
| **Default** | `false` |
| **Type** | Boolean |

When enabled, CRL Distribution Points are extracted from the certificate and the CRLs are fetched and checked. This adds an extra HTTP request per unique CRL URL but prevents acceptance of revoked certificates.

### `crl_cache_ttl`

Time-to-live (in seconds) for cached CRLs.

| Property | Value |
|----------|-------|
| **Default** | `3600` (1 hour) |
| **Type** | Numeric |

Cached CRLs are reused within this window to avoid repeated downloads.

## Security Validation

After every call to `StirShaken.configure`, the library runs `validate_security!` automatically. This method checks that:

- `http_timeout` is between 5 and 120 (inclusive) and is a positive number.
- `certificate_cache_ttl` is between 300 and 86400 (inclusive) and is a positive number.
- `default_attestation` is one of `A`, `B`, or `C`.
- `default_max_age` is between 1 and 900 (inclusive) and is a positive number.

If any constraint is violated, a `StirShaken::ConfigurationError` is raised with a descriptive message.

### Test Environment Bypass

Security validation is **skipped** when any of the following conditions is true:

- `ENV['RAILS_ENV']` is `'test'`
- `ENV['RACK_ENV']` is `'test'`
- `RSpec` is defined

This lets test suites use extreme values without triggering validation errors.

## Resetting Configuration

To restore all options to their defaults:

```ruby
StirShaken.reset_configuration!
```

This creates a fresh `Configuration` instance. It does **not** clear the certificate cache; use `StirShaken::CertificateManager.clear_cache!` for that.

## Example Configurations

### Development

Reasonable defaults with a short cache for rapid iteration:

```ruby
StirShaken.configure do |config|
  config.certificate_cache_ttl = 300   # 5 minutes (minimum)
  config.http_timeout = 10
  config.default_attestation = 'C'
  config.default_max_age = 120
end
```

### Production

Longer cache, moderate timeout, full attestation by default:

```ruby
StirShaken.configure do |config|
  config.certificate_cache_ttl = 3600  # 1 hour
  config.http_timeout = 30
  config.default_attestation = 'A'
  config.default_max_age = 60
  config.trust_store_path = '/etc/ssl/stir-shaken/trusted-cas'
end
```

### High Security

Full chain validation, CRL checking, and tighter timeouts:

```ruby
StirShaken.configure do |config|
  config.certificate_cache_ttl = 600   # 10 minutes
  config.http_timeout = 15
  config.default_attestation = 'A'
  config.default_max_age = 30

  # Full certificate chain validation
  config.trust_store_path = '/etc/ssl/stir-shaken/trusted-cas'

  # Optionally add individual CA certs inline
  config.trust_store_certificates = [
    File.read('/etc/ssl/stir-shaken/sti-ca.pem')
  ]

  # Enable CRL checking
  config.check_revocation = true
  config.crl_cache_ttl = 1800  # 30 minutes
end
```
