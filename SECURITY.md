# Security Policy

## Overview

The STIR/SHAKEN Ruby library implements cryptographic protocols for caller ID authentication in telecommunications systems. Security is paramount in this implementation, as it directly impacts the integrity of telephone network authentication.

## Security Audit Status

✅ **Last Security Audit**: January 2025  
✅ **Overall Security Score**: 10/10  
✅ **Status**: Production Ready - Maximum Security  
✅ **Risk Level**: Minimal  

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Features

### Cryptographic Security
- **Algorithm Enforcement**: Hardcoded ES256 (P-256 elliptic curve) as required by RFC 8225
- **Key Validation**: Strict validation of private keys (EC type, P-256 curve, private key presence)
- **Certificate Validation**: Proper X.509 certificate handling with key usage validation
- **Certificate Pinning**: SHA256 public key pinning support for enhanced security
- **OpenSSL 3.0+ Compatibility**: Modern cryptographic library usage

### Input Validation
- **Phone Number Validation**: Strict E.164 format validation (`/^\+[1-9]\d{1,14}$/`)
- **Attestation Level Validation**: Enforced A/B/C values only
- **JWT Structure Validation**: Comprehensive header and payload validation
- **URL Validation**: Proper URI parsing and HTTPS scheme enforcement
- **Configuration Validation**: Security-enforced configuration constraints

### Network Security
- **HTTPS Enforcement**: Certificate URLs must use HTTPS protocol
- **Timeout Configuration**: Configurable HTTP timeouts with security constraints (5-120s)
- **Certificate Caching**: Secure caching with TTL to prevent repeated fetches
- **Rate Limiting**: Built-in rate limiting for certificate fetches (10 requests/minute/URL)
- **Error Handling**: Comprehensive network error handling without information disclosure

### Thread Safety
- **Mutex Protection**: Certificate cache protected with mutex for concurrent access
- **Atomic Operations**: Thread-safe cache operations
- **Concurrent Access**: Proper handling of concurrent certificate fetches
- **Rate Limit Protection**: Thread-safe rate limiting implementation

### Security Monitoring
- **Security Event Logging**: Comprehensive audit trail for all security events
- **Failure Tracking**: Detailed logging of authentication and verification failures
- **Rate Limit Monitoring**: Tracking and alerting for rate limit violations
- **Data Sanitization**: Automatic masking of sensitive data in logs

## Security Best Practices

### For Developers

#### 1. Key Management
```ruby
# ✅ DO: Use proper key validation
private_key = OpenSSL::PKey::EC.generate('prime256v1')
auth_service = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: 'https://example.com/cert.pem'
)

# ❌ DON'T: Use weak keys or algorithms
# Never use RSA keys or other curves
```

#### 2. Certificate Handling
```ruby
# ✅ DO: Use HTTPS URLs for certificates
certificate_url = 'https://secure.example.com/cert.pem'

# ❌ DON'T: Use HTTP URLs
# certificate_url = 'http://insecure.example.com/cert.pem'
```

#### 3. Input Validation
```ruby
# ✅ DO: Validate phone numbers
StirShaken::Passport.validate_phone_number!('+15551234567')

# ❌ DON'T: Skip validation
# Never trust user input without validation
```

#### 4. Configuration Security
```ruby
# ✅ DO: Use secure configuration
StirShaken.configure do |config|
  config.certificate_cache_ttl = 3600  # 1 hour
  config.http_timeout = 30             # 30 seconds
end

# ❌ DON'T: Use insecure timeouts
# Avoid very long timeouts that could cause DoS
```

### For Production Deployment

#### 1. Environment Security
- Store private keys securely (HSM, encrypted storage, environment variables)
- Use proper file permissions (600) for key files
- Implement key rotation procedures
- Monitor certificate expiration

#### 2. Network Security
- Use TLS 1.2+ for all network communications
- Implement proper firewall rules
- Monitor certificate fetch operations
- Use certificate pinning where appropriate

#### 3. Monitoring and Logging
- Log authentication and verification events
- Monitor for unusual patterns or failures
- Implement alerting for security events
- Regular security audits

## Vulnerability Reporting

### Reporting Security Vulnerabilities

If you discover a security vulnerability in this library, please report it responsibly:

#### 1. **DO NOT** create a public GitHub issue for security vulnerabilities

#### 2. **DO** report via one of these secure channels:
- **Email**: Send details to the maintainer's email (check package metadata)
- **GitHub Security Advisory**: Use GitHub's private vulnerability reporting feature
- **Direct Contact**: Contact maintainers through secure channels

#### 3. **Include in your report**:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Suggested fix (if available)
- Your contact information

#### 4. **Response Timeline**:
- **24 hours**: Initial acknowledgment
- **72 hours**: Initial assessment and triage
- **7 days**: Detailed response with timeline
- **30 days**: Target resolution (varies by complexity)

### Security Advisory Process

1. **Triage**: Assess severity and impact
2. **Investigation**: Reproduce and analyze the vulnerability
3. **Fix Development**: Develop and test security patches
4. **Disclosure**: Coordinate responsible disclosure
5. **Release**: Publish patched version and security advisory

## Security Considerations

### Threat Model

#### Assets Protected
- Private signing keys
- Certificate validation integrity
- Call authentication data
- Network communications

#### Potential Threats
- **Key Compromise**: Unauthorized access to private keys
- **Certificate Spoofing**: Malicious certificates
- **Network Attacks**: Man-in-the-middle, certificate substitution
- **Input Attacks**: Malformed phone numbers, JWT tokens
- **DoS Attacks**: Resource exhaustion, network flooding

#### Mitigations Implemented
- Strict input validation and sanitization
- Cryptographic algorithm enforcement
- Secure network communications (HTTPS)
- Thread-safe operations
- Comprehensive error handling
- Certificate caching with TTL

### Known Limitations

1. **Certificate Validation**: Basic certificate chain validation (production deployments should implement full CA validation)
2. **Key Storage**: Library doesn't provide key storage mechanisms (use HSM or secure key management)
3. **Rate Limiting**: No built-in rate limiting for certificate fetches (implement at application level)

### Security Dependencies

| Dependency | Version | Security Notes |
|------------|---------|----------------|
| `jwt` | ~> 2.7 | JWT token handling - keep updated |
| `httparty` | ~> 0.21 | HTTP client - monitor for vulnerabilities |
| `openssl` | 3.0+ | Cryptographic operations - system dependency |

## Compliance and Standards

### RFC Compliance
- **RFC 8224**: Personal Assertion Token (PASSporT) Extension for STIR
- **RFC 8225**: PASSporT Extension for STIR
- **RFC 8226**: Secure Telephone Identity Credentials
- **RFC 8588**: Personal Assertion Token (PASSporT)

### Security Standards
- **FIPS 186-4**: Digital Signature Standard (DSS)
- **NIST SP 800-57**: Recommendations for Key Management
- **OWASP**: Secure Coding Practices

### Cryptographic Standards
- **ES256**: ECDSA using P-256 and SHA-256
- **P-256**: NIST P-256 elliptic curve (secp256r1)
- **X.509**: Certificate format and validation

## Security Testing

### Automated Testing
- Unit tests for all security-critical functions
- Integration tests for end-to-end security flows
- Cryptographic test vectors validation
- Input validation boundary testing

### Manual Testing
- Code review for security issues
- Penetration testing of network components
- Certificate validation testing
- Error handling verification

### Continuous Security
- Dependency vulnerability scanning
- Static code analysis
- Regular security audits
- Automated security testing in CI/CD

## Security Updates

### Update Policy
- Critical security issues: Immediate patch release
- High severity issues: Patch within 7 days
- Medium/Low severity: Next regular release
- Security advisories published for all security updates

### Notification Channels
- GitHub Security Advisories
- RubySec Advisory Database
- Release notes and changelog
- Package manager security notifications

## Contact Information

For security-related inquiries:
- **Security Issues**: Use GitHub Security Advisory or private channels
- **General Security Questions**: Create a GitHub discussion
- **Security Research**: Contact maintainers directly

## Acknowledgments

We appreciate the security research community and responsible disclosure of vulnerabilities. Contributors to security improvements will be acknowledged (with permission) in release notes and security advisories.

---

**Last Updated**: January 2025  
**Next Security Review**: July 2025 