# STIR/SHAKEN Certificate Management Guide

This guide covers everything you need to know about certificates for STIR/SHAKEN implementation, from testing with self-signed certificates to obtaining production certificates from authorized STI-CAs.

## Table of Contents

1. [Overview](#overview)
2. [Testing Certificates](#testing-certificates)
3. [Production Certificates](#production-certificates)
4. [STI-CA Providers](#sti-ca-providers)
5. [Certificate Requirements](#certificate-requirements)
6. [Certificate Validation](#certificate-validation)
7. [Certificate Management](#certificate-management)
8. [Troubleshooting](#troubleshooting)

## Overview

STIR/SHAKEN requires X.509 certificates with specific extensions and properties. There are two types of certificates you'll work with:

- **Test Certificates**: Self-signed certificates for development and testing
- **Production Certificates**: Certificates issued by authorized STI-CAs for production use

## Testing Certificates

### Quick Start

Generate a test certificate using our automated script:

```bash
# Generate default test certificate
./scripts/generate_test_certificate.sh

# Generate certificate with custom parameters
./scripts/generate_test_certificate.sh \
  --name my-test-cert \
  --org "My Telecom Company" \
  --phone "+15551234567,+15559876543" \
  --days 30
```

### Manual Certificate Generation

If you prefer to generate certificates manually:

#### 1. Generate Private Key (ES256 - P-256 Curve)

```bash
# Generate EC private key using P-256 curve (required for ES256)
openssl ecparam -genkey -name prime256v1 -out private_key.pem

# Extract public key
openssl ec -in private_key.pem -pubout -out public_key.pem
```

#### 2. Create OpenSSL Configuration

Create a configuration file `cert_config.conf`:

```ini
[ req ]
default_bits = 2048
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
C = US
ST = California
L = San Francisco
O = Test Service Provider
OU = STIR/SHAKEN Testing
CN = test.example.com
emailAddress = admin@test.example.com

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
extendedKeyUsage = clientAuth, serverAuth

# STIR/SHAKEN specific extensions
1.3.6.1.5.5.7.1.26 = ASN1:UTF8String:12345678-1234-5678-9012-123456789012

[ alt_names ]
DNS.1 = test.example.com
DNS.2 = *.test.example.com
URI.1 = sip:test@example.com
URI.2 = tel:+15551234567
URI.3 = tel:+15559876543
```

#### 3. Generate Certificate

```bash
# Create certificate signing request
openssl req -new -key private_key.pem -out cert_request.csr -config cert_config.conf

# Generate self-signed certificate
openssl x509 -req -in cert_request.csr -signkey private_key.pem \
  -out certificate.pem -days 365 -extensions v3_req -extfile cert_config.conf

# Verify certificate
openssl x509 -in certificate.pem -text -noout
```

### Using Test Certificates in Ruby

```ruby
require 'stirshaken'

StirShaken.configure do |config|
  config.private_key_path = './certs/stirshaken-test.key'
  config.certificate_url = 'file://./certs/stirshaken-test.pem'
  config.cache_certificates = false  # Disable caching for testing
end

# Create authentication service
auth_service = StirShaken::AuthenticationService.new

# Generate Identity header
identity_header = auth_service.create_identity_header(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A'
)

puts "Identity: #{identity_header}"
```

## Production Certificates

### Overview

Production STIR/SHAKEN certificates must be obtained from authorized STI-CAs (STIR/SHAKEN Token Issuing Certificate Authorities). These certificates are tied to your Service Provider Code (SPC) and authorized telephone number ranges.

### Prerequisites

Before obtaining a production certificate, you need:

1. **Service Provider Code (SPC)**: A unique identifier assigned by the SPC Registry
2. **Operating Company Number (OCN)**: Your FCC-assigned OCN
3. **Authorized Number Ranges**: Documentation of telephone numbers you're authorized to use
4. **Legal Entity Verification**: Proof of your organization's legal status
5. **Technical Contact Information**: Designated technical contacts for certificate management

### Certificate Request Process

#### Step 1: Choose an STI-CA

Select an authorized STI-CA from the list below. Each has different processes and pricing.

#### Step 2: Prepare Documentation

Gather required documentation:

- **Legal Entity Documents**: Articles of incorporation, business license
- **FCC Authorization**: OCN assignment letter, tariff filings
- **Number Authorization**: LOAs (Letters of Authorization) for number ranges
- **Technical Specifications**: Network architecture, SIP infrastructure details
- **Security Policies**: Certificate management and key protection procedures

#### Step 3: Generate Certificate Signing Request (CSR)

```bash
# Generate private key (keep this secure!)
openssl ecparam -genkey -name prime256v1 -out production_private_key.pem
chmod 600 production_private_key.pem

# Create production CSR configuration
cat > production_csr.conf << EOF
[ req ]
default_bits = 2048
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
C = US
ST = [Your State]
L = [Your City]
O = [Your Organization Name]
OU = STIR/SHAKEN Production
CN = [your-domain.com]
emailAddress = [certificates@your-domain.com]

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
extendedKeyUsage = clientAuth, serverAuth

[ alt_names ]
DNS.1 = [your-domain.com]
DNS.2 = [*.your-domain.com]
URI.1 = sip:[your-sip-domain.com]
# Add your authorized telephone number ranges
URI.2 = tel:+1555NXXXXXX
URI.3 = tel:+1556NXXXXXX
EOF

# Generate CSR
openssl req -new -key production_private_key.pem -out production_cert.csr -config production_csr.conf
```

#### Step 4: Submit to STI-CA

Submit your CSR along with required documentation to your chosen STI-CA. The process typically includes:

1. **Application Submission**: Online form with CSR and documentation
2. **Identity Verification**: STI-CA verifies your organization and authority
3. **Technical Review**: Validation of technical requirements and number authorization
4. **Certificate Issuance**: Signed certificate delivered securely
5. **Installation Support**: Assistance with certificate deployment

#### Step 5: Certificate Installation

```ruby
# Production configuration
StirShaken.configure do |config|
  config.private_key_path = '/secure/path/to/production_private_key.pem'
  config.certificate_url = 'https://your-domain.com/certificates/stirshaken.pem'
  config.cache_certificates = true
  config.certificate_cache_ttl = 3600  # 1 hour
  
  # Security settings
  config.validate_certificates = true
  config.require_fresh_certificates = true
  config.max_token_age = 60  # seconds
end
```

## STI-CA Providers

### Authorized STI-CAs

As of 2024, the following organizations are authorized STI-CAs:

#### 1. **TransNexus**
- **Website**: https://transnexus.com/
- **Services**: STIR/SHAKEN certificates, ClearIP platform
- **Specialization**: Comprehensive STIR/SHAKEN solutions
- **Contact**: certificates@transnexus.com

#### 2. **Neustar**
- **Website**: https://www.home.neustar/
- **Services**: Trusted Call Solutions, certificate management
- **Specialization**: Large-scale carrier solutions
- **Contact**: stirshaken@neustar.biz

#### 3. **Sectigo (formerly Comodo CA)**
- **Website**: https://sectigo.com/
- **Services**: STIR/SHAKEN certificates, PKI solutions
- **Specialization**: Enterprise PKI and certificate management
- **Contact**: enterprise@sectigo.com

#### 4. **DigiCert**
- **Website**: https://www.digicert.com/
- **Services**: STIR/SHAKEN certificates, IoT device certificates
- **Specialization**: High-assurance certificates
- **Contact**: enterprise@digicert.com

#### 5. **Bandwidth**
- **Website**: https://www.bandwidth.com/
- **Services**: STIR/SHAKEN certificates, voice services
- **Specialization**: Voice service providers
- **Contact**: stirshaken@bandwidth.com

### Choosing an STI-CA

Consider these factors when selecting an STI-CA:

- **Pricing**: Certificate costs and renewal fees
- **Support**: Technical support quality and availability
- **Integration**: API availability and integration tools
- **Reputation**: Industry standing and reliability
- **Geographic Coverage**: Service availability in your regions
- **Additional Services**: Bundled STIR/SHAKEN services

## Certificate Requirements

### Technical Requirements

STIR/SHAKEN certificates must meet these specifications:

#### Algorithm Support
- **Signature Algorithm**: ES256 (ECDSA using P-256 and SHA-256)
- **Key Type**: Elliptic Curve (EC)
- **Curve**: P-256 (prime256v1)
- **Key Size**: 256 bits

#### Certificate Extensions

**Required Extensions:**
- `keyUsage`: digitalSignature, nonRepudiation
- `extendedKeyUsage`: clientAuth, serverAuth
- `subjectAltName`: DNS names and SIP URIs
- `basicConstraints`: CA:FALSE

**STIR/SHAKEN Specific Extensions:**
- **SPC Token** (OID 1.3.6.1.5.5.7.1.26): Service Provider Code
- **Telephone Number Authorization**: URI extensions with tel: scheme

#### Subject Information

```
C = [Country Code]
ST = [State/Province]
L = [City/Locality]
O = [Organization Name]
OU = [Organizational Unit]
CN = [Common Name - your domain]
emailAddress = [Certificate contact email]
```

### Validation Requirements

STI-CAs must validate:

1. **Legal Entity**: Organization's legal existence and standing
2. **Domain Control**: Control over certificate domain names
3. **Number Authorization**: Authority to use specified telephone numbers
4. **Technical Capability**: Ability to properly implement STIR/SHAKEN
5. **Operational Security**: Adequate security controls and procedures

## Certificate Validation

### Automatic Validation

The Ruby library automatically validates certificates:

```ruby
# Certificate validation is enabled by default
verification_service = StirShaken::VerificationService.new

result = verification_service.verify_call(
  identity_header: identity_header,
  originating_number: '+15551234567',
  destination_number: '+15559876543'
)

if result.valid?
  puts "Certificate validation: PASSED"
  puts "Attestation level: #{result.attestation}"
  puts "Confidence: #{result.confidence}%"
else
  puts "Certificate validation: FAILED"
  puts "Reason: #{result.reason}"
end
```

### Manual Validation

You can also validate certificates manually:

```bash
# Download and verify certificate
curl -o cert.pem https://your-domain.com/certificates/stirshaken.pem

# Verify certificate structure
openssl x509 -in cert.pem -text -noout

# Check certificate chain (if intermediate CAs are used)
openssl verify -CAfile ca-bundle.pem cert.pem

# Verify certificate against CRL/OCSP
openssl ocsp -issuer ca-cert.pem -cert cert.pem -url http://ocsp.sti-ca.com
```

### Certificate Pinning

For enhanced security, implement certificate pinning:

```ruby
StirShaken.configure do |config|
  # Pin specific certificate fingerprints
  config.pinned_certificates = {
    'https://your-domain.com/certificates/stirshaken.pem' => 
      'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
  }
end
```

## Certificate Management

### Certificate Lifecycle

#### 1. **Issuance** (Day 0)
- Generate key pair
- Submit CSR to STI-CA
- Complete validation process
- Receive signed certificate

#### 2. **Deployment** (Day 1-7)
- Install certificate in production
- Configure certificate URL
- Test STIR/SHAKEN functionality
- Monitor certificate usage

#### 3. **Operation** (Ongoing)
- Monitor certificate expiration
- Maintain certificate availability
- Handle certificate revocation if needed
- Monitor for security incidents

#### 4. **Renewal** (30-90 days before expiration)
- Generate new key pair (recommended)
- Submit renewal CSR
- Complete re-validation if required
- Deploy new certificate

#### 5. **Revocation** (If compromised)
- Report compromise to STI-CA
- Request certificate revocation
- Generate new certificate immediately
- Update all systems

### Best Practices

#### Security
- **Key Protection**: Store private keys in HSMs or secure key stores
- **Access Control**: Limit access to certificate management systems
- **Monitoring**: Monitor certificate usage and access logs
- **Backup**: Maintain secure backups of certificates and keys
- **Rotation**: Rotate certificates regularly (annually recommended)

#### Operational
- **Automation**: Automate certificate renewal and deployment
- **Monitoring**: Set up expiration alerts (30, 14, 7 days)
- **Testing**: Test certificate functionality after deployment
- **Documentation**: Maintain certificate inventory and procedures
- **Incident Response**: Have procedures for certificate compromise

#### High Availability
- **Multiple Certificates**: Use multiple certificates for redundancy
- **Load Balancing**: Distribute certificate serving across multiple servers
- **Caching**: Implement appropriate certificate caching
- **Fallback**: Have fallback procedures for certificate failures

### Certificate Monitoring

```ruby
# Monitor certificate expiration
def check_certificate_expiration(cert_url)
  cert_manager = StirShaken::CertificateManager.new
  cert = cert_manager.fetch_certificate(cert_url)
  
  expiration = cert.not_after
  days_until_expiration = (expiration - Time.now) / (24 * 60 * 60)
  
  if days_until_expiration < 30
    puts "WARNING: Certificate expires in #{days_until_expiration.to_i} days"
    # Send alert to operations team
  end
  
  puts "Certificate expires: #{expiration}"
  puts "Days remaining: #{days_until_expiration.to_i}"
end

# Check certificate validity
def validate_certificate_chain(cert_url)
  cert_manager = StirShaken::CertificateManager.new
  
  begin
    cert = cert_manager.fetch_certificate(cert_url)
    puts "Certificate validation: PASSED"
    puts "Subject: #{cert.subject}"
    puts "Issuer: #{cert.issuer}"
    puts "Valid from: #{cert.not_before}"
    puts "Valid until: #{cert.not_after}"
  rescue => e
    puts "Certificate validation: FAILED"
    puts "Error: #{e.message}"
  end
end
```

## Troubleshooting

### Common Issues

#### Certificate Not Found (404)
```
Error: Failed to fetch certificate from https://example.com/cert.pem: 404 Not Found
```

**Solutions:**
- Verify certificate URL is correct
- Check web server configuration
- Ensure certificate file exists and is accessible
- Verify DNS resolution

#### Certificate Expired
```
Error: Certificate has expired
```

**Solutions:**
- Renew certificate with STI-CA
- Update certificate URL if renewed
- Check system clock synchronization
- Implement certificate monitoring

#### Invalid Certificate Format
```
Error: Invalid certificate format
```

**Solutions:**
- Verify certificate is in PEM format
- Check for certificate corruption
- Ensure complete certificate chain
- Validate certificate structure with OpenSSL

#### Key Mismatch
```
Error: Private key does not match certificate
```

**Solutions:**
- Verify private key corresponds to certificate
- Check key file permissions and accessibility
- Regenerate key pair if necessary
- Ensure proper key format (PEM)

#### Algorithm Not Supported
```
Error: Unsupported signature algorithm
```

**Solutions:**
- Ensure certificate uses ES256 algorithm
- Verify elliptic curve is P-256
- Check OpenSSL version compatibility
- Regenerate certificate with correct algorithm

### Debugging Tools

#### Certificate Analysis
```bash
# View certificate details
openssl x509 -in certificate.pem -text -noout

# Check certificate and key match
openssl x509 -in certificate.pem -pubkey -noout | openssl md5
openssl rsa -in private_key.pem -pubout | openssl md5

# Verify certificate chain
openssl verify -CAfile ca-bundle.pem certificate.pem

# Test certificate URL
curl -I https://your-domain.com/certificates/stirshaken.pem
```

#### Ruby Debugging
```ruby
# Enable debug logging
StirShaken.configure do |config|
  config.logger = Logger.new(STDOUT)
  config.logger.level = Logger::DEBUG
end

# Test certificate loading
cert_manager = StirShaken::CertificateManager.new
begin
  cert = cert_manager.fetch_certificate('https://your-domain.com/cert.pem')
  puts "Certificate loaded successfully"
  puts "Subject: #{cert.subject}"
  puts "Expires: #{cert.not_after}"
rescue => e
  puts "Certificate loading failed: #{e.message}"
  puts e.backtrace
end
```

### Support Resources

#### STI-CA Support
- Contact your STI-CA's technical support
- Review STI-CA documentation and FAQs
- Check STI-CA status pages for service issues

#### Industry Resources
- **ATIS**: https://www.atis.org/stir-shaken/
- **FCC STIR/SHAKEN**: https://www.fcc.gov/call-authentication
- **RFC 8224**: https://tools.ietf.org/html/rfc8224
- **RFC 8225**: https://tools.ietf.org/html/rfc8225

#### Community Support
- STIR/SHAKEN working groups
- Telecom industry forums
- Technical mailing lists
- GitHub issues and discussions

---

## Quick Reference

### Test Certificate Generation
```bash
./scripts/generate_test_certificate.sh --name my-test --days 30
```

### Production Certificate CSR
```bash
openssl ecparam -genkey -name prime256v1 -out prod_key.pem
openssl req -new -key prod_key.pem -out prod_csr.csr -config prod_config.conf
```

### Certificate Validation
```bash
openssl x509 -in certificate.pem -text -noout
openssl verify -CAfile ca-bundle.pem certificate.pem
```

### Ruby Configuration
```ruby
StirShaken.configure do |config|
  config.private_key_path = '/path/to/private_key.pem'
  config.certificate_url = 'https://domain.com/cert.pem'
end
```

For additional support, please refer to the main documentation or contact your STI-CA provider. 