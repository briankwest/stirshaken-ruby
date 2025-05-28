# STIR/SHAKEN Ruby Library - Examples

This directory contains comprehensive examples demonstrating every aspect of the STIR/SHAKEN Ruby library. Each example file focuses on a specific component or use case, providing practical code samples and detailed explanations.

## 📁 Example Files

### 🔧 Core Components

#### [`basic_usage.rb`](basic_usage.rb)
**Quick start guide and basic functionality**
- Key generation and certificate creation
- Basic call signing and verification
- Error handling examples
- Configuration overview

#### [`authentication_service_examples.rb`](authentication_service_examples.rb)
**Authentication Service - Comprehensive Examples**
- Service setup and configuration
- Single and multiple destination call signing
- All attestation levels (A, B, C)
- Custom origination IDs and additional parameters
- Direct PASSporT token creation
- Service information and authorization checking
- Batch call processing
- Performance measurement
- Real-world certificate loading patterns

#### [`verification_service_examples.rb`](verification_service_examples.rb)
**Verification Service - Comprehensive Examples**
- Basic verification service setup
- Call verification with expected number validation
- Token age validation and expiration handling
- All attestation levels verification
- Direct PASSporT token verification
- Structure validation for debugging
- Multiple destination number handling
- Verification statistics and monitoring
- Error handling for various failure scenarios
- Certificate authorization testing
- Batch verification processing
- Advanced scenarios (emergency, international, toll-free)

#### [`certificate_management_examples.rb`](certificate_management_examples.rb)
**Certificate Management - Comprehensive Examples**
- Certificate manager usage and singleton pattern
- Creating test certificates with various configurations
- Certificate validation and expiration checking
- Certificate caching with TTL management
- HTTP certificate fetching simulation
- Telephone number authorization checking
- Certificate information extraction
- Cache management operations
- Performance testing and optimization
- Real-world certificate scenarios
- Certificate chain validation concepts

#### [`passport_examples.rb`](passport_examples.rb)
**PASSporT Token - Comprehensive Examples**
- Basic PASSporT token creation and structure
- Token signing with cryptographic signatures
- Token parsing and payload inspection
- JWT header and payload analysis
- Multiple destination number handling
- All attestation levels (A, B, C)
- Custom origination ID patterns
- Comprehensive validation testing
- Token age and expiration checking
- JSON representation and serialization
- Token comparison and equality
- Signature verification with public keys
- Performance testing and optimization
- Advanced scenarios (emergency, international, conference)

#### [`sip_identity_examples.rb`](sip_identity_examples.rb)
**SIP Identity Header - Comprehensive Examples**
- Basic SIP Identity header creation and parsing
- Header structure analysis and parameter inspection
- Multiple destination number handling
- Header validation and error scenarios
- Parameter analysis and additional information
- Header reconstruction and format variations
- Comprehensive error handling
- Performance testing and optimization
- Real SIP message integration
- STIR/SHAKEN compliance checking
- Debug information and troubleshooting
- Advanced scenarios (retransmission, forwarding, robocall detection)

#### [`security_features_examples.rb`](security_features_examples.rb)
**Security Features - 10/10 Security Enhancements**
- Configuration security validation
- Certificate pinning demonstrations
- Rate limiting examples and testing
- Security event logging and monitoring
- Thread safety demonstrations
- Enhanced error handling patterns
- Security best practices implementation
- Production security considerations
- Security audit trail examples
- Advanced security configurations

### 🔗 Integration Examples

#### [`integration_examples.rb`](integration_examples.rb)
**Complete Integration - Real-World Scenarios**
- Complete end-to-end call flows
- Multi-party conference call handling
- Call forwarding chains with attestation degradation
- Emergency call prioritization and handling
- International call routing scenarios
- Robocall detection and blocking strategies
- Load testing and performance analysis
- Certificate management lifecycle
- Error recovery and system resilience
- Real-world integration patterns (SIP proxy, analytics, fraud detection)
- System monitoring and alerting
- Configuration management

## 🚀 Running the Examples

### Prerequisites

Ensure you have the STIR/SHAKEN library installed and all dependencies available:

```bash
# Install dependencies
bundle install

# Verify installation
bundle exec rspec --version
```

### Running Individual Examples

Each example file can be run independently:

```bash
# Basic usage and quick start
ruby examples/basic_usage.rb

# Authentication Service examples
ruby examples/authentication_service_examples.rb

# Verification Service examples
ruby examples/verification_service_examples.rb

# Certificate Management examples
ruby examples/certificate_management_examples.rb

# PASSporT Token examples
ruby examples/passport_examples.rb

# SIP Identity Header examples
ruby examples/sip_identity_examples.rb

# Security Features examples
ruby examples/security_features_examples.rb

# Complete integration examples
ruby examples/integration_examples.rb
```

### Running All Examples

To run all examples in sequence:

```bash
# Run all examples
for file in examples/*.rb; do
  echo "Running $file..."
  ruby "$file"
  echo "Completed $file"
  echo "---"
done
```

## 📚 Example Categories

### 🎯 By Use Case

#### **Getting Started**
- [`basic_usage.rb`](basic_usage.rb) - Start here for quick overview

#### **Authentication (Originating Side)**
- [`authentication_service_examples.rb`](authentication_service_examples.rb) - Complete authentication scenarios
- [`passport_examples.rb`](passport_examples.rb) - PASSporT token creation and management
- [`sip_identity_examples.rb`](sip_identity_examples.rb) - SIP header generation

#### **Verification (Terminating Side)**
- [`verification_service_examples.rb`](verification_service_examples.rb) - Complete verification scenarios
- [`certificate_management_examples.rb`](certificate_management_examples.rb) - Certificate handling

#### **Production Integration**
- [`integration_examples.rb`](integration_examples.rb) - Real-world deployment scenarios

### 🔧 By Component

#### **Core Services**
- Authentication Service
- Verification Service
- Certificate Manager

#### **Data Structures**
- PASSporT Tokens
- SIP Identity Headers
- X.509 Certificates

#### **Utilities**
- Phone Number Validation
- Attestation Level Management
- Error Handling

## 🎓 Learning Path

### **Beginner** (New to STIR/SHAKEN)
1. [`basic_usage.rb`](basic_usage.rb) - Understand core concepts
2. [`authentication_service_examples.rb`](authentication_service_examples.rb) - Learn call signing
3. [`verification_service_examples.rb`](verification_service_examples.rb) - Learn call verification

### **Intermediate** (Familiar with basics)
1. [`passport_examples.rb`](passport_examples.rb) - Deep dive into PASSporT tokens
2. [`sip_identity_examples.rb`](sip_identity_examples.rb) - Understand SIP integration
3. [`certificate_management_examples.rb`](certificate_management_examples.rb) - Master certificate handling

### **Advanced** (Production deployment)
1. [`integration_examples.rb`](integration_examples.rb) - Complete integration patterns
2. Performance optimization examples
3. Error recovery and resilience patterns

## 🔍 Example Features

### **Comprehensive Coverage**
- ✅ All library components demonstrated
- ✅ Real-world scenarios included
- ✅ Error handling patterns shown
- ✅ Performance considerations covered

### **Production Ready**
- ✅ Security best practices
- ✅ Error recovery patterns
- ✅ Performance optimization
- ✅ Monitoring and alerting

### **Educational Value**
- ✅ Step-by-step explanations
- ✅ Code comments and documentation
- ✅ Expected outputs shown
- ✅ Common pitfalls highlighted

## 📊 Example Statistics

| Example File | Lines of Code | Examples Count | Components Covered |
|--------------|---------------|----------------|-------------------|
| `basic_usage.rb` | 149 | 9 | All core components |
| `authentication_service_examples.rb` | 400+ | 12 | Authentication Service |
| `verification_service_examples.rb` | 450+ | 14 | Verification Service |
| `certificate_management_examples.rb` | 500+ | 14 | Certificate Manager |
| `passport_examples.rb` | 450+ | 15 | PASSporT Tokens |
| `sip_identity_examples.rb` | 500+ | 15 | SIP Identity Headers |
| `integration_examples.rb` | 600+ | 12 | Complete Integration |

**Total: 3000+ lines of example code covering 91+ scenarios**

## 🛠 Customization

### Modifying Examples

All examples are designed to be easily modified for your specific use cases:

```ruby
# Change phone numbers
originating_number: '+1YOUR_NUMBER'
destination_number: '+1DEST_NUMBER'

# Modify attestation levels
attestation: 'A'  # or 'B', 'C'

# Customize certificate URLs
certificate_url: 'https://your-domain.com/cert.pem'
```

### Adding New Examples

To add new examples:

1. Create a new `.rb` file in the `examples/` directory
2. Follow the existing pattern:
   ```ruby
   #!/usr/bin/env ruby
   # frozen_string_literal: true
   
   require_relative '../lib/stirshaken'
   
   puts "Your Example Title"
   puts "=" * 50
   
   # Your example code here
   ```
3. Update this README with your new example

## 🔧 Troubleshooting

### Common Issues

#### **Ruby Version Compatibility**
```bash
# Check Ruby version
ruby --version

# Should be Ruby 3.0+ for best compatibility
```

#### **Missing Dependencies**
```bash
# Install missing gems
bundle install

# Check for specific gems
gem list | grep jwt
```

#### **Certificate Errors**
```bash
# Verify OpenSSL version
openssl version

# Should be OpenSSL 3.0+ for Ruby 3.4+
```

### Getting Help

1. **Check the main README**: [`../README.md`](../README.md)
2. **Review the usage guide**: [`../USAGE_GUIDE.md`](../USAGE_GUIDE.md)
3. **Run the test suite**: `bundle exec rspec`
4. **Check example outputs**: Each example shows expected results

## 📈 Performance Notes

### Benchmarking

Most examples include performance measurements:

```ruby
# Typical performance metrics shown:
# - Operations per second
# - Average time per operation
# - Memory usage patterns
# - Cache hit rates
```

### Optimization Tips

1. **Certificate Caching**: Examples show proper cache usage
2. **Batch Processing**: Demonstrated in relevant examples
3. **Error Handling**: Efficient error recovery patterns
4. **Resource Management**: Memory and CPU optimization

## 🔒 Security Considerations

### Key Management

Examples demonstrate:
- ✅ Secure key generation
- ✅ Proper key storage patterns
- ✅ Certificate validation
- ✅ Signature verification

### Best Practices

- ✅ Input validation
- ✅ Error message sanitization
- ✅ Secure random generation
- ✅ Certificate chain validation

## 📝 Contributing

To contribute new examples:

1. Fork the repository
2. Create your example file
3. Follow existing patterns and documentation style
4. Add comprehensive comments
5. Include expected outputs
6. Update this README
7. Submit a pull request

## 📄 License

These examples are part of the STIR/SHAKEN Ruby library and are licensed under the same terms as the main project.

---

**Happy coding with STIR/SHAKEN! 📞🔒** 