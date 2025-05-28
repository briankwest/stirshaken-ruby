#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../lib/stirshaken'

puts "STIR/SHAKEN Ruby Implementation - Basic Usage Example"
puts "=" * 60

# Step 1: Generate a key pair for testing
puts "\n1. Generating EC key pair for testing..."
key_pair = StirShaken::AuthenticationService.generate_key_pair
private_key = key_pair[:private_key]
public_key = key_pair[:public_key]
puts "✓ Generated P-256 EC key pair"

# Step 2: Create a test certificate
puts "\n2. Creating test certificate..."
certificate = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Test STIR Certificate/O=Example Telecom',
  telephone_numbers: ['+15551234567', '+15559876543']
)
puts "✓ Created self-signed certificate with telephone numbers"

# Step 3: Create an authentication service
puts "\n3. Setting up authentication service..."
auth_service = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: 'https://example.com/cert.pem',
  certificate: certificate
)
puts "✓ Authentication service ready"

# Step 4: Sign a call with different attestation levels
puts "\n4. Signing calls with different attestation levels..."

attestation_levels = [
  { level: 'A', description: 'Full Attestation' },
  { level: 'B', description: 'Partial Attestation' },
  { level: 'C', description: 'Gateway Attestation' }
]

signed_calls = {}

attestation_levels.each do |att|
  puts "\n   Signing call with #{att[:description]} (#{att[:level]})..."
  
  identity_header = auth_service.sign_call(
    originating_number: '+15551234567',
    destination_number: '+15559876543',
    attestation: att[:level]
  )
  
  signed_calls[att[:level]] = identity_header
  
  # Show truncated header for readability
  truncated = identity_header.length > 100 ? "#{identity_header[0..100]}..." : identity_header
  puts "   Identity Header: #{truncated}"
  puts "   Confidence Level: #{StirShaken::Attestation.confidence_level(att[:level])}%"
end

# Step 5: Parse and inspect a PASSporT token
puts "\n5. Parsing PASSporT token..."
sip_identity = StirShaken::SipIdentity.parse(signed_calls['A'])
passport = sip_identity.parse_passport(verify_signature: false)

puts "   Originating Number: #{passport.originating_number}"
puts "   Destination Numbers: #{passport.destination_numbers.join(', ')}"
puts "   Attestation: #{passport.attestation}"
puts "   Origination ID: #{passport.origination_id}"
puts "   Issued At: #{Time.at(passport.issued_at)}"
puts "   Certificate URL: #{passport.certificate_url}"

# Step 6: Verify calls
puts "\n6. Verifying signed calls..."
verification_service = StirShaken::VerificationService.new

# Mock certificate in cache for verification
cache = StirShaken::CertificateManager.certificate_cache
mutex = StirShaken::CertificateManager.cache_mutex

mutex.synchronize do
  cache['https://example.com/cert.pem'] = {
    certificate: certificate,
    fetched_at: Time.now
  }
end

attestation_levels.each do |att|
  puts "\n   Verifying #{att[:description]} call..."
  
  result = verification_service.verify_call(
    signed_calls[att[:level]],
    originating_number: '+15551234567',
    destination_number: '+15559876543'
  )
  
  if result.valid?
    puts "   ✓ Verification successful!"
    puts "     Attestation: #{result.attestation}"
    puts "     Confidence: #{result.confidence_level}%"
    puts "     Reason: #{result.reason}"
  else
    puts "   ✗ Verification failed!"
    puts "     Reason: #{result.reason}"
  end
end

# Step 7: Demonstrate error handling
puts "\n7. Demonstrating error handling..."

# Invalid attestation level
begin
  auth_service.sign_call(
    originating_number: '+15551234567',
    destination_number: '+15559876543',
    attestation: 'X'  # Invalid
  )
rescue StirShaken::InvalidAttestationError => e
  puts "   ✓ Caught invalid attestation error: #{e.message}"
end

# Invalid phone number
begin
  auth_service.sign_call(
    originating_number: 'invalid-number',
    destination_number: '+15559876543',
    attestation: 'A'
  )
rescue StirShaken::InvalidPhoneNumberError => e
  puts "   ✓ Caught invalid phone number error: #{e.message}"
end

# Step 8: Show configuration options
puts "\n8. Configuration options..."
puts "   Certificate Cache TTL: #{StirShaken.configuration.certificate_cache_ttl} seconds"
puts "   HTTP Timeout: #{StirShaken.configuration.http_timeout} seconds"
puts "   Default Attestation: #{StirShaken.configuration.default_attestation}"

# Step 9: Certificate cache statistics
puts "\n9. Certificate cache statistics..."
stats = StirShaken::CertificateManager.cache_stats
puts "   Cache size: #{stats[:size]} entries"
puts "   Cached URLs: #{stats[:entries].join(', ')}" if stats[:entries].any?

puts "\n" + "=" * 60
puts "Example completed successfully!"
puts "This demonstrates the core STIR/SHAKEN functionality:"
puts "- Key generation and certificate creation"
puts "- Call signing with different attestation levels"
puts "- PASSporT token parsing and inspection"
puts "- Call verification with confidence levels"
puts "- Error handling for invalid inputs"
puts "- Configuration and caching features" 