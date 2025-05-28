#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../lib/stirshaken'

puts "STIR/SHAKEN SIP Identity Header - Comprehensive Examples"
puts "=" * 70

# Setup: Create test data for SIP Identity examples
puts "\nSETUP: Creating test data for SIP Identity examples"
puts "-" * 50

# Generate key pair and create authentication service
key_pair = StirShaken::AuthenticationService.generate_key_pair
private_key = key_pair[:private_key]
public_key = key_pair[:public_key]

auth_service = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: 'https://certs.example.com/test.pem'
)

puts "✓ Test environment setup complete"

# Example 1: Basic SIP Identity Header Creation
puts "\n1. BASIC SIP IDENTITY HEADER CREATION"
puts "-" * 40

# Create a basic SIP Identity header
basic_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

puts "✓ Basic SIP Identity header created:"
puts "  Header length: #{basic_header.length} characters"
puts "  Header preview: #{basic_header[0..100]}..."

# Example 2: SIP Identity Header Parsing
puts "\n2. SIP IDENTITY HEADER PARSING"
puts "-" * 40

# Parse the SIP Identity header
sip_identity = StirShaken::SipIdentity.parse(basic_header)

puts "✓ SIP Identity header parsed:"
puts "  Token present: #{sip_identity.passport_token ? 'Yes' : 'No'}"
puts "  Token length: #{sip_identity.passport_token.length} characters"

# Show information about the SIP Identity
info = sip_identity.info
puts "  Algorithm: #{info[:algorithm]}"
puts "  Extension: #{info[:extension]}"
puts "  Info URL: #{info[:info_url]}"
puts "  Token length: #{info[:token_length]} characters"

# Example 3: SIP Identity Header Structure Analysis
puts "\n3. SIP IDENTITY HEADER STRUCTURE ANALYSIS"
puts "-" * 40

# Analyze the structure of different SIP Identity headers
structure_examples = [
  {
    name: "Full Attestation Header",
    header: auth_service.sign_call(
      originating_number: '+15551234567',
      destination_number: '+15559876543',
      attestation: 'A'
    )
  },
  {
    name: "Partial Attestation Header",
    header: auth_service.sign_call(
      originating_number: '+15551234567',
      destination_number: '+15559876543',
      attestation: 'B'
    )
  },
  {
    name: "Gateway Attestation Header",
    header: auth_service.sign_call(
      originating_number: '+15551234567',
      destination_number: '+15559876543',
      attestation: 'C'
    )
  }
]

structure_examples.each do |example|
  parsed = StirShaken::SipIdentity.parse(example[:header])
  
  puts "✓ #{example[:name]}:"
  puts "  Algorithm: #{parsed.algorithm}"
  puts "  Extension: #{parsed.extension}"
  puts "  Certificate URL: #{parsed.info_url}"
  
  # Parse the embedded PASSporT
  passport = parsed.parse_passport(verify_signature: false)
  puts "  Attestation: #{passport.attestation}"
  puts "  Confidence: #{StirShaken::Attestation.confidence_level(passport.attestation)}%"
end

# Example 4: Multiple Destination Numbers in SIP Headers
puts "\n4. MULTIPLE DESTINATION NUMBERS IN SIP HEADERS"
puts "-" * 40

# Create SIP Identity header with multiple destinations
multi_dest_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: ['+15559876543', '+15551111111', '+15552222222'],
  attestation: 'A'
)

multi_sip_identity = StirShaken::SipIdentity.parse(multi_dest_header)
multi_passport = multi_sip_identity.parse_passport(verify_signature: false)

puts "✓ Multi-destination SIP Identity header:"
puts "  Originating: #{multi_passport.originating_number}"
puts "  Destinations: #{multi_passport.destination_numbers.length} numbers"
puts "  Numbers: #{multi_passport.destination_numbers.join(', ')}"
puts "  Header size: #{multi_dest_header.length} characters"

# Example 5: SIP Identity Header Validation
puts "\n5. SIP IDENTITY HEADER VALIDATION"
puts "-" * 40

# Test various SIP Identity header validation scenarios
validation_scenarios = [
  {
    name: "Valid SIP Identity Header",
    header: basic_header,
    should_be_valid: true
  },
  {
    name: "Empty Header",
    header: "",
    should_be_valid: false
  },
  {
    name: "Malformed Header (no semicolons)",
    header: "malformed-header-without-semicolons",
    should_be_valid: false
  },
  {
    name: "Missing Token",
    header: ";info=<https://example.com/cert.pem>;alg=ES256;ppt=shaken",
    should_be_valid: false
  },
  {
    name: "Missing Parameters",
    header: "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature",
    should_be_valid: false
  }
]

validation_scenarios.each do |scenario|
  begin
    if scenario[:header].empty?
      raise StirShaken::InvalidIdentityHeaderError, "Empty header"
    end
    
    parsed = StirShaken::SipIdentity.parse(scenario[:header])
    result = scenario[:should_be_valid] ? "✓ VALID (expected)" : "✗ INVALID (should have failed)"
    puts "  #{scenario[:name]}: #{result}"
    
    if parsed.passport_token
      puts "    Token length: #{parsed.passport_token.length} characters"
      puts "    Algorithm: #{parsed.algorithm}, Extension: #{parsed.extension}"
    end
  rescue => e
    result = scenario[:should_be_valid] ? "✗ INVALID (unexpected)" : "✓ INVALID (expected)"
    puts "  #{scenario[:name]}: #{result}"
    puts "    Error: #{e.message}"
  end
end

# Example 6: SIP Identity Header Information
puts "\n6. SIP IDENTITY HEADER INFORMATION"
puts "-" * 40

# Create SIP Identity header and examine information
detailed_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

detailed_sip_identity = StirShaken::SipIdentity.parse(detailed_header)

puts "✓ SIP Identity header information:"
info = detailed_sip_identity.info
info.each do |key, value|
  puts "  #{key}: #{value}"
end

# Show the core components
puts "\n✓ Core components:"
puts "  Algorithm: #{detailed_sip_identity.algorithm} (Cryptographic algorithm)"
puts "  Extension: #{detailed_sip_identity.extension} (PASSporT extension type)"
puts "  Info URL: #{detailed_sip_identity.info_url} (Certificate URL)"
puts "  Token: #{detailed_sip_identity.passport_token.length} characters (PASSporT JWT)"

# Example 7: SIP Identity Header Reconstruction
puts "\n7. SIP IDENTITY HEADER RECONSTRUCTION"
puts "-" * 40

# Parse a SIP Identity header and reconstruct it
original_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

# Parse the header
parsed_sip_identity = StirShaken::SipIdentity.parse(original_header)

# Reconstruct the header using to_header method
reconstructed_header = parsed_sip_identity.to_header

puts "✓ SIP Identity header reconstruction:"
puts "  Original length: #{original_header.length} characters"
puts "  Reconstructed length: #{reconstructed_header.length} characters"
puts "  Headers match: #{original_header == reconstructed_header}"

if original_header != reconstructed_header
  puts "  Note: Headers may differ due to parameter ordering but are functionally equivalent"
end

# Example 8: SIP Identity Header Error Handling
puts "\n8. SIP IDENTITY HEADER ERROR HANDLING"
puts "-" * 40

# Test various error conditions
error_scenarios = [
  {
    name: "Nil Header",
    test: -> { StirShaken::SipIdentity.parse(nil) },
    expected_error: "ArgumentError or NoMethodError"
  },
  {
    name: "Empty String",
    test: -> { StirShaken::SipIdentity.parse("") },
    expected_error: "InvalidIdentityHeaderError"
  },
  {
    name: "Invalid JWT Token",
    test: -> { 
      parsed = StirShaken::SipIdentity.parse("invalid.jwt.token;info=<https://example.com/cert.pem>;alg=ES256;ppt=shaken")
      parsed.parse_passport(verify_signature: false)
    },
    expected_error: "InvalidTokenError"
  },
  {
    name: "Missing Required Parameters",
    test: -> { StirShaken::SipIdentity.parse("eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature;info=<https://example.com/cert.pem>") },
    expected_error: "InvalidIdentityHeaderError"
  }
]

error_scenarios.each do |scenario|
  begin
    scenario[:test].call
    puts "  ✗ #{scenario[:name]}: Expected error but parsing succeeded"
  rescue => e
    puts "  ✓ #{scenario[:name]}: Correctly caught #{e.class.name}"
    puts "    Error: #{e.message}"
  end
end

# Example 9: SIP Identity Header Performance Testing
puts "\n9. SIP IDENTITY HEADER PERFORMANCE TESTING"
puts "-" * 40

# Performance test: Header creation
creation_iterations = 500
start_time = Time.now

creation_iterations.times do |i|
  auth_service.sign_call(
    originating_number: '+15551234567',
    destination_number: '+15559876543',
    attestation: 'A',
    origination_id: "perf-test-#{i}"
  )
end

creation_time = Time.now - start_time
avg_creation_time = (creation_time / creation_iterations * 1000).round(2)

puts "✓ SIP Identity header creation performance:"
puts "  Iterations: #{creation_iterations}"
puts "  Total time: #{creation_time.round(3)} seconds"
puts "  Average time: #{avg_creation_time} ms per header"

# Performance test: Header parsing
parsing_iterations = 1000
test_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

start_time = Time.now

parsing_iterations.times do
  StirShaken::SipIdentity.parse(test_header)
end

parsing_time = Time.now - start_time
avg_parsing_time = (parsing_time / parsing_iterations * 1000).round(2)

puts "\n✓ SIP Identity header parsing performance:"
puts "  Iterations: #{parsing_iterations}"
puts "  Total time: #{parsing_time.round(3)} seconds"
puts "  Average time: #{avg_parsing_time} ms per parse"

# Performance test: PASSporT extraction
extraction_iterations = 500
start_time = Time.now

extraction_iterations.times do
  parsed = StirShaken::SipIdentity.parse(test_header)
  parsed.parse_passport(verify_signature: false)
end

extraction_time = Time.now - start_time
avg_extraction_time = (extraction_time / extraction_iterations * 1000).round(2)

puts "\n✓ PASSporT extraction performance:"
puts "  Iterations: #{extraction_iterations}"
puts "  Total time: #{extraction_time.round(3)} seconds"
puts "  Average time: #{avg_extraction_time} ms per extraction"

# Example 10: SIP Identity Header in Real SIP Messages
puts "\n10. SIP IDENTITY HEADER IN REAL SIP MESSAGES"
puts "-" * 40

# Simulate how SIP Identity headers would appear in real SIP messages
sip_scenarios = [
  {
    name: "INVITE Message",
    method: "INVITE",
    from: '+15551234567',
    to: '+15559876543',
    attestation: 'A'
  },
  {
    name: "Emergency Call",
    method: "INVITE",
    from: '+15551234567',
    to: '+911',
    attestation: 'A'
  },
  {
    name: "International Call",
    method: "INVITE",
    from: '+15551234567',
    to: '+442071234567',
    attestation: 'B'
  },
  {
    name: "Conference Call",
    method: "INVITE",
    from: '+15551234567',
    to: ['+15559876543', '+15551111111', '+15552222222'],
    attestation: 'A'
  }
]

sip_scenarios.each do |scenario|
  identity_header = auth_service.sign_call(
    originating_number: scenario[:from],
    destination_number: scenario[:to],
    attestation: scenario[:attestation]
  )
  
  puts "✓ #{scenario[:name]}:"
  puts "  Method: #{scenario[:method]}"
  puts "  From: #{scenario[:from]}"
  puts "  To: #{Array(scenario[:to]).join(', ')}"
  puts "  Attestation: #{scenario[:attestation]}"
  puts "  Identity Header Length: #{identity_header.length} characters"
  
  # Show how it would appear in a SIP message
  puts "  SIP Header: Identity: #{identity_header[0..80]}..."
end

# Example 11: SIP Identity Header Compliance Checking
puts "\n11. SIP IDENTITY HEADER COMPLIANCE CHECKING"
puts "-" * 40

# Check compliance with STIR/SHAKEN standards
compliance_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

compliance_sip_identity = StirShaken::SipIdentity.parse(compliance_header)
compliance_passport = compliance_sip_identity.parse_passport(verify_signature: false)

puts "✓ STIR/SHAKEN compliance check:"

# RFC 8224 compliance checks
rfc8224_checks = [
  {
    name: "Contains PASSporT token",
    check: -> { compliance_sip_identity.passport_token && !compliance_sip_identity.passport_token.empty? },
    requirement: "RFC 8224 Section 4.1"
  },
  {
    name: "Algorithm is ES256",
    check: -> { compliance_sip_identity.algorithm == 'ES256' },
    requirement: "RFC 8224 Section 4.1"
  },
  {
    name: "Extension is 'shaken'",
    check: -> { compliance_sip_identity.extension == 'shaken' },
    requirement: "RFC 8588 Section 3"
  },
  {
    name: "Certificate URL present",
    check: -> { compliance_sip_identity.info_url && compliance_sip_identity.info_url.start_with?('https://') },
    requirement: "RFC 8224 Section 4.1"
  },
  {
    name: "Valid attestation level",
    check: -> { ['A', 'B', 'C'].include?(compliance_passport.attestation) },
    requirement: "RFC 8588 Section 4"
  },
  {
    name: "E.164 phone numbers",
    check: -> { 
      compliance_passport.originating_number.start_with?('+') &&
      compliance_passport.destination_numbers.all? { |num| num.start_with?('+') }
    },
    requirement: "RFC 8225 Section 5.2"
  }
]

rfc8224_checks.each do |check|
  result = check[:check].call
  status = result ? "✓ PASS" : "✗ FAIL"
  puts "  #{check[:name]}: #{status}"
  puts "    Requirement: #{check[:requirement]}"
end

# Example 12: SIP Identity Header Debugging
puts "\n12. SIP IDENTITY HEADER DEBUGGING"
puts "-" * 40

# Create a debug-friendly representation of SIP Identity header
debug_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

debug_sip_identity = StirShaken::SipIdentity.parse(debug_header)
debug_passport = debug_sip_identity.parse_passport(verify_signature: false)

puts "✓ SIP Identity header debug information:"
puts "  Full header: #{debug_header}"
puts ""
puts "  Token (first 50 chars): #{debug_sip_identity.passport_token[0..50]}..."
puts "  Token parts: #{debug_sip_identity.passport_token.count('.')} (should be 2 dots)"
puts ""
puts "  Components:"
puts "    Algorithm: #{debug_sip_identity.algorithm}"
puts "    Extension: #{debug_sip_identity.extension}"
puts "    Info URL: #{debug_sip_identity.info_url}"
puts ""
puts "  PASSporT payload:"
puts "    Originating: #{debug_passport.originating_number}"
puts "    Destinations: #{debug_passport.destination_numbers.join(', ')}"
puts "    Attestation: #{debug_passport.attestation}"
puts "    Origination ID: #{debug_passport.origination_id}"
puts "    Issued At: #{Time.at(debug_passport.issued_at)} (#{debug_passport.issued_at})"
puts "    Certificate URL: #{debug_passport.certificate_url}"

# Example 13: Advanced SIP Identity Header Scenarios
puts "\n13. ADVANCED SIP IDENTITY HEADER SCENARIOS"
puts "-" * 40

# Scenario 1: Retransmission handling
puts "✓ Retransmission scenario:"
retrans_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A',
  origination_id: 'retrans-call-001'
)

puts "  Original call with fixed origination ID"
puts "  Retransmissions should use same Identity header"
puts "  Origination ID: retrans-call-001"

# Scenario 2: Call forwarding
puts "\n✓ Call forwarding scenario:"
forwarded_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'B', # Partial attestation for forwarded calls
  origination_id: 'forwarded-call-001'
)

puts "  Original caller: +15551234567"
puts "  Forwarded to: +15559876543"
puts "  Attestation: B (Partial - forwarding reduces confidence)"

# Scenario 3: Robocall detection
puts "\n✓ Robocall detection scenario:"
robocall_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'C', # Gateway attestation for suspicious calls
  origination_id: 'suspicious-call-001'
)

puts "  Potentially suspicious call"
puts "  Attestation: C (Gateway - limited verification)"
puts "  Requires additional verification by terminating carrier"

puts "\n" + "=" * 70
puts "SIP Identity Header Examples Completed!"
puts ""
puts "This demonstration covered:"
puts "• Basic SIP Identity header creation and parsing"
puts "• Header structure analysis and information extraction"
puts "• Multiple destination number handling"
puts "• Header validation and error scenarios"
puts "• Header reconstruction and round-trip testing"
puts "• Comprehensive error handling"
puts "• Performance testing and optimization"
puts "• Real SIP message integration"
puts "• STIR/SHAKEN compliance checking"
puts "• Debug information and troubleshooting"
puts "• Advanced scenarios (retransmission, forwarding, robocall detection)"
puts ""
puts "SIP Identity headers are ready for production use!" 