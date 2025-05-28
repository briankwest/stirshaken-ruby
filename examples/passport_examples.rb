#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../lib/stirshaken'
require 'json'
require 'base64'

puts "STIR/SHAKEN PASSporT Token - Comprehensive Examples"
puts "=" * 70

# Setup: Create test data for PASSporT examples
puts "\nSETUP: Creating test data for PASSporT examples"
puts "-" * 50

# Generate key pair for signing
key_pair = StirShaken::AuthenticationService.generate_key_pair
private_key = key_pair[:private_key]
public_key = key_pair[:public_key]

puts "✓ Generated EC P-256 key pair for PASSporT signing"

# Example 1: Basic PASSporT Token Creation
puts "\n1. BASIC PASSPORT TOKEN CREATION"
puts "-" * 40

# Create a basic PASSporT token using the class method
basic_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A',
  origination_id: 'basic-passport-001',
  certificate_url: 'https://certs.example.com/test.pem',
  private_key: private_key
)

# Parse the token to show its contents
basic_passport = StirShaken::Passport.parse(basic_token, verify_signature: false)

puts "✓ Basic PASSporT token created:"
puts "  Originating: #{basic_passport.originating_number}"
puts "  Destinations: #{basic_passport.destination_numbers.join(', ')}"
puts "  Attestation: #{basic_passport.attestation}"
puts "  Origination ID: #{basic_passport.origination_id}"
puts "  Issued At: #{Time.at(basic_passport.issued_at)}"

# Example 2: PASSporT Token Signing
puts "\n2. PASSPORT TOKEN SIGNING"
puts "-" * 40

# The token is already signed when created
signed_token = basic_token

puts "✓ PASSporT token signed:"
puts "  Token length: #{signed_token.length} characters"
puts "  Token parts: #{signed_token.count('.')} dots (header.payload.signature)"

# Show token structure
token_parts = signed_token.split('.')
puts "  Header length: #{token_parts[0].length} characters"
puts "  Payload length: #{token_parts[1].length} characters"
puts "  Signature length: #{token_parts[2].length} characters"

# Example 3: PASSporT Token Parsing
puts "\n3. PASSPORT TOKEN PARSING"
puts "-" * 40

# Parse the signed token (without signature verification)
parsed_passport = StirShaken::Passport.parse(signed_token, verify_signature: false)

puts "✓ PASSporT token parsed successfully:"
puts "  Originating: #{parsed_passport.originating_number}"
puts "  Destinations: #{parsed_passport.destination_numbers.join(', ')}"
puts "  Attestation: #{parsed_passport.attestation}"
puts "  Origination ID: #{parsed_passport.origination_id}"
puts "  Issued At: #{Time.at(parsed_passport.issued_at)}"
puts "  Certificate URL: #{parsed_passport.certificate_url}"

# Example 4: PASSporT Header Inspection
puts "\n4. PASSPORT HEADER INSPECTION"
puts "-" * 40

# Decode and inspect the JWT header
# Add proper padding for Base64 decoding
header_b64 = token_parts[0]
header_b64 += '=' * (4 - header_b64.length % 4) if header_b64.length % 4 != 0
header_json = Base64.urlsafe_decode64(header_b64)
header_data = JSON.parse(header_json)

puts "✓ PASSporT JWT Header:"
header_data.each do |key, value|
  puts "  #{key}: #{value}"
end

# Verify header compliance
expected_header = {
  'alg' => 'ES256',
  'typ' => 'passport',
  'ppt' => 'shaken',
  'x5u' => 'https://certs.example.com/test.pem'
}

puts "\n✓ Header compliance check:"
expected_header.each do |key, expected_value|
  actual_value = header_data[key]
  status = actual_value == expected_value ? "✓ PASS" : "✗ FAIL"
  puts "  #{key}: #{actual_value} #{status}"
end

# Example 5: PASSporT Payload Inspection
puts "\n5. PASSPORT PAYLOAD INSPECTION"
puts "-" * 40

# Decode and inspect the JWT payload
# Add proper padding for Base64 decoding
payload_b64 = token_parts[1]
payload_b64 += '=' * (4 - payload_b64.length % 4) if payload_b64.length % 4 != 0
payload_json = Base64.urlsafe_decode64(payload_b64)
payload_data = JSON.parse(payload_json)

puts "✓ PASSporT JWT Payload:"
payload_data.each do |key, value|
  formatted_value = case key
  when 'iat'
    "#{value} (#{Time.at(value)})"
  when 'dest'
    value.is_a?(Hash) ? value['tn'].join(', ') : value
  when 'orig'
    value.is_a?(Hash) ? value['tn'] : value
  else
    value
  end
  puts "  #{key}: #{formatted_value}"
end

# Example 6: Multiple Destination Numbers
puts "\n6. MULTIPLE DESTINATION NUMBERS"
puts "-" * 40

# Create PASSporT with multiple destinations
multi_dest_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543', '+15551111111', '+15552222222', '+18005551234'],
  attestation: 'A',
  origination_id: 'multi-dest-001',
  certificate_url: 'https://certs.example.com/test.pem',
  private_key: private_key
)

multi_dest_passport = StirShaken::Passport.parse(multi_dest_token, verify_signature: false)

puts "✓ Multi-destination PASSporT created:"
puts "  Originating: #{multi_dest_passport.originating_number}"
puts "  Destinations: #{multi_dest_passport.destination_numbers.length} numbers"
puts "  Numbers: #{multi_dest_passport.destination_numbers.join(', ')}"

# Parse and verify multiple destinations
parsed_multi = StirShaken::Passport.parse(multi_dest_token, verify_signature: false)
puts "  Parsed destinations: #{parsed_multi.destination_numbers.join(', ')}"

# Example 7: All Attestation Levels
puts "\n7. ALL ATTESTATION LEVELS"
puts "-" * 40

attestation_levels = [
  { level: 'A', name: 'Full Attestation', confidence: 100 },
  { level: 'B', name: 'Partial Attestation', confidence: 75 },
  { level: 'C', name: 'Gateway Attestation', confidence: 50 }
]

attestation_tokens = {}

attestation_levels.each do |att|
  token = StirShaken::Passport.create(
    originating_number: '+15551234567',
    destination_numbers: ['+15559876543'],
    attestation: att[:level],
    origination_id: "attestation-#{att[:level]}-001",
    certificate_url: 'https://certs.example.com/test.pem',
    private_key: private_key
  )
  
  attestation_tokens[att[:level]] = token
  
  puts "✓ #{att[:name]} (#{att[:level]}) PASSporT:"
  puts "  Confidence: #{att[:confidence]}%"
  puts "  Description: #{StirShaken::Attestation.description(att[:level])}"
  puts "  Token length: #{token.length} characters"
end

# Example 8: Custom Origination IDs
puts "\n8. CUSTOM ORIGINATION IDS"
puts "-" * 40

origination_id_examples = [
  { id: SecureRandom.uuid, type: 'UUID' },
  { id: "call-#{Time.now.to_i}-#{rand(1000)}", type: 'Timestamp-based' },
  { id: "session-#{SecureRandom.hex(8)}", type: 'Session-based' },
  { id: "trunk-001-call-#{rand(10000)}", type: 'Trunk-based' },
  { id: "emergency-#{Time.now.strftime('%Y%m%d%H%M%S')}", type: 'Emergency call' }
]

origination_id_examples.each do |example|
  token = StirShaken::Passport.create(
    originating_number: '+15551234567',
    destination_numbers: ['+15559876543'],
    attestation: 'A',
    origination_id: example[:id],
    certificate_url: 'https://certs.example.com/test.pem',
    private_key: private_key
  )
  
  puts "✓ #{example[:type]} Origination ID:"
  puts "  ID: #{example[:id]}"
  puts "  Length: #{example[:id].length} characters"
end

# Example 9: PASSporT Validation
puts "\n9. PASSPORT VALIDATION"
puts "-" * 40

# Test various validation scenarios
validation_tests = [
  {
    name: "Valid PASSporT",
    test: -> {
      token = StirShaken::Passport.create(
        originating_number: '+15551234567',
        destination_numbers: ['+15559876543'],
        attestation: 'A',
        origination_id: 'validation-test-001',
        certificate_url: 'https://certs.example.com/test.pem',
        private_key: private_key
      )
      passport = StirShaken::Passport.parse(token, verify_signature: false)
      passport.validate!
    },
    should_pass: true
  },
  {
    name: "Invalid originating number",
    test: -> {
      StirShaken::Passport.create(
        originating_number: 'invalid-number',
        destination_numbers: ['+15559876543'],
        attestation: 'A',
        origination_id: 'invalid-orig-001',
        certificate_url: 'https://certs.example.com/test.pem',
        private_key: private_key
      )
    },
    should_pass: false
  },
  {
    name: "Invalid destination number",
    test: -> {
      StirShaken::Passport.create(
        originating_number: '+15551234567',
        destination_numbers: ['invalid-dest'],
        attestation: 'A',
        origination_id: 'invalid-dest-001',
        certificate_url: 'https://certs.example.com/test.pem',
        private_key: private_key
      )
    },
    should_pass: false
  },
  {
    name: "Invalid attestation",
    test: -> {
      StirShaken::Passport.create(
        originating_number: '+15551234567',
        destination_numbers: ['+15559876543'],
        attestation: 'X',
        origination_id: 'invalid-att-001',
        certificate_url: 'https://certs.example.com/test.pem',
        private_key: private_key
      )
    },
    should_pass: false
  }
]

validation_tests.each do |test|
  begin
    test[:test].call
    result = test[:should_pass] ? "✓ PASS (expected)" : "✗ FAIL (should have failed)"
    puts "  #{test[:name]}: #{result}"
  rescue => e
    result = test[:should_pass] ? "✗ FAIL (unexpected)" : "✓ PASS (expected failure)"
    puts "  #{test[:name]}: #{result}"
    puts "    Error: #{e.message}"
  end
end

# Example 10: PASSporT Age and Expiration
puts "\n10. PASSPORT AGE AND EXPIRATION"
puts "-" * 40

# Create PASSporT token
current_time = Time.now.to_i
age_test_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A',
  origination_id: 'age-test-001',
  certificate_url: 'https://certs.example.com/test.pem',
  private_key: private_key
)

past_passport = StirShaken::Passport.parse(age_test_token, verify_signature: false)

puts "✓ PASSporT age testing:"
puts "  Current time: #{Time.at(current_time)}"
puts "  PASSporT issued: #{Time.at(past_passport.issued_at)}"
puts "  Age: #{current_time - past_passport.issued_at} seconds"

# Test age validation
age_limits = [60, 300, 600, 3600] # 1 min, 5 min, 10 min, 1 hour

age_limits.each do |max_age|
  age = current_time - past_passport.issued_at
  valid = age <= max_age
  status = valid ? "✓ VALID" : "✗ EXPIRED"
  puts "  Max age #{max_age}s: #{status} (actual age: #{age}s)"
end

# Example 11: PASSporT JSON Representation
puts "\n11. PASSPORT JSON REPRESENTATION"
puts "-" * 40

# Create PASSporT and show JSON representation
json_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543', '+15551111111'],
  attestation: 'A',
  origination_id: 'json-example-001',
  certificate_url: 'https://certs.example.com/test.pem',
  private_key: private_key
)

json_passport = StirShaken::Passport.parse(json_token, verify_signature: false)

json_representation = json_passport.to_h.to_json
puts "✓ PASSporT JSON representation:"
puts JSON.pretty_generate(JSON.parse(json_representation))

# Show payload that would be in JWT
payload = json_passport.payload
puts "\n✓ JWT payload (claims):"
puts JSON.pretty_generate(payload)

# Example 12: PASSporT Comparison and Equality
puts "\n12. PASSPORT COMPARISON AND EQUALITY"
puts "-" * 40

# Create identical PASSporTs with fixed timestamp
fixed_timestamp = 1640995200

# We can't directly set the timestamp, so we'll create tokens and compare their structure
passport1_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A',
  origination_id: 'comparison-001',
  certificate_url: 'https://certs.example.com/test.pem',
  private_key: private_key
)

passport2_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A',
  origination_id: 'comparison-001',
  certificate_url: 'https://certs.example.com/test.pem',
  private_key: private_key
)

# Create different PASSporT
passport3_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'B', # Different attestation
  origination_id: 'comparison-001',
  certificate_url: 'https://certs.example.com/test.pem',
  private_key: private_key
)

passport1 = StirShaken::Passport.parse(passport1_token, verify_signature: false)
passport2 = StirShaken::Passport.parse(passport2_token, verify_signature: false)
passport3 = StirShaken::Passport.parse(passport3_token, verify_signature: false)

puts "✓ PASSporT comparison:"
puts "  Passport1 origination_id == Passport2 origination_id: #{passport1.origination_id == passport2.origination_id}"
puts "  Passport1 attestation == Passport3 attestation: #{passport1.attestation == passport3.attestation}"
puts "  Difference: Attestation (#{passport1.attestation} vs #{passport3.attestation})"

# Example 13: PASSporT Signature Verification
puts "\n13. PASSPORT SIGNATURE VERIFICATION"
puts "-" * 40

# Create and sign a PASSporT
verification_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A',
  origination_id: 'signature-verification-001',
  certificate_url: 'https://certs.example.com/test.pem',
  private_key: private_key
)

puts "✓ PASSporT signature verification:"
puts "  Token created and signed"

# Verify signature with correct public key
begin
  verified_passport = StirShaken::Passport.parse(
    verification_token,
    verify_signature: true,
    public_key: public_key
  )
  puts "  ✓ Signature verification: VALID"
  puts "    Originating: #{verified_passport.originating_number}"
  puts "    Attestation: #{verified_passport.attestation}"
rescue => e
  puts "  ✗ Signature verification: FAILED"
  puts "    Error: #{e.message}"
end

# Try to verify with wrong public key
wrong_key_pair = StirShaken::AuthenticationService.generate_key_pair
wrong_public_key = wrong_key_pair[:public_key]

begin
  StirShaken::Passport.parse(
    verification_token,
    verify_signature: true,
    public_key: wrong_public_key
  )
  puts "  ✗ Wrong key verification: UNEXPECTEDLY VALID"
rescue => e
  puts "  ✓ Wrong key verification: CORRECTLY FAILED"
  puts "    Error: #{e.message}"
end

# Example 14: PASSporT Performance Testing
puts "\n14. PASSPORT PERFORMANCE TESTING"
puts "-" * 40

# Performance test: PASSporT creation
creation_iterations = 100
start_time = Time.now

creation_iterations.times do |i|
  StirShaken::Passport.create(
    originating_number: '+15551234567',
    destination_numbers: ['+15559876543'],
    attestation: 'A',
    origination_id: "perf-test-#{i}",
    certificate_url: 'https://certs.example.com/test.pem',
    private_key: private_key
  )
end

creation_time = Time.now - start_time
avg_creation_time = (creation_time / creation_iterations * 1000).round(2)

puts "✓ PASSporT creation performance:"
puts "  Iterations: #{creation_iterations}"
puts "  Total time: #{creation_time.round(3)} seconds"
puts "  Average time: #{avg_creation_time} ms per PASSporT"

# Performance test: PASSporT parsing
parsing_iterations = 1000
test_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A',
  origination_id: 'parsing-perf-test',
  certificate_url: 'https://certs.example.com/test.pem',
  private_key: private_key
)

start_time = Time.now

parsing_iterations.times do
  StirShaken::Passport.parse(test_token, verify_signature: false)
end

parsing_time = Time.now - start_time
avg_parsing_time = (parsing_time / parsing_iterations * 1000).round(2)

puts "\n✓ PASSporT parsing performance:"
puts "  Iterations: #{parsing_iterations}"
puts "  Total time: #{parsing_time.round(3)} seconds"
puts "  Average time: #{avg_parsing_time} ms per parse"

# Example 15: Advanced PASSporT Scenarios
puts "\n15. ADVANCED PASSPORT SCENARIOS"
puts "-" * 40

# Scenario 1: Emergency call PASSporT
emergency_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+911'],
  attestation: 'A',
  origination_id: "emergency-#{Time.now.strftime('%Y%m%d%H%M%S')}",
  certificate_url: 'https://certs.example.com/test.pem',
  private_key: private_key
)

emergency_passport = StirShaken::Passport.parse(emergency_token, verify_signature: false)

puts "✓ Emergency call PASSporT:"
puts "  Originating: #{emergency_passport.originating_number}"
puts "  Destination: #{emergency_passport.destination_numbers.first}"
puts "  Attestation: #{emergency_passport.attestation} (Full - critical for emergency)"
puts "  Origination ID: #{emergency_passport.origination_id}"

# Scenario 2: International call PASSporT
international_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+442071234567'], # UK number
  attestation: 'B', # Partial attestation for international
  origination_id: 'international-call-001',
  certificate_url: 'https://certs.example.com/test.pem',
  private_key: private_key
)

international_passport = StirShaken::Passport.parse(international_token, verify_signature: false)

puts "\n✓ International call PASSporT:"
puts "  From: US (+1) to UK (+44)"
puts "  Originating: #{international_passport.originating_number}"
puts "  Destination: #{international_passport.destination_numbers.first}"
puts "  Attestation: #{international_passport.attestation} (Partial - appropriate for international)"

# Scenario 3: Conference call PASSporT
conference_destinations = ['+15559876543', '+15551111111', '+15552222222', '+15553333333']
conference_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: conference_destinations,
  attestation: 'A',
  origination_id: "conference-#{SecureRandom.hex(4)}",
  certificate_url: 'https://certs.example.com/test.pem',
  private_key: private_key
)

conference_passport = StirShaken::Passport.parse(conference_token, verify_signature: false)

puts "\n✓ Conference call PASSporT:"
puts "  Originating: #{conference_passport.originating_number}"
puts "  Destinations: #{conference_passport.destination_numbers.length} participants"
puts "  Participants: #{conference_passport.destination_numbers.join(', ')}"
puts "  Attestation: #{conference_passport.attestation} (Full - all participants verified)"

puts "\n" + "=" * 70
puts "PASSporT Token Examples Completed!"
puts ""
puts "This demonstration covered:"
puts "• Basic PASSporT token creation and structure"
puts "• Token signing with cryptographic signatures"
puts "• Token parsing and payload inspection"
puts "• JWT header and payload analysis"
puts "• Multiple destination number handling"
puts "• All attestation levels (A, B, C)"
puts "• Custom origination ID patterns"
puts "• Comprehensive validation testing"
puts "• Token age and expiration checking"
puts "• JSON representation and serialization"
puts "• Token comparison and equality"
puts "• Signature verification with public keys"
puts "• Performance testing and optimization"
puts "• Advanced scenarios (emergency, international, conference)"
puts ""
puts "PASSporT tokens are ready for production use!" 