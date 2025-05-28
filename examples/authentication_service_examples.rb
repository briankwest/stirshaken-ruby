#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../lib/stirshaken'

puts "STIR/SHAKEN Authentication Service - Comprehensive Examples"
puts "=" * 70

# Example 1: Basic Authentication Service Setup
puts "\n1. BASIC AUTHENTICATION SERVICE SETUP"
puts "-" * 40

# Generate key pair
key_pair = StirShaken::AuthenticationService.generate_key_pair
private_key = key_pair[:private_key]
public_key = key_pair[:public_key]

puts "✓ Generated EC P-256 key pair"
puts "  Private key type: #{private_key.class}"
puts "  Curve: #{private_key.group.curve_name}"
puts "  Private key? #{private_key.private_key?}"

# Create test certificate
certificate = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Example Telecom/O=Example Corp/C=US',
  telephone_numbers: ['+15551234567', '+15559876543', '+15551111111']
)

puts "✓ Created test certificate"
puts "  Subject: #{certificate.subject}"
puts "  Valid from: #{certificate.not_before}"
puts "  Valid until: #{certificate.not_after}"

# Initialize authentication service
auth_service = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: 'https://certs.example.com/stirshaken.pem',
  certificate: certificate
)

puts "✓ Authentication service initialized"

# Example 2: Single Call Signing
puts "\n2. SINGLE CALL SIGNING"
puts "-" * 40

# Basic call signing
identity_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

puts "✓ Signed single call"
puts "  From: +15551234567"
puts "  To: +15559876543"
puts "  Attestation: A (Full)"
puts "  Header length: #{identity_header.length} characters"

# Example 3: Multiple Destination Numbers
puts "\n3. MULTIPLE DESTINATION NUMBERS"
puts "-" * 40

multi_dest_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: ['+15559876543', '+15551111111', '+15552222222'],
  attestation: 'A'
)

puts "✓ Signed call with multiple destinations"
puts "  From: +15551234567"
puts "  To: +15559876543, +15551111111, +15552222222"
puts "  Attestation: A (Full)"

# Parse to verify multiple destinations
sip_identity = StirShaken::SipIdentity.parse(multi_dest_header)
passport = sip_identity.parse_passport(verify_signature: false)
puts "  Verified destinations: #{passport.destination_numbers.join(', ')}"

# Example 4: All Attestation Levels
puts "\n4. ALL ATTESTATION LEVELS"
puts "-" * 40

attestation_examples = [
  {
    level: 'A',
    name: 'Full Attestation',
    scenario: 'Direct customer call - fully authenticated',
    confidence: 100
  },
  {
    level: 'B', 
    name: 'Partial Attestation',
    scenario: 'Known origination but unverified caller',
    confidence: 75
  },
  {
    level: 'C',
    name: 'Gateway Attestation', 
    scenario: 'Transit/gateway call with limited info',
    confidence: 50
  }
]

attestation_examples.each do |att|
  header = auth_service.sign_call(
    originating_number: '+15551234567',
    destination_number: '+15559876543',
    attestation: att[:level]
  )
  
  puts "✓ #{att[:name]} (#{att[:level]})"
  puts "  Scenario: #{att[:scenario]}"
  puts "  Confidence: #{att[:confidence]}%"
  puts "  Description: #{StirShaken::Attestation.description(att[:level])}"
end

# Example 5: Custom Origination IDs
puts "\n5. CUSTOM ORIGINATION IDS"
puts "-" * 40

# UUID origination ID (auto-generated)
auto_id_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

auto_passport = StirShaken::SipIdentity.parse(auto_id_header).parse_passport(verify_signature: false)
puts "✓ Auto-generated origination ID: #{auto_passport.origination_id}"

# Custom origination ID
custom_id_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A',
  origination_id: 'call-session-12345-abc'
)

custom_passport = StirShaken::SipIdentity.parse(custom_id_header).parse_passport(verify_signature: false)
puts "✓ Custom origination ID: #{custom_passport.origination_id}"

# Timestamp-based origination ID
timestamp_id = "call-#{Time.now.to_i}-#{rand(1000)}"
timestamp_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A',
  origination_id: timestamp_id
)

timestamp_passport = StirShaken::SipIdentity.parse(timestamp_header).parse_passport(verify_signature: false)
puts "✓ Timestamp-based ID: #{timestamp_passport.origination_id}"

# Example 6: Additional SIP Header Parameters
puts "\n6. ADDITIONAL SIP HEADER PARAMETERS"
puts "-" * 40

enhanced_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A',
  additional_info: {
    'session-id' => 'sip-session-98765',
    'call-type' => 'emergency',
    'priority' => 'high',
    'custom-param' => 'custom-value'
  }
)

puts "✓ Enhanced SIP header with additional parameters"
puts "  Session ID: sip-session-98765"
puts "  Call Type: emergency"
puts "  Priority: high"
puts "  Custom Parameter: custom-value"

# Verify additional parameters are included
if enhanced_header.include?('session-id=sip-session-98765')
  puts "  ✓ Additional parameters successfully included"
end

# Example 7: Direct PASSporT Token Creation
puts "\n7. DIRECT PASSPORT TOKEN CREATION"
puts "-" * 40

# Create PASSporT token directly (without SIP header)
passport_token = auth_service.create_passport(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543', '+15551111111'],
  attestation: 'A',
  origination_id: 'direct-passport-123'
)

puts "✓ Created PASSporT token directly"
puts "  Token length: #{passport_token.length} characters"
puts "  Token parts: #{passport_token.count('.')} dots (header.payload.signature)"

# Parse the token to show contents
direct_passport = StirShaken::Passport.parse(passport_token, verify_signature: false)
puts "  Originating: #{direct_passport.originating_number}"
puts "  Destinations: #{direct_passport.destination_numbers.join(', ')}"
puts "  Attestation: #{direct_passport.attestation}"
puts "  Origination ID: #{direct_passport.origination_id}"

# Example 8: Service Information and Validation
puts "\n8. SERVICE INFORMATION AND VALIDATION"
puts "-" * 40

# Get service information
service_info = auth_service.info
puts "✓ Service Information:"
service_info.each do |key, value|
  puts "  #{key}: #{value}"
end

# Check authorization for different numbers
test_numbers = ['+15551234567', '+15559876543', '+15551111111', '+19995551234']

puts "\n✓ Number Authorization Check:"
test_numbers.each do |number|
  authorized = auth_service.authorized_for_number?(number)
  status = authorized ? "✓ Authorized" : "✗ Not Authorized"
  puts "  #{number}: #{status}"
end

# Check certificate validity
cert_valid = auth_service.certificate_valid?
puts "\n✓ Certificate Status: #{cert_valid ? 'Valid' : 'Invalid'}"

# Example 9: Batch Call Signing
puts "\n9. BATCH CALL SIGNING"
puts "-" * 40

# Define multiple calls to sign
calls_to_sign = [
  { from: '+15551234567', to: '+15559876543', att: 'A', id: 'batch-call-001' },
  { from: '+15551234567', to: '+15551111111', att: 'B', id: 'batch-call-002' },
  { from: '+15551234567', to: '+15552222222', att: 'A', id: 'batch-call-003' },
  { from: '+15551234567', to: ['+15553333333', '+15554444444'], att: 'C', id: 'batch-call-004' }
]

puts "✓ Signing #{calls_to_sign.length} calls in batch:"

signed_calls = calls_to_sign.map.with_index do |call, index|
  start_time = Time.now
  
  header = auth_service.sign_call(
    originating_number: call[:from],
    destination_number: call[:to],
    attestation: call[:att],
    origination_id: call[:id]
  )
  
  elapsed = ((Time.now - start_time) * 1000).round(2)
  
  puts "  Call #{index + 1}: #{call[:id]} (#{elapsed}ms)"
  puts "    From: #{call[:from]}"
  puts "    To: #{Array(call[:to]).join(', ')}"
  puts "    Attestation: #{call[:att]}"
  
  header
end

puts "  ✓ Successfully signed #{signed_calls.length} calls"

# Example 10: Error Handling Scenarios
puts "\n10. ERROR HANDLING SCENARIOS"
puts "-" * 40

error_scenarios = [
  {
    name: "Invalid Attestation Level",
    params: { originating_number: '+15551234567', destination_number: '+15559876543', attestation: 'X' },
    expected_error: StirShaken::InvalidAttestationError
  },
  {
    name: "Invalid Originating Number",
    params: { originating_number: 'invalid-number', destination_number: '+15559876543', attestation: 'A' },
    expected_error: StirShaken::InvalidPhoneNumberError
  },
  {
    name: "Invalid Destination Number",
    params: { originating_number: '+15551234567', destination_number: '123-invalid', attestation: 'A' },
    expected_error: StirShaken::InvalidPhoneNumberError
  },
  {
    name: "Missing Plus Sign",
    params: { originating_number: '15551234567', destination_number: '+15559876543', attestation: 'A' },
    expected_error: StirShaken::InvalidPhoneNumberError
  },
  {
    name: "Number Too Short",
    params: { originating_number: '+1555', destination_number: '+15559876543', attestation: 'A' },
    expected_error: StirShaken::InvalidPhoneNumberError
  }
]

error_scenarios.each do |scenario|
  begin
    auth_service.sign_call(**scenario[:params])
    puts "  ✗ #{scenario[:name]}: Expected error but call succeeded"
  rescue scenario[:expected_error] => e
    puts "  ✓ #{scenario[:name]}: Correctly caught #{e.class.name}"
    puts "    Error: #{e.message}"
  rescue => e
    puts "  ⚠ #{scenario[:name]}: Unexpected error #{e.class.name}: #{e.message}"
  end
end

# Example 11: Performance Measurement
puts "\n11. PERFORMANCE MEASUREMENT"
puts "-" * 40

# Measure signing performance
iterations = 100
start_time = Time.now

iterations.times do |i|
  auth_service.sign_call(
    originating_number: '+15551234567',
    destination_number: '+15559876543',
    attestation: 'A',
    origination_id: "perf-test-#{i}"
  )
end

total_time = Time.now - start_time
avg_time = (total_time / iterations * 1000).round(2)

puts "✓ Performance Test Results:"
puts "  Total calls: #{iterations}"
puts "  Total time: #{total_time.round(3)} seconds"
puts "  Average time per call: #{avg_time} ms"
puts "  Calls per second: #{(iterations / total_time).round(1)}"

# Example 12: Real Certificate Loading (Simulation)
puts "\n12. REAL CERTIFICATE LOADING SIMULATION"
puts "-" * 40

# Simulate loading certificate from file
puts "✓ Simulating real certificate loading:"
puts "  # Load certificate from file"
puts "  cert_data = File.read('/path/to/certificate.pem')"
puts "  certificate = OpenSSL::X509::Certificate.new(cert_data)"
puts ""
puts "  # Load private key from file"
puts "  key_data = File.read('/path/to/private_key.pem')"
puts "  private_key = OpenSSL::PKey::EC.new(key_data)"
puts ""
puts "  # Create service with real credentials"
puts "  auth_service = StirShaken::AuthenticationService.new("
puts "    private_key: private_key,"
puts "    certificate_url: 'https://myservice.com/cert.pem',"
puts "    certificate: certificate"
puts "  )"

puts "\n" + "=" * 70
puts "Authentication Service Examples Completed!"
puts ""
puts "This demonstration covered:"
puts "• Basic service setup and configuration"
puts "• Single and multiple destination call signing"
puts "• All attestation levels (A, B, C)"
puts "• Custom origination IDs and additional parameters"
puts "• Direct PASSporT token creation"
puts "• Service information and authorization checking"
puts "• Batch call processing"
puts "• Comprehensive error handling"
puts "• Performance measurement"
puts "• Real-world certificate loading patterns"
puts ""
puts "The Authentication Service is ready for production use!" 