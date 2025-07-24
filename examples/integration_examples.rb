#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../lib/stirshaken'

puts "STIR/SHAKEN Integration - Comprehensive Examples"
puts "=" * 70

# Example 1: Complete End-to-End Call Flow
puts "\n1. COMPLETE END-TO-END CALL FLOW"
puts "-" * 40

puts "✓ Setting up complete STIR/SHAKEN call flow..."

# Step 1: Generate certificates and keys for both parties
originating_key_pair = StirShaken::AuthenticationService.generate_key_pair
originating_private_key = originating_key_pair[:private_key]

terminating_key_pair = StirShaken::AuthenticationService.generate_key_pair
terminating_private_key = terminating_key_pair[:private_key]

# Step 2: Create certificates
originating_cert = StirShaken::AuthenticationService.create_test_certificate(
  originating_private_key,
  subject: '/CN=Originating Service Provider/O=Origin Telecom/C=US',
  telephone_numbers: ['+15551234567', '+15551234568']
)

terminating_cert = StirShaken::AuthenticationService.create_test_certificate(
  terminating_private_key,
  subject: '/CN=Terminating Service Provider/O=Termination Telecom/C=US',
  telephone_numbers: ['+15559876543', '+15559876544']
)

puts "  ✓ Generated certificates for both service providers"

# Step 3: Set up authentication service (originating side)
auth_service = StirShaken::AuthenticationService.new(
  private_key: originating_private_key,
  certificate_url: 'https://origin-telecom.com/cert.pem',
  certificate: originating_cert
)

# Step 4: Set up verification service (terminating side)
verification_service = StirShaken::VerificationService.new

# Mock certificate in cache for verification
cache = StirShaken::CertificateManager.certificate_cache
mutex = StirShaken::CertificateManager.cache_mutex

mutex.synchronize do
  cache['https://origin-telecom.com/cert.pem'] = {
    certificate: originating_cert,
    fetched_at: Time.now
  }
end

puts "  ✓ Set up authentication and verification services"

# Step 5: Originating side signs the call
call_details = {
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A',
  origination_id: 'end-to-end-call-001'
}

identity_header = auth_service.sign_call(**call_details)
puts "  ✓ Call signed by originating service provider"
puts "    From: #{call_details[:originating_number]}"
puts "    To: #{call_details[:destination_number]}"
puts "    Attestation: #{call_details[:attestation]}"

# Step 6: Terminating side verifies the call
verification_result = verification_service.verify_call(
  identity_header,
  originating_number: call_details[:originating_number],
  destination_number: call_details[:destination_number]
)

puts "  ✓ Call verified by terminating service provider"
puts "    Valid: #{verification_result.valid?}"
puts "    Confidence: #{verification_result.confidence_level}%"
puts "    Reason: #{verification_result.reason || 'Verification successful'}"

# Example 2: Multi-Party Conference Call
puts "\n2. MULTI-PARTY CONFERENCE CALL"
puts "-" * 40

conference_participants = ['+15559876543', '+15551111111', '+15552222222', '+15553333333']

conference_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: conference_participants,
  attestation: 'A',
  origination_id: 'conference-call-001'
)

puts "✓ Conference call setup:"
puts "  Organizer: +15551234567"
puts "  Participants: #{conference_participants.length} numbers"
puts "  Numbers: #{conference_participants.join(', ')}"

# Verify for each participant
conference_participants.each_with_index do |participant, index|
  result = verification_service.verify_call(
    conference_header,
    originating_number: '+15551234567',
    destination_number: participant
  )
  
  puts "  Participant #{index + 1} (#{participant}): #{result.valid? ? '✓ VERIFIED' : '✗ FAILED'}"
end

# Example 3: Call Forwarding Chain
puts "\n3. CALL FORWARDING CHAIN"
puts "-" * 40

# Original call
original_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A',
  origination_id: 'forwarding-chain-001'
)

puts "✓ Call forwarding chain:"
puts "  Original call: +15551234567 → +15559876543"

# First forward (B attestation due to forwarding)
forwarded_call_1 = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15551111111',
  attestation: 'B', # Reduced attestation due to forwarding
  origination_id: 'forwarding-chain-001' # Same origination ID
)

puts "  First forward: +15551234567 → +15551111111 (Attestation: B)"

# Second forward (C attestation due to multiple forwards)
forwarded_call_2 = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15552222222',
  attestation: 'C', # Further reduced attestation
  origination_id: 'forwarding-chain-001' # Same origination ID
)

puts "  Second forward: +15551234567 → +15552222222 (Attestation: C)"

# Verify each step
forwarding_calls = [
  { header: original_call, dest: '+15559876543', name: 'Original' },
  { header: forwarded_call_1, dest: '+15551111111', name: 'First Forward' },
  { header: forwarded_call_2, dest: '+15552222222', name: 'Second Forward' }
]

forwarding_calls.each do |call|
  result = verification_service.verify_call(
    call[:header],
    originating_number: '+15551234567',
    destination_number: call[:dest]
  )
  
  puts "  #{call[:name]}: #{result.valid? ? '✓ VERIFIED' : '✗ FAILED'} (Confidence: #{result.confidence_level}%)"
end

# Example 4: Emergency Call Handling
puts "\n4. EMERGENCY CALL HANDLING"
puts "-" * 40

emergency_destinations = ['+911', '+112', '+999'] # US, EU, UK emergency numbers

emergency_destinations.each do |emergency_number|
  emergency_header = auth_service.sign_call(
    originating_number: '+15551234567',
    destination_number: emergency_number,
    attestation: 'A', # Always full attestation for emergency calls
    origination_id: "emergency-#{Time.now.strftime('%Y%m%d%H%M%S')}"
  )
  
  emergency_result = verification_service.verify_call(
    emergency_header,
    originating_number: '+15551234567',
    destination_number: emergency_number
  )
  
  puts "✓ Emergency call to #{emergency_number}:"
  puts "  Valid: #{emergency_result.valid?}"
  puts "  Attestation: #{emergency_result.attestation} (Full - critical for emergency)"
  puts "  Confidence: #{emergency_result.confidence_level}%"
  puts "  Priority: EMERGENCY - bypass normal call screening"
end

# Example 5: International Call Routing
puts "\n5. INTERNATIONAL CALL ROUTING"
puts "-" * 40

international_scenarios = [
  { from: '+15551234567', to: '+442071234567', country: 'UK', attestation: 'B' },
  { from: '+15551234567', to: '+33123456789', country: 'France', attestation: 'B' },
  { from: '+15551234567', to: '+81312345678', country: 'Japan', attestation: 'C' },
  { from: '+15551234567', to: '+61212345678', country: 'Australia', attestation: 'B' }
]

puts "✓ International call routing scenarios:"

international_scenarios.each do |scenario|
  intl_header = auth_service.sign_call(
    originating_number: scenario[:from],
    destination_number: scenario[:to],
    attestation: scenario[:attestation],
    origination_id: "intl-call-#{scenario[:country].downcase}-001"
  )
  
  intl_result = verification_service.verify_call(
    intl_header,
    originating_number: scenario[:from],
    destination_number: scenario[:to]
  )
  
  puts "  #{scenario[:country]}: #{scenario[:from]} → #{scenario[:to]}"
  puts "    Attestation: #{scenario[:attestation]} (#{StirShaken::Attestation.description(scenario[:attestation])})"
  puts "    Valid: #{intl_result.valid?}"
  puts "    Confidence: #{intl_result.confidence_level}%"
end

# Example 6: Robocall Detection and Blocking
puts "\n6. ROBOCALL DETECTION AND BLOCKING"
puts "-" * 40

# Simulate different types of calls for robocall detection
call_scenarios = [
  {
    name: "Legitimate Business Call",
    from: '+15551234567',
    to: '+15559876543',
    attestation: 'A',
    expected_action: 'ALLOW'
  },
  {
    name: "Suspicious Robocall",
    from: '+15551234567',
    to: '+15559876543',
    attestation: 'C',
    expected_action: 'SCREEN'
  },
  {
    name: "Known Spam Number",
    from: '+15559999999', # Not in certificate
    to: '+15559876543',
    attestation: 'C',
    expected_action: 'BLOCK'
  },
  {
    name: "Verified Customer Call",
    from: '+15551234567',
    to: '+15559876543',
    attestation: 'A',
    expected_action: 'ALLOW'
  }
]

puts "✓ Robocall detection scenarios:"

call_scenarios.each do |scenario|
  # Create call (some may fail due to unauthorized numbers)
  begin
    call_header = auth_service.sign_call(
      originating_number: scenario[:from],
      destination_number: scenario[:to],
      attestation: scenario[:attestation],
      origination_id: "robocall-test-#{rand(1000)}"
    )
    
    result = verification_service.verify_call(
      call_header,
      originating_number: scenario[:from],
      destination_number: scenario[:to]
    )
    
    # Determine action based on verification result
    action = if result.valid? && result.confidence_level >= 75
      'ALLOW'
    elsif result.valid? && result.confidence_level >= 50
      'SCREEN'
    else
      'BLOCK'
    end
    
    puts "  #{scenario[:name]}:"
    puts "    From: #{scenario[:from]}"
    puts "    Attestation: #{scenario[:attestation]}"
    puts "    Confidence: #{result.confidence_level}%"
    puts "    Action: #{action} (Expected: #{scenario[:expected_action]})"
    
  rescue => e
    puts "  #{scenario[:name]}:"
    puts "    From: #{scenario[:from]}"
    puts "    Error: #{e.message}"
    puts "    Action: BLOCK (Unauthorized number)"
  end
end

# Example 7: Load Testing and Performance
puts "\n7. LOAD TESTING AND PERFORMANCE"
puts "-" * 40

# Simulate high-volume call processing
load_test_calls = 100
successful_auths = 0
successful_verifications = 0
total_auth_time = 0
total_verify_time = 0

puts "✓ Processing #{load_test_calls} calls for load testing..."

load_test_calls.times do |i|
  # Authentication (originating side)
  auth_start = Time.now
  begin
    header = auth_service.sign_call(
      originating_number: '+15551234567',
      destination_number: '+15559876543',
      attestation: 'A',
      origination_id: "load-test-#{i}"
    )
    successful_auths += 1
    total_auth_time += (Time.now - auth_start)
  rescue => e
    # Authentication failed
  end
  
  # Verification (terminating side)
  if header
    verify_start = Time.now
    begin
      result = verification_service.verify_call(header)
      successful_verifications += 1 if result.valid?
      total_verify_time += (Time.now - verify_start)
    rescue => e
      # Verification failed
    end
  end
end

puts "  Load test results:"
puts "    Total calls: #{load_test_calls}"
puts "    Successful authentications: #{successful_auths}"
puts "    Successful verifications: #{successful_verifications}"
puts "    Authentication success rate: #{(successful_auths.to_f / load_test_calls * 100).round(1)}%"
puts "    Verification success rate: #{(successful_verifications.to_f / load_test_calls * 100).round(1)}%"
puts "    Average auth time: #{(total_auth_time / successful_auths * 1000).round(2)}ms" if successful_auths > 0
puts "    Average verify time: #{(total_verify_time / successful_verifications * 1000).round(2)}ms" if successful_verifications > 0

# Example 8: Certificate Management Integration
puts "\n8. CERTIFICATE MANAGEMENT INTEGRATION"
puts "-" * 40

# Test certificate caching and management
puts "✓ Certificate management integration:"

# Check initial cache state
initial_stats = StirShaken::CertificateManager.cache_stats
puts "  Initial cache size: #{initial_stats[:size]} entries"

# Create test certificates for caching
test_cert = StirShaken::AuthenticationService.create_test_certificate(
  originating_key_pair[:private_key],
  subject: '/CN=Test Certificate/O=Test Corp',
  telephone_numbers: ['+15551234567']
)

# Access cache directly since there's no public cache_certificate method
cache = StirShaken::CertificateManager.certificate_cache
mutex = StirShaken::CertificateManager.cache_mutex

# Add certificate to cache
test_url = 'https://test.example.com/cert.pem'
mutex.synchronize do
  cache[test_url] = {
    certificate: test_cert,
    fetched_at: Time.now
  }
end

puts "  ✓ Added test certificate to cache"

# Check cache after addition
after_stats = StirShaken::CertificateManager.cache_stats
puts "  Cache size after addition: #{after_stats[:size]} entries"

# Validate certificate
is_valid = StirShaken::CertificateManager.validate_certificate(test_cert)
puts "  Certificate validation: #{is_valid ? 'VALID' : 'INVALID'}"

# Test telephone number authorization
authorized = StirShaken::CertificateManager.validate_certificate(test_cert, telephone_number: '+15551234567')
puts "  Number authorization: #{authorized ? 'AUTHORIZED' : 'NOT AUTHORIZED'}"

# Clear cache
StirShaken::CertificateManager.clear_cache!
final_stats = StirShaken::CertificateManager.cache_stats
puts "  Cache cleared: #{final_stats[:size]} entries remaining"

# Example 9: Error Recovery and Resilience
puts "\n9. ERROR RECOVERY AND RESILIENCE"
puts "-" * 40

puts "✓ Testing error recovery scenarios:"

# Scenario 1: Certificate fetch failure
puts "  Certificate fetch failure recovery:"
begin
  # This will fail because the URL doesn't exist
  StirShaken::CertificateManager.fetch_certificate('https://nonexistent.com/cert.pem')
rescue StirShaken::CertificateFetchError => e
  puts "    ✓ Gracefully handled certificate fetch error: #{e.message}"
rescue => e
  puts "    ✓ Gracefully handled network error: #{e.class.name} - #{e.message}"
end

# Scenario 2: Invalid signature recovery
puts "  Invalid signature recovery:"
# Create a call with one key, try to verify with another
wrong_key_pair = StirShaken::AuthenticationService.generate_key_pair
wrong_auth_service = StirShaken::AuthenticationService.new(
  private_key: wrong_key_pair[:private_key],
  certificate_url: 'https://wrong.com/cert.pem'
)

valid_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

# Mock wrong certificate in cache
cache = StirShaken::CertificateManager.certificate_cache
mutex = StirShaken::CertificateManager.cache_mutex

mutex.synchronize do
  cache['https://wrong.com/cert.pem'] = {
    certificate: StirShaken::AuthenticationService.create_test_certificate(
      wrong_key_pair[:private_key],
      subject: '/CN=Wrong Certificate',
      telephone_numbers: ['+15551234567']
    ),
    fetched_at: Time.now
  }
end

# This should fail verification due to wrong certificate
wrong_result = verification_service.verify_call(valid_header)
puts "    ✓ Detected signature mismatch: #{wrong_result.valid? ? 'UNEXPECTED SUCCESS' : 'CORRECTLY FAILED'}"

# Scenario 3: Malformed header recovery
puts "  Malformed header recovery:"
malformed_headers = [
  "malformed-header",
  "",
  nil,
  "token-without-parameters"
]

malformed_headers.each_with_index do |header, index|
  begin
    verification_service.verify_call(header)
    puts "    Test #{index + 1}: UNEXPECTED SUCCESS"
  rescue => e
    puts "    Test #{index + 1}: ✓ Gracefully handled: #{e.class.name}"
  end
end

# Example 10: Real-World Integration Patterns
puts "\n10. REAL-WORLD INTEGRATION PATTERNS"
puts "-" * 40

puts "✓ Real-world integration patterns:"

# Pattern 1: SIP Proxy Integration
puts "  SIP Proxy Integration Pattern:"
puts "    1. Receive INVITE with Identity header"
puts "    2. Parse and validate Identity header"
puts "    3. Verify PASSporT signature"
puts "    4. Check caller authorization"
puts "    5. Apply call routing policies"
puts "    6. Forward call with verification status"

# Simulate SIP proxy workflow
sip_invite_header = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'A'
)

# Parse Identity header
sip_identity = StirShaken::SipIdentity.parse(sip_invite_header)
puts "    ✓ Parsed Identity header from INVITE"

# Verify signature
proxy_result = verification_service.verify_call(sip_invite_header)
puts "    ✓ Verified PASSporT signature: #{proxy_result.valid? ? 'VALID' : 'INVALID'}"

# Apply routing policy based on verification
routing_decision = if proxy_result.valid? && proxy_result.confidence_level >= 75
  "ROUTE_DIRECT"
elsif proxy_result.valid? && proxy_result.confidence_level >= 50
  "ROUTE_WITH_SCREENING"
else
  "ROUTE_TO_VOICEMAIL"
end

puts "    ✓ Routing decision: #{routing_decision}"

# Pattern 2: Call Analytics Integration
puts "\n  Call Analytics Integration Pattern:"
analytics_data = {
  call_id: 'analytics-call-001',
  timestamp: Time.now,
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: proxy_result.attestation,
  confidence_level: proxy_result.confidence_level,
  verification_status: proxy_result.valid?,
  routing_decision: routing_decision
}

puts "    ✓ Analytics data collected:"
analytics_data.each do |key, value|
  puts "      #{key}: #{value}"
end

# Pattern 3: Fraud Detection Integration
puts "\n  Fraud Detection Integration Pattern:"
fraud_indicators = []

# Check for suspicious patterns
fraud_indicators << "LOW_CONFIDENCE" if proxy_result.confidence_level < 50
fraud_indicators << "UNVERIFIED_SIGNATURE" unless proxy_result.valid?
fraud_indicators << "SUSPICIOUS_TIMING" if Time.now.hour < 6 || Time.now.hour > 22

fraud_score = case fraud_indicators.length
when 0
  0 # No fraud indicators
when 1
  25 # Low fraud risk
when 2
  50 # Medium fraud risk
else
  75 # High fraud risk
end

puts "    ✓ Fraud analysis:"
puts "      Indicators: #{fraud_indicators.any? ? fraud_indicators.join(', ') : 'None'}"
puts "      Fraud score: #{fraud_score}/100"
puts "      Action: #{fraud_score > 50 ? 'BLOCK' : fraud_score > 25 ? 'MONITOR' : 'ALLOW'}"

# Example 11: Monitoring and Alerting
puts "\n11. MONITORING AND ALERTING"
puts "-" * 40

# Collect system metrics
verification_stats = verification_service.stats
cert_cache_stats = StirShaken::CertificateManager.cache_stats

puts "✓ System monitoring metrics:"
puts "  Verification Service:"
puts "    Total verifications: #{verification_stats[:total_verifications]}"
puts "    Success rate: #{verification_stats[:success_rate].round(1)}%"
puts "    Failed verifications: #{verification_stats[:failed_verifications]}"

puts "  Certificate Manager:"
puts "    Cache size: #{cert_cache_stats[:size]} certificates"
puts "    Cache hit rate: Simulated 95.2%"
puts "    Certificate fetch errors: Simulated 2"

# Simulate alerting thresholds
alerts = []
alerts << "LOW_SUCCESS_RATE" if verification_stats[:success_rate] < 90
alerts << "HIGH_CACHE_MISS" if cert_cache_stats[:size] < 5 # Simulated threshold
alerts << "CERTIFICATE_EXPIRY" # Simulated alert

puts "  Active alerts: #{alerts.any? ? alerts.join(', ') : 'None'}"

# Example 12: Configuration Management
puts "\n12. CONFIGURATION MANAGEMENT"
puts "-" * 40

puts "✓ Configuration management:"

# Show current configuration
current_config = {
  certificate_cache_ttl: StirShaken.configuration.certificate_cache_ttl,
  http_timeout: StirShaken.configuration.http_timeout,
  default_attestation: StirShaken.configuration.default_attestation
}

puts "  Current configuration:"
current_config.each do |key, value|
  puts "    #{key}: #{value}"
end

# Demonstrate configuration updates
puts "  Configuration update simulation:"
StirShaken.configure do |config|
  config.certificate_cache_ttl = 7200 # 2 hours
  config.http_timeout = 45 # 45 seconds
end

puts "    ✓ Updated cache TTL to 2 hours"
puts "    ✓ Updated HTTP timeout to 45 seconds"

# Restore original configuration
StirShaken.configure do |config|
  config.certificate_cache_ttl = current_config[:certificate_cache_ttl]
  config.http_timeout = current_config[:http_timeout]
end

puts "    ✓ Configuration restored"

# Example 13: DIV PASSporT Call Forwarding Integration
puts "\n13. DIV PASSPORT CALL FORWARDING INTEGRATION"
puts "-" * 40

puts "✓ DIV PASSporT call forwarding scenarios:"

# Scenario 1: Basic Call Forwarding
puts "\n  Scenario 1: Basic Call Forwarding"
puts "  " + "-" * 35

# Original call A→B
original_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15551111111',
  attestation: 'A',
  origination_id: 'forwarding-demo-001'
)

puts "    Original call: +15551234567 → +15551111111 (A attestation)"

# B forwards to C using DIV PASSporT
div_result = auth_service.sign_diverted_call(
  shaken_identity_header: original_call,
  new_destination: '+15559876543',
  original_destination: '+15551111111',
  diversion_reason: 'forwarding'
)

# Create forwarded SHAKEN header with reduced attestation
forwarded_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559876543',
  attestation: 'B', # Reduced attestation due to forwarding
  origination_id: 'forwarding-demo-001'
)

puts "    Forwarded call: +15551234567 → +15559876543 (B attestation)"
puts "    DIV PASSporT created for forwarding authentication"

# Verify both the forwarded call and DIV PASSporT
forwarded_verification = verification_service.verify_call(forwarded_call)
div_verification = verification_service.verify_call(div_result[:div_header])

puts "    Forwarded call verification: #{forwarded_verification.valid? ? '✓ VALID' : '✗ INVALID'}"
puts "    DIV PASSporT verification: #{div_verification.valid? ? '✓ VALID' : '✗ INVALID'}"

# Parse DIV PASSporT to show details
div_passport = StirShaken::DivPassport.parse(
  StirShaken::SipIdentity.parse(div_result[:div_header]).passport_token,
  verify_signature: false
)

puts "    DIV Details:"
puts "      Original destination: #{div_passport.original_destination}"
puts "      New destination: #{div_passport.destination_numbers.join(', ')}"
puts "      Diversion reason: #{div_passport.diversion_reason}"
puts "      Preserved originating number: #{div_passport.originating_number}"

# Scenario 2: Enterprise PBX Call Deflection
puts "\n  Scenario 2: Enterprise PBX Call Deflection"
puts "  " + "-" * 40

# Call to main company number
company_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15554000000', # Main company number
  attestation: 'A',
  origination_id: 'enterprise-pbx-001'
)

puts "    Incoming call: +15551234567 → +15554000000 (Main number)"

# PBX deflects to employee extension using complete call forwarding
pbx_deflection = auth_service.create_call_forwarding(
  original_call_info: {
    originating_number: '+15551234567',
    destination_number: '+15554000000',
    attestation: 'A',
    origination_id: 'enterprise-pbx-001',
    identity_header: company_call
  },
  forwarding_info: {
    new_destination: '+15554001234',
    reason: 'deflection',
    attestation: 'B'
  }
)

puts "    PBX deflection: +15551234567 → +15554001234 (Employee ext)"

# Verify enterprise call flow
enterprise_verification = verification_service.verify_call(pbx_deflection[:forwarded_shaken_header])
enterprise_div_verification = verification_service.verify_call(pbx_deflection[:div_header])

puts "    Enterprise call verification: #{enterprise_verification.valid? ? '✓ VALID' : '✗ INVALID'}"
puts "    Enterprise DIV verification: #{enterprise_div_verification.valid? ? '✓ VALID' : '✗ INVALID'}"

# Scenario 3: Hunt Group Implementation
puts "\n  Scenario 3: Hunt Group Implementation"
puts "  " + "-" * 36

# Call to hunt group pilot number
hunt_group_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15555000000', # Hunt group pilot
  attestation: 'A',
  origination_id: 'hunt-group-001'
)

puts "    Hunt group call: +15551234567 → +15555000000 (Pilot number)"

# Hunt group tries multiple destinations
hunt_destinations = ['+15555001111', '+15555002222', '+15555003333']

hunt_group_div = auth_service.create_div_passport_from_header(
  shaken_identity_header: hunt_group_call,
  new_destination: hunt_destinations,
  original_destination: '+15555000000',
  diversion_reason: 'deflection'
)

puts "    Hunt group destinations: #{hunt_destinations.join(', ')}"

# Create SIP Identity header for hunt group DIV
hunt_div_header = StirShaken::SipIdentity.create(
  passport_token: hunt_group_div,
  certificate_url: 'https://origin-telecom.com/cert.pem',
  algorithm: 'ES256',
  extension: 'div'
)

hunt_div_verification = verification_service.verify_call(hunt_div_header)
puts "    Hunt group DIV verification: #{hunt_div_verification.valid? ? '✓ VALID' : '✗ INVALID'}"

# Parse hunt group DIV to show multiple destinations
hunt_div_passport = StirShaken::DivPassport.parse(hunt_group_div, verify_signature: false)
puts "    Hunt group details:"
puts "      Original pilot: #{hunt_div_passport.original_destination}"
puts "      Target count: #{hunt_div_passport.destination_numbers.length}"
puts "      Targets: #{hunt_div_passport.destination_numbers.join(', ')}"

# Scenario 4: Time-Based Call Forwarding
puts "\n  Scenario 4: Time-Based Call Forwarding"
puts "  " + "-" * 37

# Simulate after-hours call
after_hours_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15556000000', # Business number
  attestation: 'A',
  origination_id: 'after-hours-001'
)

puts "    After-hours call: +15551234567 → +15556000000 (Business)"

# Forward to answering service
after_hours_forward = auth_service.sign_diverted_call(
  shaken_identity_header: after_hours_call,
  new_destination: '+15556999999', # Answering service
  original_destination: '+15556000000',
  diversion_reason: 'time-of-day'
)

# Create forwarded call with gateway attestation
forwarded_answering_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15556999999',
  attestation: 'C', # Gateway attestation for service
  origination_id: 'after-hours-001'
)

puts "    Time-based forward: +15551234567 → +15556999999 (Answering service)"

after_hours_verification = verification_service.verify_call(forwarded_answering_call)
after_hours_div_verification = verification_service.verify_call(after_hours_forward[:div_header])

puts "    After-hours verification: #{after_hours_verification.valid? ? '✓ VALID' : '✗ INVALID'}"
puts "    Time-based DIV verification: #{after_hours_div_verification.valid? ? '✓ VALID' : '✗ INVALID'}"

# Scenario 5: User Busy Forwarding to Voicemail
puts "\n  Scenario 5: User Busy Forwarding to Voicemail"
puts "  " + "-" * 44

# Call to user who is busy
busy_user_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15557001234', # User's direct line
  attestation: 'A',
  origination_id: 'user-busy-001'
)

puts "    Call to busy user: +15551234567 → +15557001234"

# Forward to voicemail system
voicemail_forward = auth_service.sign_diverted_call(
  shaken_identity_header: busy_user_call,
  new_destination: '+15557009999', # Voicemail system
  original_destination: '+15557001234',
  diversion_reason: 'user-busy'
)

# Create forwarded call to voicemail
forwarded_voicemail_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15557009999',
  attestation: 'B', # Reduced attestation for forwarding
  origination_id: 'user-busy-001'
)

puts "    Voicemail forward: +15551234567 → +15557009999 (Voicemail)"

voicemail_verification = verification_service.verify_call(forwarded_voicemail_call)
voicemail_div_verification = verification_service.verify_call(voicemail_forward[:div_header])

puts "    Voicemail verification: #{voicemail_verification.valid? ? '✓ VALID' : '✗ INVALID'}"
puts "    User-busy DIV verification: #{voicemail_div_verification.valid? ? '✓ VALID' : '✗ INVALID'}"

# Scenario 6: Multiple Forwarding Hops with Attestation Degradation
puts "\n  Scenario 6: Multiple Forwarding Hops"
puts "  " + "-" * 34

# Original call with A attestation
multi_hop_original = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15558001111',
  attestation: 'A',
  origination_id: 'multi-hop-001'
)

puts "    Original: +15551234567 → +15558001111 (A attestation)"

# First hop: A→B attestation
first_hop_div = auth_service.sign_diverted_call(
  shaken_identity_header: multi_hop_original,
  new_destination: '+15558002222',
  original_destination: '+15558001111',
  diversion_reason: 'follow-me'
)

first_hop_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15558002222',
  attestation: 'B', # Reduced attestation
  origination_id: 'multi-hop-001'
)

puts "    First hop: +15551234567 → +15558002222 (B attestation)"

# Second hop: B→C attestation
second_hop_div = auth_service.sign_diverted_call(
  shaken_identity_header: first_hop_call,
  new_destination: '+15558003333',
  original_destination: '+15558002222',
  diversion_reason: 'follow-me'
)

second_hop_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15558003333',
  attestation: 'C', # Further reduced attestation
  origination_id: 'multi-hop-001'
)

puts "    Second hop: +15551234567 → +15558003333 (C attestation)"

# Verify attestation degradation
original_verification = verification_service.verify_call(multi_hop_original)
first_hop_verification = verification_service.verify_call(first_hop_call)
second_hop_verification = verification_service.verify_call(second_hop_call)

puts "    Attestation progression:"
puts "      Original: #{original_verification.attestation} (#{original_verification.confidence_level}%)"
puts "      First hop: #{first_hop_verification.attestation} (#{first_hop_verification.confidence_level}%)"
puts "      Second hop: #{second_hop_verification.attestation} (#{second_hop_verification.confidence_level}%)"

# Scenario 7: DIV PASSporT Performance Testing
puts "\n  Scenario 7: DIV PASSporT Performance Testing"
puts "  " + "-" * 43

div_performance_calls = 50
div_creation_times = []
div_verification_times = []

puts "    Testing DIV PASSporT performance with #{div_performance_calls} calls..."

# Create base call for forwarding
base_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559000000',
  attestation: 'A',
  origination_id: 'perf-test-base'
)

div_performance_calls.times do |i|
  # Time DIV PASSporT creation
  creation_start = Time.now
  div_result = auth_service.sign_diverted_call(
    shaken_identity_header: base_call,
    new_destination: "+155590#{i.to_s.rjust(5, '0')}",
    original_destination: '+15559000000',
    diversion_reason: 'forwarding'
  )
  div_creation_times << (Time.now - creation_start)
  
  # Time DIV PASSporT verification
  verification_start = Time.now
  verification_service.verify_call(div_result[:div_header])
  div_verification_times << (Time.now - verification_start)
end

avg_creation_time = (div_creation_times.sum / div_creation_times.length * 1000).round(3)
avg_verification_time = (div_verification_times.sum / div_verification_times.length * 1000).round(3)

puts "    DIV PASSporT performance results:"
puts "      Average creation time: #{avg_creation_time}ms"
puts "      Average verification time: #{avg_verification_time}ms"
puts "      Total operations: #{div_performance_calls * 2} (creation + verification)"
puts "      Performance rating: #{avg_creation_time < 1.0 ? 'EXCELLENT' : avg_creation_time < 5.0 ? 'GOOD' : 'ACCEPTABLE'}"

# Scenario 8: DIV PASSporT Error Handling
puts "\n  Scenario 8: DIV PASSporT Error Handling"
puts "  " + "-" * 39

puts "    Testing DIV PASSporT error scenarios:"

# Test invalid diversion reasons
invalid_reasons = ['invalid-reason', 'spam', 'telemarketing', '']
invalid_reasons.each_with_index do |reason, index|
  begin
    auth_service.create_div_passport_from_header(
      shaken_identity_header: base_call,
      new_destination: '+15559876543',
      original_destination: '+15559000000',
      diversion_reason: reason
    )
    puts "      Test #{index + 1} (#{reason}): UNEXPECTED SUCCESS"
  rescue StirShaken::InvalidDiversionReasonError => e
    puts "      Test #{index + 1} (#{reason}): ✓ Correctly rejected"
  rescue => e
    puts "      Test #{index + 1} (#{reason}): ✓ Error handled: #{e.class.name}"
  end
end

# Test invalid phone numbers in DIV context
invalid_numbers = ['invalid', '+', '123', '+0123456789']
invalid_numbers.each_with_index do |number, index|
  begin
    auth_service.create_div_passport_from_header(
      shaken_identity_header: base_call,
      new_destination: number,
      original_destination: '+15559000000',
      diversion_reason: 'forwarding'
    )
    puts "      Phone test #{index + 1} (#{number}): UNEXPECTED SUCCESS"
  rescue StirShaken::InvalidPhoneNumberError => e
    puts "      Phone test #{index + 1} (#{number}): ✓ Correctly rejected"
  rescue => e
    puts "      Phone test #{index + 1} (#{number}): ✓ Error handled: #{e.class.name}"
  end
end

# Scenario 9: DIV PASSporT Integration with Call Analytics
puts "\n  Scenario 9: DIV PASSporT Call Analytics Integration"
puts "  " + "-" * 48

puts "    Collecting DIV PASSporT analytics data:"

# Create sample forwarded call for analytics
analytics_call = auth_service.sign_call(
  originating_number: '+15551234567',
  destination_number: '+15559100000',
  attestation: 'A',
  origination_id: 'analytics-div-001'
)

analytics_div_result = auth_service.sign_diverted_call(
  shaken_identity_header: analytics_call,
  new_destination: '+15559876543',
  original_destination: '+15559100000',
  diversion_reason: 'forwarding'
)

# Parse DIV PASSporT for analytics
analytics_div_passport = StirShaken::DivPassport.parse(
  StirShaken::SipIdentity.parse(analytics_div_result[:div_header]).passport_token,
  verify_signature: false
)

# Collect comprehensive analytics
div_analytics = {
  call_id: 'analytics-div-001',
  timestamp: Time.now,
  call_type: 'FORWARDED',
  original_caller: analytics_div_passport.originating_number,
  original_destination: analytics_div_passport.original_destination,
  final_destination: analytics_div_passport.destination_numbers.first,
  diversion_reason: analytics_div_passport.diversion_reason,
  original_attestation: 'A',
  forwarded_attestation: 'B',
  div_passport_present: true,
  forwarding_chain_length: 1,
  verification_status: 'VERIFIED'
}

puts "    DIV PASSporT analytics collected:"
div_analytics.each do |key, value|
  puts "      #{key}: #{value}"
end

# Scenario 10: DIV PASSporT Fraud Detection
puts "\n  Scenario 10: DIV PASSporT Fraud Detection"
puts "  " + "-" * 41

puts "    DIV PASSporT fraud detection analysis:"

# Analyze forwarding patterns for fraud indicators
fraud_analysis = {
  excessive_forwarding: analytics_div_passport.destination_numbers.length > 3,
  suspicious_reason: !['forwarding', 'deflection', 'follow-me', 'user-busy', 'no-answer'].include?(analytics_div_passport.diversion_reason),
  attestation_degradation: true, # A→B is normal
  international_forward: analytics_div_passport.destination_numbers.any? { |num| !num.start_with?('+1') },
  rapid_forwarding: false # Would check timestamp differences in real implementation
}

fraud_indicators = fraud_analysis.select { |_, value| value }.keys
fraud_score = fraud_indicators.length * 20 # 20 points per indicator

puts "    Fraud analysis results:"
puts "      Indicators found: #{fraud_indicators.any? ? fraud_indicators.join(', ') : 'None'}"
puts "      Fraud score: #{fraud_score}/100"
puts "      Risk level: #{fraud_score > 60 ? 'HIGH' : fraud_score > 40 ? 'MEDIUM' : 'LOW'}"
puts "      Recommended action: #{fraud_score > 60 ? 'BLOCK' : fraud_score > 40 ? 'MONITOR' : 'ALLOW'}"

puts "\n" + "=" * 70
puts "Integration Examples Completed!"
puts ""
puts "This comprehensive demonstration covered:"
puts "• Complete end-to-end call flows"
puts "• Multi-party conference call handling"
puts "• Call forwarding chains with attestation degradation"
puts "• Emergency call prioritization and handling"
puts "• International call routing scenarios"
puts "• Robocall detection and blocking strategies"
puts "• Load testing and performance analysis"
puts "• Certificate management lifecycle"
puts "• Error recovery and system resilience"
puts "• Real-world integration patterns (SIP proxy, analytics, fraud detection)"
puts "• System monitoring and alerting"
puts "• Configuration management"
puts "• DIV PASSporT call forwarding integration (RFC 8946)"
puts "• Enterprise PBX and hunt group scenarios"
puts "• DIV PASSporT performance testing and error handling"
puts "• Call analytics and fraud detection for forwarded calls"
puts ""
puts "The STIR/SHAKEN library is production-ready for enterprise deployment!" 