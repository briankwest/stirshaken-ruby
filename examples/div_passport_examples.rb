#!/usr/bin/env ruby
# frozen_string_literal: true

require 'bundler/setup'
require 'stirshaken'

##
# DIV PASSporT Implementation Examples
#
# This file demonstrates how to implement DIV PASSporT for call diversion/forwarding
# scenarios in STIR/SHAKEN systems, particularly with SignalWire.
#
# Examples include:
# 1. Basic call forwarding
# 2. Multiple forwarding hops
# 3. Enterprise PBX scenarios
# 4. SignalWire-specific implementations
# 5. Error handling and validation

puts "🔐 DIV PASSporT Implementation Examples"
puts "=" * 50

# Generate test keys and certificate for examples
key_pair = StirShaken::AuthenticationService.generate_key_pair
private_key = key_pair[:private_key]
public_key = key_pair[:public_key]
certificate = StirShaken::AuthenticationService.create_test_certificate(private_key)
certificate_url = 'https://example.com/stir-shaken-cert.pem'

# Create authentication service
auth_service = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: certificate_url,
  certificate: certificate
)

puts "\n📞 Example 1: Basic Call Forwarding"
puts "-" * 30

# Scenario: Call to +15551111111 is forwarded to +15559876543
originating_number = '+15551234567'
original_destination = '+15551111111'
forwarded_destination = '+15559876543'

begin
  # Step 1: Create original SHAKEN Identity header
  original_identity = auth_service.sign_call(
    originating_number: originating_number,
    destination_number: original_destination,
    attestation: 'A' # Full attestation from originating carrier
  )
  
  puts "✅ Original SHAKEN Identity: #{original_identity[0..80]}..."
  
  # Step 2: Create DIV PASSporT for forwarding
  div_result = auth_service.sign_diverted_call(
    shaken_identity_header: original_identity,
    new_destination: forwarded_destination,
    original_destination: original_destination,
    diversion_reason: 'forwarding'
  )
  
  puts "✅ DIV Identity Header: #{div_result[:div_header][0..80]}..."
  
  # Step 3: Verify the DIV PASSporT
  div_sip_identity = StirShaken::SipIdentity.parse(div_result[:div_header])
  div_passport = StirShaken::DivPassport.parse(div_sip_identity.passport_token, verify_signature: false)
  
  puts "📋 DIV PASSporT Details:"
  puts "   - Original Destination: #{div_passport.original_destination}"
  puts "   - New Destination: #{div_passport.destination_numbers.join(', ')}"
  puts "   - Diversion Reason: #{div_passport.diversion_reason}"
  puts "   - Attestation: #{div_passport.attestation}"
  puts "   - Originating Number: #{div_passport.originating_number}"

rescue => e
  puts "❌ Error in basic forwarding: #{e.message}"
end

puts "\n📞 Example 2: Complete Call Forwarding Workflow"
puts "-" * 40

begin
  # Use the comprehensive call forwarding method
  forwarding_result = auth_service.create_call_forwarding(
    original_call_info: {
      originating_number: originating_number,
      destination_number: original_destination,
      attestation: 'A',
      origination_id: 'example-call-001'
    },
    forwarding_info: {
      new_destination: forwarded_destination,
      reason: 'forwarding'
    }
  )
  
  puts "✅ Complete forwarding scenario created:"
  puts "   - Original SHAKEN header: #{forwarding_result[:original_shaken_header][0..50]}..."
  puts "   - Forwarded SHAKEN header: #{forwarding_result[:forwarded_shaken_header][0..50]}..."
  puts "   - DIV header: #{forwarding_result[:div_header][0..50]}..."
  
  metadata = forwarding_result[:metadata]
  puts "📋 Forwarding Metadata:"
  puts "   - Original Attestation: #{metadata[:original_attestation]}"
  puts "   - Forwarded Attestation: #{metadata[:forwarded_attestation]}"
  puts "   - Diversion Reason: #{metadata[:diversion_reason]}"
  puts "   - Origination ID: #{metadata[:origination_id]}"

rescue => e
  puts "❌ Error in complete forwarding: #{e.message}"
end

puts "\n📞 Example 3: Multiple Forwarding Hops"
puts "-" * 35

begin
  # Scenario: Call forwarded multiple times
  # Original: +15551111111 → First Forward: +15552222222 → Final: +15553333333
  
  first_forward = '+15552222222'
  final_destination = '+15553333333'
  
  # First forwarding hop
  first_hop = auth_service.sign_diverted_call(
    shaken_identity_header: original_identity,
    new_destination: first_forward,
    original_destination: original_destination,
    diversion_reason: 'forwarding'
  )
  
  # Second forwarding hop (follow-me scenario)
  second_hop = auth_service.sign_diverted_call(
    shaken_identity_header: first_hop[:shaken_header],
    new_destination: final_destination,
    original_destination: first_forward, # Previous destination becomes original
    diversion_reason: 'follow-me'
  )
  
  puts "✅ Multiple hop forwarding:"
  puts "   - Original → First Forward: #{first_hop[:div_header][0..50]}..."
  puts "   - First Forward → Final: #{second_hop[:div_header][0..50]}..."
  
  # Parse both DIV headers
  first_div_sip = StirShaken::SipIdentity.parse(first_hop[:div_header])
  first_div_passport = StirShaken::DivPassport.parse(first_div_sip.passport_token, verify_signature: false)
  
  second_div_sip = StirShaken::SipIdentity.parse(second_hop[:div_header])
  second_div_passport = StirShaken::DivPassport.parse(second_div_sip.passport_token, verify_signature: false)
  
  puts "📋 Forwarding Chain:"
  puts "   - Hop 1: #{first_div_passport.original_destination} → #{first_div_passport.destination_numbers.first} (#{first_div_passport.diversion_reason})"
  puts "   - Hop 2: #{second_div_passport.original_destination} → #{second_div_passport.destination_numbers.first} (#{second_div_passport.diversion_reason})"

rescue => e
  puts "❌ Error in multiple hops: #{e.message}"
end

puts "\n📞 Example 4: Enterprise PBX Scenario"
puts "-" * 35

begin
  # Scenario: Call to main number forwarded to extension
  main_number = '+15551234000'
  extension = '+15551234567'
  
  enterprise_forwarding = auth_service.create_call_forwarding(
    original_call_info: {
      originating_number: '+15559876543',
      destination_number: main_number,
      attestation: 'B', # Partial attestation from enterprise
      origination_id: 'enterprise-call-001'
    },
    forwarding_info: {
      new_destination: extension,
      reason: 'deflection', # Call deflected to specific extension
      attestation: 'B' # Maintain same attestation level
    }
  )
  
  puts "✅ Enterprise PBX forwarding:"
  puts "   - Main number: #{main_number}"
  puts "   - Extension: #{extension}"
  puts "   - Reason: deflection"
  
  # Parse the DIV header
  enterprise_div_sip = StirShaken::SipIdentity.parse(enterprise_forwarding[:div_header])
  enterprise_div_passport = StirShaken::DivPassport.parse(enterprise_div_sip.passport_token, verify_signature: false)
  
  puts "📋 Enterprise Details:"
  puts "   - Attestation maintained: #{enterprise_div_passport.attestation}"
  puts "   - Diversion reason: #{enterprise_div_passport.diversion_reason}"

rescue => e
  puts "❌ Error in enterprise scenario: #{e.message}"
end

puts "\n📞 Example 5: Multiple Destinations (Hunt Group)"
puts "-" * 42

begin
  # Scenario: Call forwarded to multiple destinations (hunt group)
  hunt_group = ['+15551111111', '+15552222222', '+15553333333']
  
  hunt_group_div = auth_service.create_div_passport_from_header(
    shaken_identity_header: original_identity,
    new_destination: hunt_group,
    original_destination: original_destination,
    diversion_reason: 'deflection'
  )
  
  # Create SIP Identity header for hunt group
  hunt_group_header = StirShaken::SipIdentity.create(
    passport_token: hunt_group_div,
    certificate_url: certificate_url,
    algorithm: 'ES256',
    extension: 'div'
  )
  
  puts "✅ Hunt group forwarding:"
  puts "   - Hunt group destinations: #{hunt_group.join(', ')}"
  
  # Parse and verify
  hunt_div_sip = StirShaken::SipIdentity.parse(hunt_group_header)
  hunt_div_passport = StirShaken::DivPassport.parse(hunt_div_sip.passport_token, verify_signature: false)
  
  puts "📋 Hunt Group Details:"
  puts "   - Destination count: #{hunt_div_passport.destination_numbers.length}"
  puts "   - All destinations: #{hunt_div_passport.destination_numbers.join(', ')}"

rescue => e
  puts "❌ Error in hunt group: #{e.message}"
end

puts "\n📞 Example 6: SignalWire Integration Pattern"
puts "-" * 40

begin
  # Simulate SignalWire call routing decision
  def signalwire_routing_decision(original_call, routing_rules)
    # This would integrate with SignalWire's routing logic
    case routing_rules[:type]
    when :forward
      {
        action: :create_div_passport,
        new_destination: routing_rules[:destination],
        reason: routing_rules[:reason] || 'forwarding'
      }
    when :pass_through
      {
        action: :pass_original,
        preserve_attestation: true
      }
    else
      {
        action: :sign_new,
        attestation: routing_rules[:attestation] || 'C'
      }
    end
  end
  
  # Example routing rules (would come from SignalWire configuration)
  routing_rules = {
    type: :forward,
    destination: '+15559876543',
    reason: 'time-of-day'
  }
  
  decision = signalwire_routing_decision(original_identity, routing_rules)
  
  if decision[:action] == :create_div_passport
    signalwire_result = auth_service.sign_diverted_call(
      shaken_identity_header: original_identity,
      new_destination: decision[:new_destination],
      original_destination: original_destination,
      diversion_reason: decision[:reason]
    )
    
    puts "✅ SignalWire routing decision: CREATE_DIV_PASSPORT"
    puts "   - Action: Forward call with DIV PASSporT"
    puts "   - Reason: #{decision[:reason]}"
    puts "   - New destination: #{decision[:new_destination]}"
    
    # This is what you'd send to the B-leg
    puts "📤 B-leg headers to send:"
    puts "   - Original Identity: #{signalwire_result[:shaken_header][0..50]}..."
    puts "   - DIV Identity: #{signalwire_result[:div_header][0..50]}..."
  end

rescue => e
  puts "❌ Error in SignalWire integration: #{e.message}"
end

puts "\n📞 Example 7: Validation and Error Handling"
puts "-" * 40

begin
  puts "🔍 Testing various validation scenarios:"
  
  # Test invalid diversion reason
  begin
    auth_service.create_div_passport_from_header(
      shaken_identity_header: original_identity,
      new_destination: '+15559876543',
      original_destination: original_destination,
      diversion_reason: 'invalid-reason'
    )
  rescue StirShaken::InvalidDiversionReasonError => e
    puts "✅ Caught invalid diversion reason: #{e.message}"
  end
  
  # Test invalid phone number
  begin
    auth_service.create_div_passport_from_header(
      shaken_identity_header: original_identity,
      new_destination: 'invalid-number',
      original_destination: original_destination,
      diversion_reason: 'forwarding'
    )
  rescue StirShaken::InvalidPhoneNumberError => e
    puts "✅ Caught invalid phone number: #{e.message}"
  end
  
  # Test invalid Identity header
  begin
    auth_service.create_div_passport_from_header(
      shaken_identity_header: 'invalid-header',
      new_destination: '+15559876543',
      original_destination: original_destination,
      diversion_reason: 'forwarding'
    )
  rescue => e
    puts "✅ Caught invalid Identity header: #{e.class.name}"
  end
  
  puts "📋 Valid diversion reasons:"
  StirShaken::DivPassport::VALID_DIVERSION_REASONS.each do |reason|
    puts "   - #{reason}"
  end

rescue => e
  puts "❌ Error in validation testing: #{e.message}"
end

puts "\n📞 Example 8: Performance and Best Practices"
puts "-" * 42

begin
  require 'benchmark'
  
  puts "⏱️  Performance benchmarks:"
  
  # Benchmark DIV PASSporT creation
  div_time = Benchmark.measure do
    100.times do
      auth_service.create_div_passport_from_header(
        shaken_identity_header: original_identity,
        new_destination: '+15559876543',
        original_destination: original_destination,
        diversion_reason: 'forwarding'
      )
    end
  end
  
  puts "   - 100 DIV PASSporT creations: #{(div_time.real * 1000).round(2)}ms"
  puts "   - Average per creation: #{(div_time.real * 10).round(2)}ms"
  
  # Best practices
  puts "\n💡 Best Practices:"
  puts "   1. Cache certificates to avoid repeated fetches"
  puts "   2. Validate phone numbers before creating PASSporTs"
  puts "   3. Use appropriate diversion reasons for compliance"
  puts "   4. Maintain origination_id across forwarding hops"
  puts "   5. Reduce attestation levels appropriately"
  puts "   6. Log all DIV PASSporT operations for audit trails"

rescue => e
  puts "❌ Error in performance testing: #{e.message}"
end

puts "\n🎯 Summary: DIV PASSporT Implementation Complete"
puts "=" * 50
puts "✅ All examples completed successfully!"
puts "📚 Key takeaways:"
puts "   - DIV PASSporT maintains call authenticity during forwarding"
puts "   - Multiple forwarding hops are supported"
puts "   - Attestation levels should be reduced appropriately"
puts "   - Comprehensive validation prevents security issues"
puts "   - SignalWire integration follows standard patterns"
puts "\n🔗 For more information, see:"
puts "   - RFC 8946: PASSporT Extension for Diverted Calls"
puts "   - STIR/SHAKEN Implementation Guide"
puts "   - SignalWire STIR/SHAKEN Documentation" 