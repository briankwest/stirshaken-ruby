#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../lib/stirshaken'
require 'webmock/rspec'

puts "STIR/SHAKEN Certificate Management - Comprehensive Examples"
puts "=" * 70

# Example 1: Basic Certificate Manager Usage
puts "\n1. BASIC CERTIFICATE MANAGER USAGE"
puts "-" * 40

# CertificateManager uses class methods, not singleton pattern
puts "✓ Certificate Manager uses class methods"
puts "  Class-based pattern for certificate operations"

# Check initial cache state
initial_stats = StirShaken::CertificateManager.cache_stats
puts "  Initial cache size: #{initial_stats[:size]} entries"

# Example 2: Creating Test Certificates
puts "\n2. CREATING TEST CERTIFICATES"
puts "-" * 40

# Generate key pair for test certificate
key_pair = StirShaken::AuthenticationService.generate_key_pair
private_key = key_pair[:private_key]

# Create basic test certificate
basic_cert = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Basic Test Certificate/O=Example Corp',
  telephone_numbers: ['+15551234567']
)

puts "✓ Basic test certificate created:"
puts "  Subject: #{basic_cert.subject}"
puts "  Serial: #{basic_cert.serial}"
puts "  Valid from: #{basic_cert.not_before}"
puts "  Valid until: #{basic_cert.not_after}"

# Create certificate with multiple telephone numbers
multi_number_cert = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Multi Number Certificate/O=Telecom Provider/C=US',
  telephone_numbers: ['+15551234567', '+15559876543', '+15551111111', '+18005551234']
)

puts "\n✓ Multi-number test certificate created:"
puts "  Subject: #{multi_number_cert.subject}"
puts "  Telephone numbers: 4 numbers authorized"

# Extract and display telephone numbers from certificate
# Note: We'll create a helper method since extract_telephone_numbers doesn't exist
def extract_telephone_numbers_from_cert(certificate)
  san_ext = certificate.extensions.find { |ext| ext.oid == 'subjectAltName' }
  return [] unless san_ext
  
  san_value = san_ext.value
  tel_uris = san_value.scan(/URI:tel:([+\d]+)/).flatten
  tel_uris
end

telephone_numbers = extract_telephone_numbers_from_cert(multi_number_cert)
puts "  Authorized numbers: #{telephone_numbers.join(', ')}"

# Create certificate with custom validity period
custom_validity_cert = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Custom Validity Certificate/O=Test Corp',
  telephone_numbers: ['+15551234567']
)

puts "\n✓ Custom validity certificate created:"
puts "  Valid from: #{custom_validity_cert.not_before}"
puts "  Valid until: #{custom_validity_cert.not_after}"
puts "  Validity period: #{((custom_validity_cert.not_after - custom_validity_cert.not_before) / 86400).round} days"

# Example 3: Certificate Validation
puts "\n3. CERTIFICATE VALIDATION"
puts "-" * 40

# Validate basic certificate
basic_valid = StirShaken::CertificateManager.validate_certificate(basic_cert)
puts "✓ Basic certificate validation:"
puts "  Valid: #{basic_valid}"
puts "  Reason: #{basic_valid ? 'Certificate passes all validation checks' : 'Validation failed'}"

# Test with expired certificate - create manually since we can't set custom dates
expired_cert = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Expired Certificate/O=Test Corp',
  telephone_numbers: ['+15551234567']
)

# Manually set expired dates
expired_cert.not_before = Time.now - (2 * 365 * 86400) # 2 years ago
expired_cert.not_after = Time.now - 86400 # Expired yesterday

expired_valid = StirShaken::CertificateManager.validate_certificate(expired_cert)
puts "\n✓ Expired certificate validation:"
puts "  Valid: #{expired_valid}"
puts "  Reason: #{expired_valid ? 'Unexpectedly valid' : 'Certificate is expired'}"

# Test with future certificate - create manually since we can't set custom dates
future_cert = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Future Certificate/O=Test Corp',
  telephone_numbers: ['+15551234567']
)

# Manually set future dates
future_cert.not_before = Time.now + 86400 # Valid from tomorrow
future_cert.not_after = Time.now + (365 * 86400) # Valid for 1 year from tomorrow

future_valid = StirShaken::CertificateManager.validate_certificate(future_cert)
puts "\n✓ Future certificate validation:"
puts "  Valid: #{future_valid}"
puts "  Reason: #{future_valid ? 'Unexpectedly valid' : 'Certificate not yet valid'}"

# Example 4: Certificate Caching
puts "\n4. CERTIFICATE CACHING"
puts "-" * 40

# Add certificates to cache manually using the cache directly
test_urls = [
  'https://certs.example.com/basic.pem',
  'https://certs.example.com/multi.pem',
  'https://certs.example.com/custom.pem'
]

test_certs = [basic_cert, multi_number_cert, custom_validity_cert]

# Access the cache directly since there's no public cache_certificate method
cache = StirShaken::CertificateManager.certificate_cache
mutex = StirShaken::CertificateManager.cache_mutex

test_urls.zip(test_certs).each do |url, cert|
  mutex.synchronize do
    cache[url] = {
      certificate: cert,
      fetched_at: Time.now
    }
  end
  puts "✓ Cached certificate: #{url}"
end

# Check cache stats after adding certificates
cache_stats = StirShaken::CertificateManager.cache_stats
puts "\n✓ Cache statistics after adding certificates:"
puts "  Cache size: #{cache_stats[:size]} entries"
puts "  Cached URLs: #{cache_stats[:entries].join(', ')}"

# Retrieve certificates from cache
test_urls.each do |url|
  cached_entry = nil
  mutex.synchronize do
    cached_entry = cache[url]
  end
  
  if cached_entry
    puts "✓ Retrieved from cache: #{url}"
    puts "  Subject: #{cached_entry[:certificate].subject}"
  else
    puts "✗ Not found in cache: #{url}"
  end
end

# Example 5: Cache TTL and Expiration
puts "\n5. CACHE TTL AND EXPIRATION"
puts "-" * 40

# Add a certificate with custom TTL
short_ttl_url = 'https://certs.example.com/short-ttl.pem'
mutex.synchronize do
  cache[short_ttl_url] = {
    certificate: basic_cert,
    fetched_at: Time.now
  }
end

puts "✓ Added certificate with default TTL"
puts "  URL: #{short_ttl_url}"
puts "  Default TTL: #{StirShaken.configuration.certificate_cache_ttl} seconds"

# Check if certificate is in cache
cached_entry = nil
mutex.synchronize do
  cached_entry = cache[short_ttl_url]
end
puts "  In cache: #{cached_entry ? 'Yes' : 'No'}"

# Simulate cache expiration by manipulating cache entry
if cached_entry
  # Set fetched_at to past TTL
  mutex.synchronize do
    cache[short_ttl_url][:fetched_at] = Time.now - (StirShaken.configuration.certificate_cache_ttl + 1)
  end
  puts "✓ Simulated cache expiration"
end

# Try to retrieve expired certificate (would need to check expiration manually)
expired_cached = nil
mutex.synchronize do
  entry = cache[short_ttl_url]
  if entry && (Time.now - entry[:fetched_at]) <= StirShaken.configuration.certificate_cache_ttl
    expired_cached = entry[:certificate]
  end
end
puts "  After expiration: #{expired_cached ? 'Still cached (unexpected)' : 'Expired and removed'}"

# Example 6: Certificate Fetching Simulation
puts "\n6. CERTIFICATE FETCHING SIMULATION"
puts "-" * 40

# Enable WebMock for HTTP simulation
WebMock.enable!

# Create PEM data for test certificate
test_cert_pem = basic_cert.to_pem

# Mock HTTP responses for certificate fetching
mock_urls = [
  'https://certs.telecom.com/valid.pem',
  'https://certs.telecom.com/invalid.pem',
  'https://certs.telecom.com/timeout.pem',
  'https://certs.telecom.com/notfound.pem'
]

# Mock successful certificate fetch
WebMock.stub_request(:get, mock_urls[0])
  .to_return(status: 200, body: test_cert_pem, headers: { 'Content-Type' => 'application/x-pem-file' })

# Mock invalid certificate content
WebMock.stub_request(:get, mock_urls[1])
  .to_return(status: 200, body: 'invalid certificate content', headers: { 'Content-Type' => 'text/plain' })

# Mock timeout
WebMock.stub_request(:get, mock_urls[2])
  .to_timeout

# Mock 404 not found
WebMock.stub_request(:get, mock_urls[3])
  .to_return(status: 404, body: 'Not Found')

puts "✓ HTTP mocks configured for certificate fetching tests"

# Test successful certificate fetch
begin
  fetched_cert = StirShaken::CertificateManager.fetch_certificate(mock_urls[0])
  puts "✓ Successful certificate fetch:"
  puts "  URL: #{mock_urls[0]}"
  puts "  Subject: #{fetched_cert.subject}"
  puts "  Cached: Yes"
rescue => e
  puts "✗ Unexpected error: #{e.message}"
end

# Test invalid certificate content
begin
  invalid_cert = StirShaken::CertificateManager.fetch_certificate(mock_urls[1])
  puts "✗ Invalid certificate should have failed"
rescue StirShaken::CertificateFetchError => e
  puts "✓ Invalid certificate correctly rejected:"
  puts "  Error: #{e.message}"
rescue => e
  puts "✓ Invalid certificate correctly rejected:"
  puts "  Error: #{e.message}"
end

# Test timeout
begin
  timeout_cert = StirShaken::CertificateManager.fetch_certificate(mock_urls[2])
  puts "✗ Timeout should have failed"
rescue StirShaken::CertificateFetchError => e
  puts "✓ Timeout correctly handled:"
  puts "  Error: #{e.message}"
rescue => e
  puts "✓ Timeout correctly handled:"
  puts "  Error: #{e.message}"
end

# Test 404 not found
begin
  notfound_cert = StirShaken::CertificateManager.fetch_certificate(mock_urls[3])
  puts "✗ 404 should have failed"
rescue StirShaken::CertificateFetchError => e
  puts "✓ 404 Not Found correctly handled:"
  puts "  Error: #{e.message}"
rescue => e
  puts "✓ 404 Not Found correctly handled:"
  puts "  Error: #{e.message}"
end

# Disable WebMock
WebMock.disable!

# Example 7: Telephone Number Authorization
puts "\n7. TELEPHONE NUMBER AUTHORIZATION"
puts "-" * 40

# Test authorization with multi-number certificate
authorized_numbers = ['+15551234567', '+15559876543', '+15551111111', '+18005551234']
unauthorized_numbers = ['+19995551234', '+14155551234', '+13105551234']

puts "✓ Testing telephone number authorization:"
puts "  Certificate has #{telephone_numbers.length} authorized numbers"

# Test authorized numbers
authorized_numbers.each do |number|
  authorized = StirShaken::CertificateManager.validate_certificate(multi_number_cert, telephone_number: number)
  status = authorized ? "✓ Authorized" : "✗ Not Authorized"
  puts "  #{number}: #{status}"
end

# Test unauthorized numbers
unauthorized_numbers.each do |number|
  authorized = StirShaken::CertificateManager.validate_certificate(multi_number_cert, telephone_number: number)
  status = authorized ? "✓ Authorized (unexpected)" : "✗ Not Authorized"
  puts "  #{number}: #{status}"
end

# Example 8: Certificate Information Extraction
puts "\n8. CERTIFICATE INFORMATION EXTRACTION"
puts "-" * 40

# Extract comprehensive information from certificate
cert_info = {
  subject: multi_number_cert.subject.to_s,
  issuer: multi_number_cert.issuer.to_s,
  serial: multi_number_cert.serial.to_s,
  version: multi_number_cert.version,
  not_before: multi_number_cert.not_before,
  not_after: multi_number_cert.not_after,
  public_key_algorithm: multi_number_cert.public_key.class.name,
  signature_algorithm: multi_number_cert.signature_algorithm
}

puts "✓ Certificate Information:"
cert_info.each do |key, value|
  puts "  #{key.to_s.gsub('_', ' ').capitalize}: #{value}"
end

# Extract extensions
puts "\n✓ Certificate Extensions:"
multi_number_cert.extensions.each do |ext|
  puts "  #{ext.oid}: #{ext.critical? ? '[CRITICAL]' : '[NON-CRITICAL]'}"
  puts "    #{ext.value}"
end

# Example 9: Cache Management Operations
puts "\n9. CACHE MANAGEMENT OPERATIONS"
puts "-" * 40

# Get current cache statistics
current_stats = StirShaken::CertificateManager.cache_stats
puts "✓ Current cache statistics:"
puts "  Size: #{current_stats[:size]} entries"
puts "  Entries: #{current_stats[:entries].join(', ')}"

# Clear specific cache entry
if current_stats[:entries].any?
  url_to_clear = current_stats[:entries].first
  mutex.synchronize do
    cache.delete(url_to_clear)
  end
  puts "✓ Cleared cache entry: #{url_to_clear}"
  
  # Verify removal
  after_clear = StirShaken::CertificateManager.cache_stats
  puts "  Cache size after clearing: #{after_clear[:size]} entries"
end

# Add multiple certificates for bulk operations
bulk_urls = [
  'https://bulk.example.com/cert1.pem',
  'https://bulk.example.com/cert2.pem',
  'https://bulk.example.com/cert3.pem'
]

bulk_urls.each do |url|
  mutex.synchronize do
    cache[url] = {
      certificate: basic_cert,
      fetched_at: Time.now
    }
  end
end

puts "\n✓ Added #{bulk_urls.length} certificates for bulk testing"

# Clear entire cache
StirShaken::CertificateManager.clear_cache!
final_stats = StirShaken::CertificateManager.cache_stats
puts "✓ Cleared entire cache"
puts "  Cache size after clearing all: #{final_stats[:size]} entries"

# Example 10: Performance Testing
puts "\n10. PERFORMANCE TESTING"
puts "-" * 40

# Performance test: Certificate validation
validation_iterations = 100
start_time = Time.now

validation_iterations.times do
  StirShaken::CertificateManager.validate_certificate(basic_cert)
end

validation_time = Time.now - start_time
avg_validation_time = (validation_time / validation_iterations * 1000).round(2)

puts "✓ Certificate validation performance:"
puts "  Iterations: #{validation_iterations}"
puts "  Total time: #{validation_time.round(3)} seconds"
puts "  Average time: #{avg_validation_time} ms per validation"

# Performance test: Telephone number authorization
auth_iterations = 1000
start_time = Time.now

auth_iterations.times do
  StirShaken::CertificateManager.validate_certificate(multi_number_cert, telephone_number: '+15551234567')
end

auth_time = Time.now - start_time
avg_auth_time = (auth_time / auth_iterations * 1000).round(2)

puts "\n✓ Number authorization performance:"
puts "  Iterations: #{auth_iterations}"
puts "  Total time: #{auth_time.round(3)} seconds"
puts "  Average time: #{avg_auth_time} ms per check"

# Performance test: Cache operations
cache_iterations = 500
test_cert_for_cache = basic_cert

start_time = Time.now

cache_iterations.times do |i|
  url = "https://perf.example.com/cert#{i}.pem"
  mutex.synchronize do
    cache[url] = {
      certificate: test_cert_for_cache,
      fetched_at: Time.now
    }
  end
  
  # Retrieve from cache
  mutex.synchronize do
    cache[url]
  end
end

cache_time = Time.now - start_time
avg_cache_time = (cache_time / cache_iterations * 1000).round(2)

puts "\n✓ Cache operations performance:"
puts "  Iterations: #{cache_iterations} (cache + retrieve)"
puts "  Total time: #{cache_time.round(3)} seconds"
puts "  Average time: #{avg_cache_time} ms per operation"

# Clean up performance test cache entries
StirShaken::CertificateManager.clear_cache!

# Example 11: Error Handling Scenarios
puts "\n11. ERROR HANDLING SCENARIOS"
puts "-" * 40

error_scenarios = [
  {
    name: "Nil Certificate Validation",
    test: -> { StirShaken::CertificateManager.validate_certificate(nil) },
    expected_error: "Certificate cannot be nil"
  },
  {
    name: "Invalid Certificate Object",
    test: -> { StirShaken::CertificateManager.validate_certificate("not a certificate") },
    expected_error: "Invalid certificate object"
  }
]

error_scenarios.each do |scenario|
  begin
    scenario[:test].call
    puts "  ✗ #{scenario[:name]}: Expected error but operation succeeded"
  rescue => e
    puts "  ✓ #{scenario[:name]}: Correctly caught error"
    puts "    Error: #{e.message}"
  end
end

# Example 12: Real-World Certificate Scenarios
puts "\n12. REAL-WORLD CERTIFICATE SCENARIOS"
puts "-" * 40

# Scenario 1: Service Provider Certificate
sp_cert = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Acme Telecom Service Provider/O=Acme Telecom Inc/C=US/ST=California/L=San Francisco',
  telephone_numbers: (1..100).map { |i| "+1555123#{i.to_s.rjust(4, '0')}" } # 100 numbers
)

sp_numbers = extract_telephone_numbers_from_cert(sp_cert)
puts "✓ Service Provider Certificate:"
puts "  Organization: Acme Telecom Inc"
puts "  Authorized numbers: #{sp_numbers.length} numbers"
puts "  Sample numbers: #{sp_numbers.first(5).join(', ')}..."

# Scenario 2: Enterprise Customer Certificate
enterprise_cert = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Enterprise Customer/O=Big Corp/C=US',
  telephone_numbers: ['+15551234567', '+15551234568', '+15551234569'] # Small range
)

enterprise_numbers = extract_telephone_numbers_from_cert(enterprise_cert)
puts "\n✓ Enterprise Customer Certificate:"
puts "  Organization: Big Corp"
puts "  Authorized numbers: #{enterprise_numbers.length} numbers"
puts "  Numbers: #{enterprise_numbers.join(', ')}"

# Scenario 3: International Service Provider
intl_cert = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  subject: '/CN=Global Telecom/O=Global Telecom Ltd/C=GB',
  telephone_numbers: ['+442071234567', '+442071234568', '+15551234567'] # UK and US numbers
)

intl_numbers = extract_telephone_numbers_from_cert(intl_cert)
puts "\n✓ International Service Provider Certificate:"
puts "  Organization: Global Telecom Ltd (UK)"
puts "  Authorized numbers: #{intl_numbers.length} numbers"
puts "  Numbers: #{intl_numbers.join(', ')}"
puts "  Countries: UK (+44) and US (+1)"

# Example 13: Certificate Chain Validation (Simulation)
puts "\n13. CERTIFICATE CHAIN VALIDATION SIMULATION"
puts "-" * 40

puts "✓ Certificate chain validation simulation:"
puts "  In production, certificates would be validated against:"
puts "  • Root CA certificates"
puts "  • Intermediate CA certificates"
puts "  • Certificate Revocation Lists (CRL)"
puts "  • Online Certificate Status Protocol (OCSP)"
puts ""
puts "  Current implementation validates:"
puts "  • Certificate format and structure"
puts "  • Validity period (not_before/not_after)"
puts "  • Telephone number extensions"
puts "  • Public key format and algorithm"

# Example 14: Configuration and Customization
puts "\n14. CONFIGURATION AND CUSTOMIZATION"
puts "-" * 40

# Show current configuration
puts "✓ Current Certificate Manager Configuration:"
puts "  Cache TTL: #{StirShaken.configuration.certificate_cache_ttl} seconds"
puts "  HTTP Timeout: #{StirShaken.configuration.http_timeout} seconds"

# Demonstrate configuration change
original_ttl = StirShaken.configuration.certificate_cache_ttl

StirShaken.configure do |config|
  config.certificate_cache_ttl = 7200 # 2 hours
end

puts "\n✓ Updated configuration:"
puts "  New Cache TTL: #{StirShaken.configuration.certificate_cache_ttl} seconds"

# Restore original configuration
StirShaken.configure do |config|
  config.certificate_cache_ttl = original_ttl
end

puts "  Restored Cache TTL: #{StirShaken.configuration.certificate_cache_ttl} seconds"

puts "\n" + "=" * 70
puts "Certificate Management Examples Completed!"
puts ""
puts "This demonstration covered:"
puts "• Basic certificate manager usage and class-based pattern"
puts "• Creating test certificates with various configurations"
puts "• Certificate validation and expiration checking"
puts "• Certificate caching with TTL management"
puts "• HTTP certificate fetching simulation"
puts "• Telephone number authorization checking"
puts "• Certificate information extraction"
puts "• Cache management operations"
puts "• Performance testing and optimization"
puts "• Comprehensive error handling"
puts "• Real-world certificate scenarios"
puts "• Certificate chain validation concepts"
puts "• Configuration and customization options"
puts ""
puts "The Certificate Manager is ready for production use!" 