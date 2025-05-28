# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

# Default task
task default: :spec

# RSpec test tasks
RSpec::Core::RakeTask.new(:spec) do |t|
  t.pattern = 'spec/**/*_spec.rb'
  t.rspec_opts = '--format documentation --color'
end

# Individual test tasks
namespace :spec do
  RSpec::Core::RakeTask.new(:unit) do |t|
    t.pattern = 'spec/*_spec.rb'
    t.exclude_pattern = 'spec/integration_spec.rb'
    t.rspec_opts = '--format documentation --color'
  end

  RSpec::Core::RakeTask.new(:integration) do |t|
    t.pattern = 'spec/integration_spec.rb'
    t.rspec_opts = '--format documentation --color'
  end

  RSpec::Core::RakeTask.new(:attestation) do |t|
    t.pattern = 'spec/attestation_spec.rb'
    t.rspec_opts = '--format documentation --color'
  end

  RSpec::Core::RakeTask.new(:passport) do |t|
    t.pattern = 'spec/passport_spec.rb'
    t.rspec_opts = '--format documentation --color'
  end

  RSpec::Core::RakeTask.new(:certificate) do |t|
    t.pattern = 'spec/certificate_manager_spec.rb'
    t.rspec_opts = '--format documentation --color'
  end

  RSpec::Core::RakeTask.new(:auth) do |t|
    t.pattern = 'spec/authentication_service_spec.rb'
    t.rspec_opts = '--format documentation --color'
  end

  RSpec::Core::RakeTask.new(:verification) do |t|
    t.pattern = 'spec/verification_service_spec.rb'
    t.rspec_opts = '--format documentation --color'
  end

  RSpec::Core::RakeTask.new(:sip) do |t|
    t.pattern = 'spec/sip_identity_spec.rb'
    t.rspec_opts = '--format documentation --color'
  end
end

# Coverage task
task :coverage do
  ENV['COVERAGE'] = 'true'
  Rake::Task[:spec].invoke
end

# Development tasks
namespace :dev do
  desc 'Start interactive console with library loaded'
  task :console do
    require 'irb'
    require_relative 'lib/stirshaken'
    
    puts "STIR/SHAKEN Ruby #{StirShaken::VERSION} - Interactive Console"
    puts "Library loaded. Try: StirShaken::AuthenticationService.generate_key_pair"
    
    IRB.start
  end

  desc 'Generate test certificates for development'
  task :generate_certs do
    require_relative 'lib/stirshaken'
    
    puts "Generating test certificates..."
    
    # Generate key pair
    key_pair = StirShaken::AuthenticationService.generate_key_pair
    private_key = key_pair[:private_key]
    
    # Create certificate
    certificate = StirShaken::AuthenticationService.create_test_certificate(
      private_key,
      subject: '/CN=STIR/SHAKEN Test Certificate/O=Test Organization',
      telephone_numbers: ['+15551234567', '+15559876543', '+15551111111']
    )
    
    # Write files
    File.write('test_private_key.pem', private_key.to_pem)
    File.write('test_certificate.pem', certificate.to_pem)
    
    puts "✓ Generated test_private_key.pem"
    puts "✓ Generated test_certificate.pem"
    puts "  Certificate includes telephone numbers: +15551234567, +15559876543, +15551111111"
  end

  desc 'Clean up generated files'
  task :clean do
    files_to_clean = [
      'test_private_key.pem',
      'test_certificate.pem',
      '.rspec_status',
      'coverage/'
    ]
    
    files_to_clean.each do |file|
      if File.exist?(file)
        if File.directory?(file)
          require 'fileutils'
          FileUtils.rm_rf(file)
          puts "✓ Removed directory: #{file}"
        else
          File.delete(file)
          puts "✓ Removed file: #{file}"
        end
      end
    end
  end
end

# Benchmark tasks
namespace :benchmark do
  desc 'Benchmark PASSporT creation performance'
  task :passport_creation do
    require_relative 'lib/stirshaken'
    require 'benchmark'
    
    puts "Benchmarking PASSporT creation..."
    
    # Setup
    key_pair = StirShaken::AuthenticationService.generate_key_pair
    private_key = key_pair[:private_key]
    
    auth_service = StirShaken::AuthenticationService.new(
      private_key: private_key,
      certificate_url: 'https://test.example.com/cert.pem'
    )
    
    # Benchmark
    iterations = 1000
    time = Benchmark.realtime do
      iterations.times do |i|
        auth_service.create_passport(
          originating_number: '+15551234567',
          destination_numbers: ['+15559876543'],
          attestation: 'A',
          origination_id: "benchmark-#{i}"
        )
      end
    end
    
    puts "Created #{iterations} PASSporT tokens in #{time.round(3)} seconds"
    puts "Rate: #{(iterations / time).round(1)} tokens/second"
  end

  desc 'Benchmark verification performance'
  task :verification do
    require_relative 'lib/stirshaken'
    require 'benchmark'
    
    puts "Benchmarking verification performance..."
    
    # Setup
    key_pair = StirShaken::AuthenticationService.generate_key_pair
    private_key = key_pair[:private_key]
    certificate = StirShaken::AuthenticationService.create_test_certificate(
      private_key,
      telephone_numbers: ['+15551234567']
    )
    
    auth_service = StirShaken::AuthenticationService.new(
      private_key: private_key,
      certificate_url: 'https://test.example.com/cert.pem',
      certificate: certificate
    )
    
    verification_service = StirShaken::VerificationService.new
    
    # Pre-create identity headers
    headers = 100.times.map do |i|
      auth_service.sign_call(
        originating_number: '+15551234567',
        destination_number: '+15559876543',
        attestation: 'A',
        origination_id: "benchmark-#{i}"
      )
    end
    
    # Mock certificate fetch to avoid network calls
    StirShaken::CertificateManager.instance_variable_get(:@certificate_cache)['https://test.example.com/cert.pem'] = {
      certificate: certificate,
      fetched_at: Time.now
    }
    
    # Benchmark verification
    time = Benchmark.realtime do
      headers.each do |header|
        verification_service.verify_call(header)
      end
    end
    
    puts "Verified #{headers.length} calls in #{time.round(3)} seconds"
    puts "Rate: #{(headers.length / time).round(1)} verifications/second"
    
    # Show stats
    stats = verification_service.stats
    puts "Success rate: #{stats[:success_rate]}%"
  end
end

# Example tasks
namespace :examples do
  desc 'Run basic usage example'
  task :basic do
    load 'examples/basic_usage.rb'
  end

  desc 'Run all examples'
  task :all do
    Dir.glob('examples/*.rb').each do |example|
      puts "\n" + "="*50
      puts "Running #{example}"
      puts "="*50
      load example
    end
  end
end

# Documentation tasks
begin
  require 'yard'
  YARD::Rake::YardocTask.new(:doc) do |t|
    t.files = ['lib/**/*.rb']
    t.options = ['--markup', 'markdown']
  end
rescue LoadError
  # YARD not available
end

# Utility tasks
desc 'Show library information'
task :info do
  require_relative 'lib/stirshaken'
  
  puts "STIR/SHAKEN Ruby Library"
  puts "Version: #{StirShaken::VERSION}"
  puts "Configuration:"
  puts "  Certificate Cache TTL: #{StirShaken.configuration.certificate_cache_ttl}s"
  puts "  HTTP Timeout: #{StirShaken.configuration.http_timeout}s"
  puts "  Default Attestation: #{StirShaken.configuration.default_attestation}"
  
  # Show available classes
  puts "\nAvailable Classes:"
  [
    'StirShaken::Passport',
    'StirShaken::AuthenticationService',
    'StirShaken::VerificationService',
    'StirShaken::CertificateManager',
    'StirShaken::SipIdentity',
    'StirShaken::Attestation'
  ].each do |klass|
    puts "  #{klass}"
  end
end 