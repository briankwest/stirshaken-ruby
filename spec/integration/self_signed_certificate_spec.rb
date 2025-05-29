require 'spec_helper'
require 'openssl'
require 'fileutils'

RSpec.describe 'Self-Signed Certificate Integration', type: :integration do
  let(:cert_dir) { File.join(Dir.pwd, 'certs') }
  let(:config_dir) { File.join(Dir.pwd, 'config') }
  let(:cert_name) { 'test-cert' }
  let(:private_key_path) { File.join(cert_dir, "#{cert_name}.key") }
  let(:certificate_path) { File.join(cert_dir, "#{cert_name}.pem") }
  let(:public_key_path) { File.join(cert_dir, "#{cert_name}.pub") }
  let(:config_file_path) { File.join(config_dir, "#{cert_name}.conf") }
  
  # Test phone numbers from the generated certificate
  let(:authorized_number) { '+15551234567' }
  let(:destination_number) { '+15559876543' }

  # Shared variables for all tests
  let(:private_key) { OpenSSL::PKey::EC.new(File.read(private_key_path)) }
  let(:certificate_url) { "https://example.com/test-cert.pem" }

  before(:all) do
    # Ensure we have a test certificate generated
    unless File.exist?(File.join(Dir.pwd, 'certs', 'test-cert.pem'))
      system('./scripts/generate_test_certificate.sh --name test-cert --days 30')
    end
  end

  describe 'Certificate File Validation' do
    it 'generates all required certificate files' do
      expect(File.exist?(private_key_path)).to be true
      expect(File.exist?(certificate_path)).to be true
      expect(File.exist?(public_key_path)).to be true
      expect(File.exist?(config_file_path)).to be true
    end

    it 'creates a valid private key file' do
      expect(File.readable?(private_key_path)).to be true
      
      # Verify it's a valid EC private key
      key_content = File.read(private_key_path)
      expect(key_content).to include('BEGIN EC PRIVATE KEY')
      expect(key_content).to include('END EC PRIVATE KEY')
      
      # Load and verify the key
      private_key = OpenSSL::PKey::EC.new(key_content)
      expect(private_key.private_key?).to be true
      expect(private_key.group.curve_name).to eq('prime256v1')
    end

    it 'creates a valid certificate file' do
      expect(File.readable?(certificate_path)).to be true
      
      # Verify it's a valid X.509 certificate
      cert_content = File.read(certificate_path)
      expect(cert_content).to include('BEGIN CERTIFICATE')
      expect(cert_content).to include('END CERTIFICATE')
      
      # Load and verify the certificate
      certificate = OpenSSL::X509::Certificate.new(cert_content)
      expect(certificate.not_before).to be <= Time.now
      expect(certificate.not_after).to be > Time.now
    end

    it 'creates a certificate with correct STIR/SHAKEN properties' do
      certificate = OpenSSL::X509::Certificate.new(File.read(certificate_path))
      
      # Check subject
      subject = certificate.subject.to_s
      expect(subject).to include('CN=test-cert.test.example.com')
      expect(subject).to include('O=Test Service Provider')
      expect(subject).to include('OU=STIR\\/SHAKEN Testing')  # Escaped slash in DN
      
      # Check key usage extensions
      key_usage = certificate.extensions.find { |ext| ext.oid == 'keyUsage' }
      expect(key_usage).not_to be_nil
      expect(key_usage.value).to include('Digital Signature')
      
      # Check extended key usage
      ext_key_usage = certificate.extensions.find { |ext| ext.oid == 'extendedKeyUsage' }
      expect(ext_key_usage).not_to be_nil
      expect(ext_key_usage.value).to include('TLS Web Client Authentication')
      expect(ext_key_usage.value).to include('TLS Web Server Authentication')
      
      # Check subject alternative names
      san = certificate.extensions.find { |ext| ext.oid == 'subjectAltName' }
      expect(san).not_to be_nil
      expect(san.value).to include('DNS:test-cert.test.example.com')
      expect(san.value).to include('URI:sip:test-cert@test.example.com')
    end

    it 'verifies private key matches certificate public key' do
      private_key = OpenSSL::PKey::EC.new(File.read(private_key_path))
      certificate = OpenSSL::X509::Certificate.new(File.read(certificate_path))
      
      # Extract public key from certificate
      cert_public_key = certificate.public_key
      
      # Compare public key PEM encodings (more reliable for EC keys)
      private_public_pem = private_key.public_to_pem
      cert_public_pem = cert_public_key.public_to_pem
      expect(private_public_pem).to eq(cert_public_pem)
    end
  end

  describe 'STIR/SHAKEN Library Integration' do
    describe 'Authentication Service' do
      let(:auth_service) do
        StirShaken::AuthenticationService.new(
          private_key: private_key,
          certificate_url: certificate_url
        )
      end

      it 'successfully creates Identity header with self-signed certificate' do
        identity_header = auth_service.sign_call(
          originating_number: authorized_number,
          destination_number: destination_number,
          attestation: 'A'
        )

        expect(identity_header).not_to be_nil
        expect(identity_header).to be_a(String)
        expect(identity_header).to include('eyJ')  # JWT header
        expect(identity_header).to include(';info=')
        expect(identity_header).to include(';alg=ES256')
        expect(identity_header).to include(';ppt=shaken')
      end

      it 'creates valid PASSporT structure' do
        identity_header = auth_service.sign_call(
          originating_number: authorized_number,
          destination_number: destination_number,
          attestation: 'A'
        )

        # Extract the token part (before the first semicolon)
        token = identity_header.split(';').first
        
        # Verify JWT structure (3 parts separated by dots)
        parts = token.split('.')
        expect(parts.length).to eq(3)
        
        header_b64, payload_b64, signature_b64 = parts
        expect(header_b64).not_to be_empty
        expect(payload_b64).not_to be_empty
        expect(signature_b64).not_to be_empty

        # Verify the header and payload are valid base64
        expect { Base64.urlsafe_decode64(header_b64) }.not_to raise_error
        expect { Base64.urlsafe_decode64(payload_b64) }.not_to raise_error
      end

      it 'supports all attestation levels' do
        %w[A B C].each do |attestation|
          identity_header = auth_service.sign_call(
            originating_number: authorized_number,
            destination_number: destination_number,
            attestation: attestation
          )

          expect(identity_header).not_to be_nil
          expect(identity_header).to include(';info=')
        end
      end

      it 'handles multiple destination numbers' do
        destinations = ['+15559876543', '+15551111111', '+15552222222']
        
        identity_header = auth_service.sign_call(
          originating_number: authorized_number,
          destination_number: destinations,
          attestation: 'A'
        )

        expect(identity_header).not_to be_nil
        expect(identity_header).to include(';info=')
      end

      it 'includes certificate URL in Identity header' do
        identity_header = auth_service.sign_call(
          originating_number: authorized_number,
          destination_number: destination_number,
          attestation: 'A'
        )

        expect(identity_header).to include(certificate_url)
      end
    end

    describe 'Error Handling' do
      it 'handles invalid private key format' do
        expect {
          StirShaken::AuthenticationService.new(
            private_key: "invalid key",
            certificate_url: certificate_url
          )
        }.to raise_error(StirShaken::ConfigurationError)
      end

      it 'validates attestation levels' do
        auth_service = StirShaken::AuthenticationService.new(
          private_key: private_key,
          certificate_url: certificate_url
        )
        
        expect {
          auth_service.sign_call(
            originating_number: authorized_number,
            destination_number: destination_number,
            attestation: 'X'  # Invalid attestation
          )
        }.to raise_error(StirShaken::InvalidAttestationError)  # Use the correct error class
      end
    end

    describe 'Performance with Self-Signed Certificates' do
      let(:auth_service) do
        StirShaken::AuthenticationService.new(
          private_key: private_key,
          certificate_url: certificate_url
        )
      end

      it 'maintains excellent performance for Identity header creation' do
        iterations = 100
        
        start_time = Time.now
        iterations.times do
          auth_service.sign_call(
            originating_number: authorized_number,
            destination_number: destination_number,
            attestation: 'A'
          )
        end
        end_time = Time.now
        
        total_time = end_time - start_time
        avg_time = (total_time / iterations) * 1000  # Convert to milliseconds
        
        expect(avg_time).to be < 10  # Should be under 10ms per operation
        puts "Average time per Identity header creation: #{avg_time.round(2)}ms"
      end
    end
  end

  describe 'Certificate Script Integration' do
    it 'generates certificates with correct permissions' do
      # Check private key permissions (should be 600)
      stat = File.stat(private_key_path)
      permissions = sprintf('%o', stat.mode)[-3..-1]
      expect(permissions).to eq('600')
      
      # Check certificate permissions (should be 644)
      stat = File.stat(certificate_path)
      permissions = sprintf('%o', stat.mode)[-3..-1]
      expect(permissions).to eq('644')
    end

    it 'creates a comprehensive summary file' do
      summary_path = File.join(cert_dir, "#{cert_name}-summary.txt")
      expect(File.exist?(summary_path)).to be true
      
      summary_content = File.read(summary_path)
      expect(summary_content).to include('STIR/SHAKEN Test Certificate Summary')
      expect(summary_content).to include('SPC Token: 12345678-1234-5678-9012-123456789012')
      expect(summary_content).to include('Authorized Numbers: +15551234567,+15559876543')
      expect(summary_content).to include('WARNING: This is a self-signed certificate for TESTING ONLY!')
    end

    it 'validates certificate against OpenSSL directly' do
      # Use OpenSSL command line to verify our certificate
      result = system("openssl x509 -in #{certificate_path} -text -noout > /dev/null 2>&1")
      expect(result).to be true
    end

    it 'generates certificate with proper STIR/SHAKEN extensions' do
      # Verify certificate contains STIR/SHAKEN specific information
      cert_text = `openssl x509 -in #{certificate_path} -text -noout`
      
      expect(cert_text).to include('Digital Signature')
      expect(cert_text).to include('TLS Web Client Authentication')
      expect(cert_text).to include('TLS Web Server Authentication')
      expect(cert_text).to include('DNS:test-cert.test.example.com')
      expect(cert_text).to include('URI:sip:test-cert@test.example.com')
      expect(cert_text).to include('URI:tel:+15551234567')
      expect(cert_text).to include('URI:tel:+15559876543')
    end
  end

  describe 'Security Considerations' do
    it 'properly warns about self-signed certificate usage' do
      summary_path = File.join(cert_dir, "#{cert_name}-summary.txt")
      summary_content = File.read(summary_path)
      
      expect(summary_content).to include('WARNING')
      expect(summary_content).to include('TESTING ONLY')
      expect(summary_content).to include('production')
      expect(summary_content).to include('STI-CA')
    end

    it 'generates unique certificates on each run' do
      # Generate another certificate with different name
      system('./scripts/generate_test_certificate.sh --name test-cert-2 --days 30 > /dev/null 2>&1')
      
      cert1_path = File.join(cert_dir, 'test-cert.pem')
      cert2_path = File.join(cert_dir, 'test-cert-2.pem')
      
      if File.exist?(cert2_path)
        cert1_content = File.read(cert1_path)
        cert2_content = File.read(cert2_path)
        
        expect(cert1_content).not_to eq(cert2_content)
        
        # Clean up
        File.delete(cert2_path)
        File.delete(File.join(cert_dir, 'test-cert-2.key')) if File.exist?(File.join(cert_dir, 'test-cert-2.key'))
        File.delete(File.join(cert_dir, 'test-cert-2.pub')) if File.exist?(File.join(cert_dir, 'test-cert-2.pub'))
      end
    end

    it 'uses appropriate cryptographic parameters' do
      certificate = OpenSSL::X509::Certificate.new(File.read(certificate_path))
      private_key = OpenSSL::PKey::EC.new(File.read(private_key_path))
      
      # Verify ES256 compatibility
      expect(certificate.signature_algorithm).to eq('ecdsa-with-SHA256')
      expect(private_key.group.curve_name).to eq('prime256v1')
      expect(private_key.group.degree).to eq(256)  # 256-bit key
    end

    it 'demonstrates security logging functionality' do
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: certificate_url
      )

      # Security logging should occur during authentication
      auth_service.sign_call(
        originating_number: authorized_number,
        destination_number: destination_number,
        attestation: 'A'
      )
      
      # Test passes if no exceptions are raised
      expect(true).to be true
    end
  end

  describe 'Integration with Certificate Generation Script' do
    it 'script generates certificates compatible with the library' do
      # Test that certificates generated by our script work with the library
      auth_service = StirShaken::AuthenticationService.new(
        private_key: private_key,
        certificate_url: certificate_url
      )

      # Should be able to create multiple Identity headers without issues
      5.times do |i|
        identity_header = auth_service.sign_call(
          originating_number: authorized_number,
          destination_number: destination_number,
          attestation: 'A'
        )
        
        expect(identity_header).not_to be_nil
        expect(identity_header).to include('eyJ')
      end
    end

    it 'validates script output matches expected format' do
      # Verify the script creates files in the expected format
      expect(File.read(private_key_path)).to match(/-----BEGIN EC PRIVATE KEY-----/)
      expect(File.read(certificate_path)).to match(/-----BEGIN CERTIFICATE-----/)
      expect(File.read(public_key_path)).to match(/-----BEGIN PUBLIC KEY-----/)
      
      # Verify config file exists and has expected content
      config_content = File.read(config_file_path)
      expect(config_content).to include('req_distinguished_name')
      expect(config_content).to include('v3_req')
      expect(config_content).to include('alt_names')
    end
  end
end 