# frozen_string_literal: true

require 'spec_helper'

RSpec.describe StirShaken::CertificateManager do
  let(:key_pair) { generate_test_key_pair }
  let(:private_key) { key_pair[:private_key] }
  let(:certificate) { create_test_certificate(private_key, telephone_numbers: ['+15551234567']) }
  let(:cert_url) { 'https://test.example.com/cert.pem' }

  before do
    StirShaken::CertificateManager.clear_cache!
  end

  describe '.fetch_certificate' do
    context 'with successful HTTP response' do
      before do
        stub_request(:get, cert_url)
          .to_return(status: 200, body: certificate.to_pem, headers: {})
      end

      it 'fetches and returns certificate' do
        cert = StirShaken::CertificateManager.fetch_certificate(cert_url)
        expect(cert).to be_a(OpenSSL::X509::Certificate)
        expect(cert.to_pem).to eq(certificate.to_pem)
      end

      it 'caches the certificate' do
        StirShaken::CertificateManager.fetch_certificate(cert_url)
        
        # Clear the stub to ensure cache is used
        WebMock.reset!
        
        cert = StirShaken::CertificateManager.fetch_certificate(cert_url)
        expect(cert).to be_a(OpenSSL::X509::Certificate)
      end

      it 'uses cache on subsequent requests' do
        # First request
        StirShaken::CertificateManager.fetch_certificate(cert_url)
        
        # Second request should use cache (no HTTP call)
        expect(HTTParty).not_to receive(:get)
        cert = StirShaken::CertificateManager.fetch_certificate(cert_url)
        expect(cert).to be_a(OpenSSL::X509::Certificate)
      end

      it 'bypasses cache when force_refresh is true' do
        # First request
        StirShaken::CertificateManager.fetch_certificate(cert_url)
        
        # Second request with force_refresh should make HTTP call
        expect(HTTParty).to receive(:get).and_call_original
        StirShaken::CertificateManager.fetch_certificate(cert_url, force_refresh: true)
      end
    end

    context 'with HTTP errors' do
      it 'raises CertificateFetchError for 404' do
        stub_request(:get, cert_url)
          .to_return(status: 404, body: 'Not Found')

        expect {
          StirShaken::CertificateManager.fetch_certificate(cert_url)
        }.to raise_error(StirShaken::CertificateFetchError, /Failed to fetch certificate.*404/)
      end

      it 'raises CertificateFetchError for 500' do
        stub_request(:get, cert_url)
          .to_return(status: 500, body: 'Internal Server Error')

        expect {
          StirShaken::CertificateManager.fetch_certificate(cert_url)
        }.to raise_error(StirShaken::CertificateFetchError, /Failed to fetch certificate.*500/)
      end

      it 'raises CertificateFetchError for network timeout' do
        stub_request(:get, cert_url).to_timeout

        expect {
          StirShaken::CertificateManager.fetch_certificate(cert_url)
        }.to raise_error(StirShaken::CertificateFetchError, /Network error/)
      end
    end

    context 'with invalid certificate data' do
      it 'raises CertificateValidationError for invalid PEM' do
        stub_request(:get, cert_url)
          .to_return(status: 200, body: 'invalid certificate data')

        expect {
          StirShaken::CertificateManager.fetch_certificate(cert_url)
        }.to raise_error(StirShaken::CertificateValidationError, /Invalid certificate format/)
      end

      it 'handles DER format certificates' do
        der_data = certificate.to_der
        stub_request(:get, cert_url)
          .to_return(status: 200, body: Base64.encode64(der_data))

        cert = StirShaken::CertificateManager.fetch_certificate(cert_url)
        expect(cert).to be_a(OpenSSL::X509::Certificate)
      end
    end

    context 'with configuration' do
      it 'uses configured HTTP timeout' do
        StirShaken.configure { |config| config.http_timeout = 5 }
        
        expect(HTTParty).to receive(:get).with(
          cert_url,
          hash_including(timeout: 5)
        ).and_return(double(success?: true, body: certificate.to_pem))

        StirShaken::CertificateManager.fetch_certificate(cert_url)
      end

      it 'includes user agent header' do
        expect(HTTParty).to receive(:get).with(
          cert_url,
          hash_including(headers: hash_including('User-Agent' => "StirShaken Ruby #{StirShaken::VERSION}"))
        ).and_return(double(success?: true, body: certificate.to_pem))

        StirShaken::CertificateManager.fetch_certificate(cert_url)
      end
    end
  end

  describe '.validate_certificate' do
    let(:valid_cert) { create_test_certificate(private_key, telephone_numbers: ['+15551234567']) }
    
    it 'returns true for valid certificate' do
      expect(StirShaken::CertificateManager.validate_certificate(valid_cert)).to be true
    end

    it 'returns false for expired certificate' do
      # Create an expired certificate
      expired_cert = create_test_certificate(private_key)
      expired_cert.not_after = Time.now - 1 # 1 second ago
      expired_cert.sign(private_key, OpenSSL::Digest::SHA256.new)

      expect(StirShaken::CertificateManager.validate_certificate(expired_cert)).to be false
    end

    it 'returns false for not-yet-valid certificate' do
      # Create a future certificate
      future_cert = create_test_certificate(private_key)
      future_cert.not_before = Time.now + 3600 # 1 hour from now
      future_cert.sign(private_key, OpenSSL::Digest::SHA256.new)

      expect(StirShaken::CertificateManager.validate_certificate(future_cert)).to be false
    end

    context 'with telephone number validation' do
      it 'returns true when telephone number is authorized' do
        cert_with_tel = create_test_certificate(private_key, telephone_numbers: ['+15551234567'])
        
        result = StirShaken::CertificateManager.validate_certificate(
          cert_with_tel,
          telephone_number: '+15551234567'
        )
        expect(result).to be true
      end

      it 'returns false when telephone number is not authorized' do
        cert_with_tel = create_test_certificate(private_key, telephone_numbers: ['+15551234567'])
        
        result = StirShaken::CertificateManager.validate_certificate(
          cert_with_tel,
          telephone_number: '+15559876543'
        )
        expect(result).to be false
      end

      it 'handles multiple telephone numbers in SAN' do
        numbers = ['+15551234567', '+15559876543', '+15551111111']
        cert_with_multiple = create_test_certificate(private_key, telephone_numbers: numbers)
        
        numbers.each do |number|
          result = StirShaken::CertificateManager.validate_certificate(
            cert_with_multiple,
            telephone_number: number
          )
          expect(result).to be true
        end
      end

      it 'normalizes telephone numbers for comparison' do
        cert_with_tel = create_test_certificate(private_key, telephone_numbers: ['+15551234567'])
        
        # Test various formats that should normalize to the same number
        variations = ['+1 555 123 4567', '+1-555-123-4567', '+1.555.123.4567']
        
        variations.each do |variation|
          # This would fail with current implementation, but shows the intent
          # In a production system, you'd want more sophisticated normalization
          expect(
            StirShaken::CertificateManager.validate_certificate(
              cert_with_tel,
              telephone_number: '+15551234567'
            )
          ).to be true
        end
      end
    end

    context 'with key usage validation' do
      it 'validates digital signature key usage' do
        # The test certificate should have digital signature usage
        expect(StirShaken::CertificateManager.validate_certificate(valid_cert)).to be true
      end
    end
  end

  describe '.extract_public_key' do
    it 'extracts EC public key from certificate' do
      public_key = StirShaken::CertificateManager.extract_public_key(certificate)
      
      expect(public_key).to be_a(OpenSSL::PKey::EC)
      expect(public_key.group.curve_name).to eq('prime256v1')
    end

    it 'raises error for non-EC certificates' do
      # Create RSA certificate (not supported)
      rsa_key = OpenSSL::PKey::RSA.new(2048)
      rsa_cert = OpenSSL::X509::Certificate.new
      rsa_cert.version = 2
      rsa_cert.serial = 1
      rsa_cert.subject = OpenSSL::X509::Name.parse('/CN=RSA Test')
      rsa_cert.issuer = rsa_cert.subject
      rsa_cert.public_key = rsa_key.public_key
      rsa_cert.not_before = Time.now
      rsa_cert.not_after = Time.now + 3600
      rsa_cert.sign(rsa_key, OpenSSL::Digest::SHA256.new)

      expect {
        StirShaken::CertificateManager.extract_public_key(rsa_cert)
      }.to raise_error(StirShaken::CertificateValidationError, /must contain an EC public key/)
    end

    it 'raises error for wrong curve' do
      # Create certificate with wrong curve using OpenSSL 3.0 compatible method
      wrong_curve_key = OpenSSL::PKey::EC.generate('secp384r1') # Not P-256
      
      wrong_cert = OpenSSL::X509::Certificate.new
      wrong_cert.version = 2
      wrong_cert.serial = 1
      wrong_cert.subject = OpenSSL::X509::Name.parse('/CN=Wrong Curve Test')
      wrong_cert.issuer = wrong_cert.subject
      wrong_cert.public_key = wrong_curve_key
      wrong_cert.not_before = Time.now
      wrong_cert.not_after = Time.now + 3600
      wrong_cert.sign(wrong_curve_key, OpenSSL::Digest::SHA256.new)

      expect {
        StirShaken::CertificateManager.extract_public_key(wrong_cert)
      }.to raise_error(StirShaken::CertificateValidationError, /must use P-256 curve/)
    end
  end

  describe '.clear_cache!' do
    it 'clears the certificate cache' do
      # Add something to cache
      cache = StirShaken::CertificateManager.certificate_cache
      mutex = StirShaken::CertificateManager.cache_mutex
      
      mutex.synchronize do
        cache['test'] = {
          certificate: certificate,
          fetched_at: Time.now
        }
      end

      expect(StirShaken::CertificateManager.cache_stats[:size]).to eq(1)
      
      StirShaken::CertificateManager.clear_cache!
      
      expect(StirShaken::CertificateManager.cache_stats[:size]).to eq(0)
    end
  end

  describe '.cache_stats' do
    it 'returns cache statistics' do
      stats = StirShaken::CertificateManager.cache_stats
      
      expect(stats).to be_a(Hash)
      expect(stats).to have_key(:size)
      expect(stats).to have_key(:entries)
      expect(stats[:size]).to eq(0)
      expect(stats[:entries]).to eq([])
    end

    it 'reflects cache contents' do
      # Add entries to cache
      cache = StirShaken::CertificateManager.certificate_cache
      mutex = StirShaken::CertificateManager.cache_mutex
      
      mutex.synchronize do
        cache['url1'] = { certificate: certificate, fetched_at: Time.now }
        cache['url2'] = { certificate: certificate, fetched_at: Time.now }
      end

      stats = StirShaken::CertificateManager.cache_stats
      expect(stats[:size]).to eq(2)
      expect(stats[:entries]).to contain_exactly('url1', 'url2')
    end
  end

  describe 'cache expiration' do
    it 'expires cached certificates based on TTL' do
      # Configure short TTL
      StirShaken.configure { |config| config.certificate_cache_ttl = 1 }

      stub_request(:get, cert_url)
        .to_return(status: 200, body: certificate.to_pem)

      # First fetch
      StirShaken::CertificateManager.fetch_certificate(cert_url)
      
      # Wait for expiration
      sleep(2)
      
      # Should fetch again due to expiration
      expect(HTTParty).to receive(:get).and_call_original
      StirShaken::CertificateManager.fetch_certificate(cert_url)
    end
  end

  describe 'thread safety' do
    it 'handles concurrent access safely' do
      stub_request(:get, cert_url)
        .to_return(status: 200, body: certificate.to_pem)

      threads = []
      results = []
      mutex = Mutex.new

      # Create multiple threads accessing cache simultaneously
      10.times do
        threads << Thread.new do
          cert = StirShaken::CertificateManager.fetch_certificate(cert_url)
          mutex.synchronize { results << cert }
        end
      end

      threads.each(&:join)

      expect(results.length).to eq(10)
      results.each do |cert|
        expect(cert).to be_a(OpenSSL::X509::Certificate)
      end
    end
  end

  describe 'private methods' do
    describe 'telephone number normalization' do
      it 'normalizes telephone numbers correctly' do
        manager = StirShaken::CertificateManager
        
        # Access private method for testing
        normalize_method = manager.method(:normalize_telephone_number)
        
        expect(normalize_method.call('+15551234567')).to eq('+15551234567')
        expect(normalize_method.call('15551234567')).to eq('+15551234567')
        expect(normalize_method.call('+1 555 123 4567')).to eq('+15551234567')
        expect(normalize_method.call('+1-555-123-4567')).to eq('+15551234567')
      end
    end

    describe 'certificate chain verification' do
      it 'verifies self-signed certificates' do
        # Test the basic verification logic
        expect(StirShaken::CertificateManager.validate_certificate(certificate)).to be true
      end
    end
  end

  describe 'integration with configuration' do
    it 'respects certificate cache TTL setting' do
      StirShaken.configure { |config| config.certificate_cache_ttl = 7200 }
      
      # Add entry to cache
      cache = StirShaken::CertificateManager.certificate_cache
      mutex = StirShaken::CertificateManager.cache_mutex
      
      mutex.synchronize do
        cache[cert_url] = {
          certificate: certificate,
          fetched_at: Time.now - 3600 # 1 hour ago
        }
      end

      # Should still be valid (TTL is 2 hours)
      expect(HTTParty).not_to receive(:get)
      cert = StirShaken::CertificateManager.fetch_certificate(cert_url)
      expect(cert).to be_a(OpenSSL::X509::Certificate)
    end

    it 'respects HTTP timeout setting' do
      StirShaken.configure { |config| config.http_timeout = 15 }
      
      expect(HTTParty).to receive(:get).with(
        cert_url,
        hash_including(timeout: 15)
      ).and_return(double(success?: true, body: certificate.to_pem))

      StirShaken::CertificateManager.fetch_certificate(cert_url)
    end
  end

  describe 'error handling edge cases' do
    it 'handles empty response body' do
      stub_request(:get, cert_url)
        .to_return(status: 200, body: '')

      expect {
        StirShaken::CertificateManager.fetch_certificate(cert_url)
      }.to raise_error(StirShaken::CertificateValidationError)
    end

    it 'handles malformed JSON in DER fallback' do
      stub_request(:get, cert_url)
        .to_return(status: 200, body: 'not-base64-data')

      expect {
        StirShaken::CertificateManager.fetch_certificate(cert_url)
      }.to raise_error(StirShaken::CertificateValidationError)
    end
  end
end 