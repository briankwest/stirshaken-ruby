# frozen_string_literal: true

require 'spec_helper'

RSpec.describe StirShaken::SignatureUtils do
  let(:private_key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:public_key) { private_key }
  let(:message) { 'test message for signing' }
  let(:test_signature_hex) { '77b8a6c4ee6979d021e6a7445e51c8aa13334d45d36ae57b12857b0f6948d9e62e2f27e9dd130c4a346350b5e020d5e3d88b90d95f177aa2fdb38c7a21f273d9' }
  let(:test_signature_binary) { [test_signature_hex].pack('H*') }

  describe '.jwt_to_der_signature' do
    it 'converts 64-byte JWT signature to DER format' do
      der_signature = described_class.jwt_to_der_signature(test_signature_binary)
      
      expect(der_signature.length).to be > 64
      expect(der_signature.unpack1('H*')).to start_with('30') # DER SEQUENCE tag
    end

    it 'raises error for invalid signature length' do
      expect {
        described_class.jwt_to_der_signature('short')
      }.to raise_error(ArgumentError, 'JWT signature must be 64 bytes')
    end
  end

  describe '.der_to_jwt_signature' do
    it 'converts DER signature back to JWT format' do
      der_signature = described_class.jwt_to_der_signature(test_signature_binary)
      jwt_signature = described_class.der_to_jwt_signature(der_signature)
      
      expect(jwt_signature).to eq(test_signature_binary)
      expect(jwt_signature.length).to eq(64)
    end

    it 'handles round-trip conversion perfectly' do
      der_signature = described_class.jwt_to_der_signature(test_signature_binary)
      jwt_signature = described_class.der_to_jwt_signature(der_signature)
      
      expect(jwt_signature).to eq(test_signature_binary)
    end
  end

  describe '.verify_jwt_signature' do
    context 'with valid signature' do
      let(:jwt_signature) { described_class.create_jwt_signature(private_key, message) }

      it 'verifies signature correctly' do
        result = described_class.verify_jwt_signature(public_key, jwt_signature, message)
        expect(result).to be true
      end

      it 'fails with wrong message' do
        result = described_class.verify_jwt_signature(public_key, jwt_signature, 'wrong message')
        expect(result).to be false
      end

      it 'fails with wrong public key' do
        wrong_key = OpenSSL::PKey::EC.generate('prime256v1')
        result = described_class.verify_jwt_signature(wrong_key, jwt_signature, message)
        expect(result).to be false
      end
    end

    context 'with invalid inputs' do
      it 'returns false for malformed signature' do
        result = described_class.verify_jwt_signature(public_key, 'invalid', message)
        expect(result).to be false
      end

      it 'returns false for wrong signature length' do
        wrong_length_sig = 'a' * 32 # Too short
        result = described_class.verify_jwt_signature(public_key, wrong_length_sig, message)
        expect(result).to be false
      end
    end
  end

  describe '.create_jwt_signature' do
    it 'creates 64-byte signature' do
      signature = described_class.create_jwt_signature(private_key, message)
      expect(signature.length).to eq(64)
    end

    it 'creates verifiable signature' do
      signature = described_class.create_jwt_signature(private_key, message)
      verified = described_class.verify_jwt_signature(public_key, signature, message)
      expect(verified).to be true
    end

    it 'creates different signatures for different messages' do
      sig1 = described_class.create_jwt_signature(private_key, 'message1')
      sig2 = described_class.create_jwt_signature(private_key, 'message2')
      expect(sig1).not_to eq(sig2)
    end
  end

  describe 'integration with OpenSSL' do
    it 'works with raw OpenSSL verification after conversion' do
      # Create signature with our utility
      jwt_signature = described_class.create_jwt_signature(private_key, message)
      
      # Convert to DER
      der_signature = described_class.jwt_to_der_signature(jwt_signature)
      
      # Verify with raw OpenSSL
      verified = public_key.verify('SHA256', der_signature, message)
      expect(verified).to be true
    end

    it 'handles P-256 curve correctly' do
      # Ensure we're using the correct curve
      expect(private_key.group.curve_name).to eq('prime256v1')
      
      signature = described_class.create_jwt_signature(private_key, message)
      verified = described_class.verify_jwt_signature(public_key, signature, message)
      
      expect(verified).to be true
    end
  end

  describe 'error handling' do
    it 'gracefully handles OpenSSL errors' do
      # This should not raise an exception, just return false
      result = described_class.verify_jwt_signature(public_key, "\x00" * 64, message)
      expect(result).to be false
    end

    it 'handles malformed DER in der_to_jwt_signature' do
      expect {
        described_class.der_to_jwt_signature('not der')
      }.to raise_error(OpenSSL::ASN1::ASN1Error)
    end
  end

  describe 'format validation' do
    it 'validates DER SEQUENCE structure' do
      der_signature = described_class.jwt_to_der_signature(test_signature_binary)
      
      # Parse as ASN.1 to verify structure
      asn1 = OpenSSL::ASN1.decode(der_signature)
      expect(asn1.tag).to eq(16) # SEQUENCE
      expect(asn1.value.length).to eq(2) # Two INTEGERs
      expect(asn1.value[0].tag).to eq(2) # INTEGER (R)
      expect(asn1.value[1].tag).to eq(2) # INTEGER (S)
    end

    it 'maintains signature component ranges' do
      der_signature = described_class.jwt_to_der_signature(test_signature_binary)
      jwt_signature = described_class.der_to_jwt_signature(der_signature)
      
      # Split back to R and S
      r_component = jwt_signature[0, 32]
      s_component = jwt_signature[32, 32]
      
      expect(r_component.length).to eq(32)
      expect(s_component.length).to eq(32)
    end
  end
end 