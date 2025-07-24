# frozen_string_literal: true

module StirShaken
  ##
  # Signature Utilities for STIR/SHAKEN
  #
  # This module provides utilities for handling ECDSA signature format conversions
  # between JWT's R||S format and OpenSSL's DER format.
  module SignatureUtils
    ##
    # Convert ECDSA signature from JWT's R||S format to DER format
    #
    # JWT ES256 signatures are stored as R||S (64 bytes: 32-byte R + 32-byte S)
    # OpenSSL expects DER-encoded ASN.1 SEQUENCE { INTEGER r, INTEGER s }
    #
    # @param jwt_signature [String] 64-byte R||S signature from JWT
    # @return [String] DER-encoded signature for OpenSSL
    def self.jwt_to_der_signature(jwt_signature)
      raise ArgumentError, "JWT signature must be 64 bytes" unless jwt_signature.length == 64
      
      # Split R and S components (32 bytes each for P-256)
      r_bytes = jwt_signature[0, 32]
      s_bytes = jwt_signature[32, 32]
      
      # Convert to OpenSSL BNs (remove leading zeros, but keep at least one byte)
      r_bn = OpenSSL::BN.new(r_bytes, 2)
      s_bn = OpenSSL::BN.new(s_bytes, 2)
      
      # Create ASN.1 sequence manually for DER encoding
      # SEQUENCE { INTEGER r, INTEGER s }
      r_der = asn1_integer_der(r_bn)
      s_der = asn1_integer_der(s_bn)
      
      # Create SEQUENCE DER encoding
      content = r_der + s_der
      sequence_der = asn1_sequence_der(content)
      
      sequence_der
    end
    
    ##
    # Convert DER signature back to JWT's R||S format
    #
    # @param der_signature [String] DER-encoded signature
    # @return [String] 64-byte R||S signature for JWT
    def self.der_to_jwt_signature(der_signature)
      # Parse DER SEQUENCE
      asn1 = OpenSSL::ASN1.decode(der_signature)
      
      unless asn1.tag == 16 && asn1.tag_class == :UNIVERSAL # SEQUENCE
        raise ArgumentError, "Invalid DER signature: not a SEQUENCE"
      end
      
      unless asn1.value.length == 2
        raise ArgumentError, "Invalid DER signature: SEQUENCE must contain exactly 2 INTEGERs"
      end
      
      r_asn1 = asn1.value[0]
      s_asn1 = asn1.value[1]
      
      unless r_asn1.tag == 2 && s_asn1.tag == 2 # INTEGER
        raise ArgumentError, "Invalid DER signature: SEQUENCE must contain INTEGERs"
      end
      
      # Get BN values
      r_bn = OpenSSL::BN.new(r_asn1.value)
      s_bn = OpenSSL::BN.new(s_asn1.value)
      
      # Convert to 32-byte fixed-length format (for P-256)
      r_bytes = bn_to_fixed_bytes(r_bn, 32)
      s_bytes = bn_to_fixed_bytes(s_bn, 32)
      
      r_bytes + s_bytes
    end
    
    ##
    # Verify ECDSA signature using raw OpenSSL with proper format conversion
    #
    # @param public_key [OpenSSL::PKey::EC] the public key
    # @param jwt_signature [String] 64-byte R||S signature from JWT
    # @param message [String] the message that was signed
    # @param digest [String] the digest algorithm (default: 'SHA256')
    # @return [Boolean] true if signature is valid
    def self.verify_jwt_signature(public_key, jwt_signature, message, digest: 'SHA256')
      # Convert JWT signature to DER format
      der_signature = jwt_to_der_signature(jwt_signature)
      
      # Verify using OpenSSL
      public_key.verify(digest, der_signature, message)
    rescue => e
      # Log the error for debugging but return false
      puts "Signature verification failed: #{e.message}" if ENV['STIRSHAKEN_DEBUG']
      false
    end
    
    ##
    # Create ECDSA signature in JWT format using raw OpenSSL
    #
    # @param private_key [OpenSSL::PKey::EC] the private key
    # @param message [String] the message to sign
    # @param digest [String] the digest algorithm (default: 'SHA256')
    # @return [String] 64-byte R||S signature for JWT
    def self.create_jwt_signature(private_key, message, digest: 'SHA256')
      # Sign with OpenSSL (returns DER format)
      der_signature = private_key.sign(digest, message)
      
      # Convert DER to JWT format
      der_to_jwt_signature(der_signature)
    end
    
    private
    
    ##
    # Create ASN.1 INTEGER DER encoding
    #
    # @param bn [OpenSSL::BN] the big number
    # @return [String] DER-encoded INTEGER
    def self.asn1_integer_der(bn)
      # Convert BN to minimal byte representation
      bytes = bn.to_s(2)
      
      # Add leading zero if high bit is set (to ensure positive interpretation)
      bytes = "\x00" + bytes if bytes.getbyte(0) >= 0x80
      
      # Create DER: tag (0x02) + length + content
      "\x02" + der_length_encode(bytes.length) + bytes
    end
    
    ##
    # Create ASN.1 SEQUENCE DER encoding
    #
    # @param content [String] the sequence content
    # @return [String] DER-encoded SEQUENCE
    def self.asn1_sequence_der(content)
      # Create DER: tag (0x30) + length + content
      "\x30" + der_length_encode(content.length) + content
    end
    
    ##
    # Encode length in DER format
    #
    # @param length [Integer] the length to encode
    # @return [String] DER-encoded length
    def self.der_length_encode(length)
      if length < 0x80
        # Short form: length fits in 7 bits
        [length].pack('C')
      else
        # Long form: first byte has high bit set + length of length
        length_bytes = []
        temp_length = length
        while temp_length > 0
          length_bytes.unshift(temp_length & 0xFF)
          temp_length >>= 8
        end
        
        first_byte = 0x80 | length_bytes.length
        [first_byte].pack('C') + length_bytes.pack('C*')
      end
    end
    
    ##
    # Convert BN to fixed-length byte array
    #
    # @param bn [OpenSSL::BN] the big number
    # @param byte_length [Integer] target byte length
    # @return [String] fixed-length byte representation
    def self.bn_to_fixed_bytes(bn, byte_length)
      bytes = bn.to_s(2)
      
      if bytes.length > byte_length
        # Truncate leading bytes if too long (shouldn't happen for valid signatures)
        bytes = bytes[-byte_length..-1]
      elsif bytes.length < byte_length
        # Pad with leading zeros if too short
        bytes = ("\x00" * (byte_length - bytes.length)) + bytes
      end
      
      bytes
    end
  end
end 