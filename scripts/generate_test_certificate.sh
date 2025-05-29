#!/bin/bash

# STIR/SHAKEN Test Certificate Generator
# =====================================
# This script generates self-signed certificates for STIR/SHAKEN testing
# WARNING: These certificates are for TESTING ONLY and should never be used in production

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/../certs"
CONFIG_DIR="${SCRIPT_DIR}/../config"

# Default values
CERT_NAME="stirshaken-test"
VALIDITY_DAYS=365
KEY_SIZE=256  # P-256 curve for ES256
COUNTRY="US"
STATE="California"
CITY="San Francisco"
ORG="Test Service Provider"
OU="STIR/SHAKEN Testing"
EMAIL="admin@test-sp.example.com"

# STIR/SHAKEN specific values
SPC_TOKEN="12345678-1234-5678-9012-123456789012"  # Test SPC Token
OCN="1234"  # Test Operating Company Number
TELEPHONE_NUMBERS="+15551234567,+15559876543"  # Test authorized numbers

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}$1${NC}"
}

# Function to show usage
show_usage() {
    cat << EOF
STIR/SHAKEN Test Certificate Generator

Usage: $0 [OPTIONS]

OPTIONS:
    -n, --name NAME         Certificate name (default: stirshaken-test)
    -d, --days DAYS         Validity period in days (default: 365)
    -c, --country CODE      Country code (default: US)
    -s, --state STATE       State/Province (default: California)
    -l, --city CITY         City/Locality (default: San Francisco)
    -o, --org ORG           Organization (default: Test Service Provider)
    -u, --ou OU             Organizational Unit (default: STIR/SHAKEN Testing)
    -e, --email EMAIL       Email address (default: admin@test-sp.example.com)
    -t, --spc-token TOKEN   SPC Token (default: test token)
    -r, --ocn OCN           Operating Company Number (default: 1234)
    -p, --phone NUMBERS     Comma-separated phone numbers (default: test numbers)
    -h, --help              Show this help message
    --clean                 Clean existing certificates before generating new ones

EXAMPLES:
    # Generate default test certificate
    $0

    # Generate certificate with custom name and validity
    $0 --name my-test-cert --days 30

    # Generate certificate for specific organization
    $0 --org "My Telecom Company" --email "certs@mytelecom.com"

    # Clean and regenerate certificates
    $0 --clean

NOTES:
    - Certificates are generated in: $CERT_DIR
    - These are self-signed certificates for TESTING ONLY
    - For production, obtain certificates from an authorized STI-CA
    - See CERT.md for production certificate instructions

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            CERT_NAME="$2"
            shift 2
            ;;
        -d|--days)
            VALIDITY_DAYS="$2"
            shift 2
            ;;
        -c|--country)
            COUNTRY="$2"
            shift 2
            ;;
        -s|--state)
            STATE="$2"
            shift 2
            ;;
        -l|--city)
            CITY="$2"
            shift 2
            ;;
        -o|--org)
            ORG="$2"
            shift 2
            ;;
        -u|--ou)
            OU="$2"
            shift 2
            ;;
        -e|--email)
            EMAIL="$2"
            shift 2
            ;;
        -t|--spc-token)
            SPC_TOKEN="$2"
            shift 2
            ;;
        -r|--ocn)
            OCN="$2"
            shift 2
            ;;
        -p|--phone)
            TELEPHONE_NUMBERS="$2"
            shift 2
            ;;
        --clean)
            CLEAN_CERTS=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    print_error "OpenSSL is required but not installed"
    exit 1
fi

# Create directories
mkdir -p "$CERT_DIR"
mkdir -p "$CONFIG_DIR"

# Clean existing certificates if requested
if [[ "$CLEAN_CERTS" == "true" ]]; then
    print_warning "Cleaning existing certificates..."
    rm -f "$CERT_DIR"/${CERT_NAME}.*
    rm -f "$CONFIG_DIR"/${CERT_NAME}.conf
fi

# File paths
PRIVATE_KEY="$CERT_DIR/${CERT_NAME}.key"
PUBLIC_KEY="$CERT_DIR/${CERT_NAME}.pub"
CERTIFICATE="$CERT_DIR/${CERT_NAME}.pem"
CONFIG_FILE="$CONFIG_DIR/${CERT_NAME}.conf"
CSR_FILE="$CERT_DIR/${CERT_NAME}.csr"

print_header "STIR/SHAKEN Test Certificate Generator"
print_header "======================================"

print_status "Configuration:"
echo "  Certificate Name: $CERT_NAME"
echo "  Validity Period: $VALIDITY_DAYS days"
echo "  Organization: $ORG"
echo "  SPC Token: $SPC_TOKEN"
echo "  OCN: $OCN"
echo "  Authorized Numbers: $TELEPHONE_NUMBERS"
echo "  Output Directory: $CERT_DIR"
echo ""

# Create OpenSSL configuration file
print_status "Creating OpenSSL configuration..."
cat > "$CONFIG_FILE" << EOF
# OpenSSL Configuration for STIR/SHAKEN Test Certificate
# This configuration creates a certificate suitable for STIR/SHAKEN testing

[ req ]
default_bits = 2048
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORG
OU = $OU
CN = $CERT_NAME.test.example.com
emailAddress = $EMAIL

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
extendedKeyUsage = clientAuth, serverAuth

# STIR/SHAKEN specific extensions
1.3.6.1.5.5.7.1.26 = ASN1:UTF8String:$SPC_TOKEN
# SPC Token - Service Provider Code Token

[ alt_names ]
DNS.1 = $CERT_NAME.test.example.com
DNS.2 = *.test.example.com
URI.1 = sip:$CERT_NAME@test.example.com
EOF

# Add telephone number extensions if provided
if [[ -n "$TELEPHONE_NUMBERS" ]]; then
    echo "" >> "$CONFIG_FILE"
    echo "# Authorized Telephone Numbers" >> "$CONFIG_FILE"
    IFS=',' read -ra NUMBERS <<< "$TELEPHONE_NUMBERS"
    for i in "${!NUMBERS[@]}"; do
        num=$((i + 1))
        echo "URI.$((num + 1)) = tel:${NUMBERS[i]}" >> "$CONFIG_FILE"
    done
fi

print_status "Generating EC private key (P-256 curve for ES256)..."
openssl ecparam -genkey -name prime256v1 -out "$PRIVATE_KEY"

print_status "Extracting public key..."
openssl ec -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

print_status "Creating certificate signing request..."
openssl req -new -key "$PRIVATE_KEY" -out "$CSR_FILE" -config "$CONFIG_FILE"

print_status "Generating self-signed certificate..."
openssl x509 -req -in "$CSR_FILE" -signkey "$PRIVATE_KEY" -out "$CERTIFICATE" \
    -days "$VALIDITY_DAYS" -extensions v3_req -extfile "$CONFIG_FILE"

# Set appropriate permissions
chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY" "$CERTIFICATE"

# Clean up CSR file
rm -f "$CSR_FILE"

print_status "Verifying certificate..."
openssl x509 -in "$CERTIFICATE" -text -noout > /dev/null

# Calculate certificate fingerprints
SHA1_FINGERPRINT=$(openssl x509 -in "$CERTIFICATE" -fingerprint -sha1 -noout | cut -d= -f2)
SHA256_FINGERPRINT=$(openssl x509 -in "$CERTIFICATE" -fingerprint -sha256 -noout | cut -d= -f2)

# Extract certificate information
SUBJECT=$(openssl x509 -in "$CERTIFICATE" -subject -noout | sed 's/subject=//')
ISSUER=$(openssl x509 -in "$CERTIFICATE" -issuer -noout | sed 's/issuer=//')
NOT_BEFORE=$(openssl x509 -in "$CERTIFICATE" -startdate -noout | sed 's/notBefore=//')
NOT_AFTER=$(openssl x509 -in "$CERTIFICATE" -enddate -noout | sed 's/notAfter=//')

print_header "Certificate Generation Complete!"
print_header "================================"

echo ""
print_status "Generated Files:"
echo "  Private Key: $PRIVATE_KEY"
echo "  Public Key:  $PUBLIC_KEY"
echo "  Certificate: $CERTIFICATE"
echo "  Config File: $CONFIG_FILE"
echo ""

print_status "Certificate Information:"
echo "  Subject: $SUBJECT"
echo "  Issuer:  $ISSUER"
echo "  Valid From: $NOT_BEFORE"
echo "  Valid Until: $NOT_AFTER"
echo ""

print_status "Certificate Fingerprints:"
echo "  SHA1:   $SHA1_FINGERPRINT"
echo "  SHA256: $SHA256_FINGERPRINT"
echo ""

print_status "STIR/SHAKEN Configuration:"
echo "  SPC Token: $SPC_TOKEN"
echo "  OCN: $OCN"
echo "  Authorized Numbers: $TELEPHONE_NUMBERS"
echo ""

# Create a summary file
SUMMARY_FILE="$CERT_DIR/${CERT_NAME}-summary.txt"
cat > "$SUMMARY_FILE" << EOF
STIR/SHAKEN Test Certificate Summary
===================================
Generated: $(date)
Certificate Name: $CERT_NAME

Files:
- Private Key: ${CERT_NAME}.key
- Public Key:  ${CERT_NAME}.pub
- Certificate: ${CERT_NAME}.pem
- Config File: ../config/${CERT_NAME}.conf

Certificate Details:
- Subject: $SUBJECT
- Valid From: $NOT_BEFORE
- Valid Until: $NOT_AFTER
- SHA256 Fingerprint: $SHA256_FINGERPRINT

STIR/SHAKEN Details:
- SPC Token: $SPC_TOKEN
- OCN: $OCN
- Authorized Numbers: $TELEPHONE_NUMBERS

Usage in Ruby:
  StirShaken.configure do |config|
    config.private_key_path = '$PRIVATE_KEY'
    config.certificate_url = 'file://$CERTIFICATE'
  end

WARNING: This is a self-signed certificate for TESTING ONLY!
For production use, obtain certificates from an authorized STI-CA.
See CERT.md for production certificate instructions.
EOF

print_status "Certificate summary saved to: $SUMMARY_FILE"

print_warning "IMPORTANT SECURITY NOTICE:"
echo "  • This is a SELF-SIGNED certificate for TESTING ONLY"
echo "  • Do NOT use this certificate in production environments"
echo "  • For production, obtain certificates from an authorized STI-CA"
echo "  • See CERT.md for production certificate instructions"
echo ""

print_header "Next Steps:"
echo "  1. Review the generated certificate: openssl x509 -in $CERTIFICATE -text"
echo "  2. Test with the Ruby library using the generated files"
echo "  3. For production, follow the steps in CERT.md"
echo ""

print_status "Certificate generation completed successfully!" 