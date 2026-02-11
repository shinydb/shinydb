#!/bin/bash
# Generate self-signed certificates for TLS testing
# Usage: ./scripts/generate_test_certs.sh

set -e

CERT_DIR="data/certs"
DAYS_VALID=365

echo "=== ShinyDB TLS Certificate Generator ==="
echo ""

# Create directory
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Generate private key
echo "[1/3] Generating private key..."
openssl genrsa -out server.key 4096 2>/dev/null

# Generate certificate signing request
echo "[2/3] Generating certificate signing request..."
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=ShinyDB/CN=localhost" 2>/dev/null

# Generate self-signed certificate
echo "[3/3] Generating self-signed certificate..."
openssl x509 -req -days $DAYS_VALID \
  -in server.csr -signkey server.key -out server.crt 2>/dev/null

# Clean up CSR
rm server.csr

# Set permissions
chmod 600 server.key
chmod 644 server.crt

echo ""
echo "✓ Certificates generated successfully!"
echo ""
echo "Files created:"
echo "  - $(pwd)/server.key (private key)"
echo "  - $(pwd)/server.crt (certificate)"
echo ""
echo "Valid for: $DAYS_VALID days"
echo ""
echo "To use in config.yaml:"
echo ""
echo "  tls:"
echo "    enabled: true"
echo "    cert_file: \"$(pwd)/server.crt\""
echo "    key_file: \"$(pwd)/server.key\""
echo ""
echo "⚠️  WARNING: These are self-signed certificates for TESTING only!"
echo "    DO NOT use in production. Get proper certificates from a CA."
echo ""

# Display certificate info
echo "Certificate details:"
openssl x509 -in server.crt -noout -text | grep -A 2 "Subject:"
openssl x509 -in server.crt -noout -text | grep -A 2 "Validity"
echo ""
