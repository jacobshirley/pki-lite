# Generate CA key and certificate
#
# This script generates a CA key and certificate, along with a signer key and certificate.
# It also creates an OCSP responder certificate and response.
# All outputs are converted to PEM format and a TypeScript file is generated with the PEM contents.
#
# Usage:
#   ./gen.sh --output-dir=./output [options]
#
# Examples:
#   ./gen.sh --output-dir=./output                             # Generate RSA keys with default settings
#   ./gen.sh --output-dir=./output --key-type=ec --key-size=p256   # Generate EC keys with P-256 curve
#   ./gen.sh --output-dir=./output --key-type=ed25519              # Generate ED25519 keys

# Default values
KEY_TYPE="rsa"
KEY_SIZE="2048"
EXPORT_PREFIX="rsa"
CA_KEY_SIZE="4096"
OUTPUT_DIR=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --key-type=*)
      KEY_TYPE="${1#*=}"
      shift
      ;;
    --key-size=*)
      KEY_SIZE="${1#*=}"
      shift
      ;;
    --ca-key-size=*)
      CA_KEY_SIZE="${1#*=}"
      shift
      ;;
    --output-dir=*)
      OUTPUT_DIR="${1#*=}"
      shift
      ;;
    --help)
      echo "Usage: $0 [options]"
      echo "Options:"
      echo "  --key-type=TYPE    Key type to generate (rsa, ec, ed25519) [default: rsa]"
      echo "  --key-size=SIZE    Key size for RSA or curve for EC (p256, p384, p521) [default: 2048 for RSA, p256 for EC]"
      echo "  --ca-key-size=SIZE Size for CA key [default: 4096 for RSA]"
      echo "  --output-dir=DIR   Output directory [REQUIRED]"
      echo "  --help             Show this help message and exit"
      exit 0
      ;;
    *)
      echo "Unknown parameter: $1"
      exit 1
      ;;
  esac
done

# Validate required parameters
if [ -z "$OUTPUT_DIR" ]; then
  echo "Error: --output-dir parameter is required"
  echo "Run '$0 --help' for usage information"
  exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR" || exit 1

# Create demoCA directory if it doesn't exist
mkdir -p demoCA
touch demoCA/index.txt
echo "01" > demoCA/serial
echo "01" > demoCA/crlnumber

# Set export prefix for TypeScript variable naming
if [ "$KEY_TYPE" == "ec" ]; then
  if [ "$KEY_SIZE" == "p256" ] || [ "$KEY_SIZE" == "prime256v1" ]; then
    EXPORT_PREFIX="ecP256"
  elif [ "$KEY_SIZE" == "p384" ] || [ "$KEY_SIZE" == "secp384r1" ]; then
    EXPORT_PREFIX="ecP384"
  elif [ "$KEY_SIZE" == "p521" ] || [ "$KEY_SIZE" == "secp521r1" ]; then
    EXPORT_PREFIX="ecP521"
  else
    EXPORT_PREFIX="ec"
  fi
elif [ "$KEY_TYPE" == "ed25519" ]; then
  EXPORT_PREFIX="ed25519"
else
  EXPORT_PREFIX="rsa"
fi

echo "Generating $KEY_TYPE keys with size/curve $KEY_SIZE..."

# Generate CA key and certificate
if [ "$KEY_TYPE" == "rsa" ]; then
  openssl genrsa -out rootCA.key $CA_KEY_SIZE
  openssl genrsa -out signer.key $KEY_SIZE
elif [ "$KEY_TYPE" == "ec" ]; then
  # Map p256, p384, p521 to proper curve names
  CURVE="$KEY_SIZE"
  if [ "$KEY_SIZE" == "p256" ]; then
    CURVE="prime256v1"
  elif [ "$KEY_SIZE" == "p384" ]; then
    CURVE="secp384r1"
  elif [ "$KEY_SIZE" == "p521" ]; then
    CURVE="secp521r1"
  fi
  
  # Generate EC keys in PKCS#8 format for compatibility with PrivateKeyInfo
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$CURVE -out rootCA.key
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$CURVE -out signer.key
elif [ "$KEY_TYPE" == "ed25519" ]; then
  openssl genpkey -algorithm ed25519 -out rootCA.key
  openssl genpkey -algorithm ed25519 -out signer.key
else
  echo "Unsupported key type: $KEY_TYPE"
  exit 1
fi

echo """
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation
extendedKeyUsage = emailProtection, codeSigning
crlDistributionPoints = URI:http://localhost:8080/ca.crl
authorityInfoAccess = @aia_info

[ aia_info ]
caIssuers;URI.0 = http://localhost:8080/ca.crt
OCSP;URI.0 = http://localhost:8080/ocsp
OCSP;URI.1 = http://localhost:8080/ocsp-backup
""" > cert-ext.cnf

# Generate certificates
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.crt -subj "/C=US/ST=Test/L=Local/O=MyOrg/OU=CA/CN=MyRootCA"
openssl req -new -key signer.key -out signer.csr -subj "/C=US/ST=Test/L=Local/O=MyOrg/OU=Signing/CN=John Doe"
openssl x509 -req -in signer.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out signer.crt -days 365 -sha256 -extfile cert-ext.cnf

# Create OCSP responder certificate
if [ "$KEY_TYPE" == "rsa" ]; then
  openssl genrsa -out ocsp.key 2048
elif [ "$KEY_TYPE" == "ec" ]; then
  # Generate EC key in PKCS#8 format for compatibility with PrivateKeyInfo
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$CURVE -out ocsp.key
elif [ "$KEY_TYPE" == "ed25519" ]; then
  openssl genpkey -algorithm ed25519 -out ocsp.key
fi

echo """
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = OCSPSigning
""" > ocsp-ext.cnf

openssl req -new -key ocsp.key -out ocsp.csr -subj "/C=US/ST=Test/L=Local/O=MyOrg/OU=OCSP/CN=OCSP Responder"
openssl x509 -req -in ocsp.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
  -out ocsp.crt -days 10000 -sha256 -extfile ocsp-ext.cnf

# Get CRL from CA
openssl ca -gencrl -keyfile rootCA.key -cert rootCA.crt -out ca.crl

# create an OCSP request for signer.crt
openssl ocsp \
  -issuer rootCA.crt \
  -cert signer.crt \
  -reqout ocsp.req

printf 'V\t360101000000Z\t76E6504D08122D5D3EA3A4A6D540BE38D1B1FB99\tunknown\t/C=US/ST=Test/L=Local/O=MyOrg/OU=Signing/CN=John Doe' > demoCA/index.txt

# create OCSP response: use the responder key (ocsp.key) and the CA index file
openssl ocsp \
  -reqin ocsp.req \
  -index "$(pwd)/demoCA/index.txt" \
  -CA rootCA.crt \
  -rsigner ocsp.crt \
  -rkey ocsp.key \
  -respout ocsp-response.der \
  -text

# Convert DER to PEM format
echo "Converting files to PEM format..."

# Convert CRL to PEM format (if not already in PEM)
openssl crl -inform DER -in ca.crl -outform PEM -out ca.pem 2>/dev/null || cp ca.crl ca.pem

# Convert OCSP response to PEM format
openssl base64 -in ocsp-response.der -out ocsp-response-base64.tmp
echo "-----BEGIN OCSP RESPONSE-----" > ocsp-response.pem
cat ocsp-response-base64.tmp >> ocsp-response.pem
echo "-----END OCSP RESPONSE-----" >> ocsp-response.pem
rm ocsp-response-base64.tmp

# Create combined PEM files for easier use
cat signer.crt rootCA.crt > cert-chain.pem
cat signer.key signer.crt rootCA.crt > fullchain.pem

echo "PEM conversion complete. Generated files:"
echo "- ca.pem (CRL in PEM format)"
echo "- ocsp-response.pem (OCSP response in PEM format)"
echo "- cert-chain.pem (Certificate chain)"
echo "- fullchain.pem (Private key + certificate chain)"

# Generate TypeScript file with all PEM contents
echo "Generating TypeScript file..."

# Function to get PEM content as is, preserving line breaks
get_pem_content() {
    cat "$1" | sed 's/\\/\\\\/g' | sed 's/`/\\`/g' | sed 's/\$/\\$/g'
}

# Get the PEM strings
PRIVATE_KEY=$(get_pem_content signer.key)
CERT=$(get_pem_content signer.crt)
CA_CERT=$(get_pem_content rootCA.crt)
CA_CRL=$(get_pem_content ca.pem)
OCSP_RESPONSE=$(get_pem_content ocsp-response.pem)

# Get base64 of the binary file (ocsp-response.der)
OCSP_RESPONSE_BASE64=$(cat ocsp-response.der | base64)

# Set variable names based on key type
if [ "$KEY_TYPE" == "rsa" ]; then
  KEY_VAR="${EXPORT_PREFIX}PrivateKeyPem"
elif [ "$KEY_TYPE" == "ec" ]; then
  KEY_VAR="${EXPORT_PREFIX}PrivateKeyPem"
elif [ "$KEY_TYPE" == "ed25519" ]; then
  KEY_VAR="${EXPORT_PREFIX}PrivateKeyPem"
else
  KEY_VAR="privateKeyPem"
fi

CERT_VAR="${EXPORT_PREFIX}Cert"
CA_CERT_VAR="${EXPORT_PREFIX}CaCert"
CA_CRL_VAR="${EXPORT_PREFIX}CaCrl"
OCSP_RESPONSE_VAR="${EXPORT_PREFIX}OcspResponse"
EXPORT_NAME="${EXPORT_PREFIX}SigningKeys"

# Create the TypeScript file
cat > "index.ts" << EOL
const ${KEY_VAR} = \`${PRIVATE_KEY}\`

const ${CERT_VAR} = \`${CERT}\`

const ${CA_CERT_VAR} = \`${CA_CERT}\`

const ${CA_CRL_VAR} = \`${CA_CRL}\`

const ${OCSP_RESPONSE_VAR} = \`${OCSP_RESPONSE}\`

function pemToUint8Array(pem: string | Uint8Array): Uint8Array {
    pem = typeof pem === 'string' ? pem : new TextDecoder().decode(pem)

    // Remove all headers, footers, and whitespace
    const b64 = pem
        .trim()
        .replace(/-----BEGIN [^-]+-----/, '')
        .replace(/-----END [^-]+-----/, '')
        .replace(/\s+/g, '')

    const binary = atob(b64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i)
    }

    return bytes
}

export const ${EXPORT_NAME} = {
    privateKey: pemToUint8Array(${KEY_VAR}),
    cert: pemToUint8Array(${CERT_VAR}),
    caCert: pemToUint8Array(${CA_CERT_VAR}),
    caCrl: pemToUint8Array(${CA_CRL_VAR}),
    ocspResponse: pemToUint8Array(${OCSP_RESPONSE_VAR}),
    privateKeyPem: ${KEY_VAR},
    certPem: ${CERT_VAR},
    caCertPem: ${CA_CERT_VAR},
    caCrlPem: ${CA_CRL_VAR},
    ocspResponsePem: ${OCSP_RESPONSE_VAR}
}
EOL

echo "TypeScript file (index.ts) generated successfully!"

# Clean up non-essential files
echo "Cleaning up temporary files..."
find . -type f -not -name "gen.sh" -not -name "index.ts" -delete
# Delete empty directories
find . -type d -empty -delete

echo "All done!"
