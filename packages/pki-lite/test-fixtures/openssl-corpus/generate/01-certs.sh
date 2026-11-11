#!/usr/bin/env bash
# Part of the OpenSSL corpus generator; run via ../generate.sh (needs AUDIT=<workdir>).
set -u
: "${AUDIT:?run via generate.sh}"
# Generates a corpus of valid X.509 certificates with openssl. Output: $AUDIT/corpus/cert/*.der
O=$AUDIT/corpus/cert; K=$AUDIT/keys; mkdir -p $O $K; cd $K
[ -f rsa.pem ] || openssl genrsa -out rsa.pem 2048 2>/dev/null
[ -f ec256.pem ] || openssl ecparam -name prime256v1 -genkey -noout -out ec256.pem
[ -f ec384.pem ] || openssl ecparam -name secp384r1 -genkey -noout -out ec384.pem
[ -f ec521.pem ] || openssl ecparam -name secp521r1 -genkey -noout -out ec521.pem
[ -f ed25519.pem ] || openssl genpkey -algorithm ed25519 -out ed25519.pem
[ -f ed448.pem ] || openssl genpkey -algorithm ed448 -out ed448.pem
[ -f rsapss.pem ] || openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out rsapss.pem 2>/dev/null
n=0
mk() { # name key subj [extra openssl args...]
  local name=$1 key=$2 subj=$3; shift 3
  if openssl req -x509 -new -key $K/$key.pem -subj "$subj" -days 30 -noenc "$@" -outform DER -out $O/$name.der 2>$O/$name.err; then rm -f $O/$name.err; n=$((n+1)); else echo "GENFAIL $name: $(head -c 200 $O/$name.err)"; rm -f $O/$name.der; fi
}
S="/CN=Test"
# --- keys / signature algorithms
for k in rsa ec256 ec384 ec521 ed25519 ed448; do mk key_$k $k "$S" ; done
mk key_rsapss rsapss "$S"
mk sig_sha512_rsa rsa "$S" -sha512
mk sig_sha1_rsa rsa "$S" -sha1
mk sig_pss rsa "$S" -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32
mk sig_ec384 ec384 "$S" -sha384
# --- basicConstraints variants
mk bc_false rsa "$S" -addext basicConstraints=CA:FALSE
mk bc_true rsa "$S" -addext basicConstraints=CA:TRUE
mk bc_crit_true rsa "$S" -addext basicConstraints=critical,CA:TRUE
mk bc_pathlen0 rsa "$S" -addext basicConstraints=CA:TRUE,pathlen:0
mk bc_pathlen5 rsa "$S" -addext basicConstraints=critical,CA:TRUE,pathlen:5
mk bc_false_crit rsa "$S" -addext basicConstraints=critical,CA:FALSE
# --- key usage
for ku in digitalSignature nonRepudiation keyEncipherment dataEncipherment keyAgreement keyCertSign cRLSign encipherOnly,keyAgreement decipherOnly,keyAgreement "digitalSignature,keyCertSign,cRLSign" "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign,encipherOnly,decipherOnly"; do
  mk "ku_$(echo $ku | tr ',' '_')" rsa "$S" -addext "keyUsage=critical,$ku"; done
# --- extended key usage
mk eku_server rsa "$S" -addext extendedKeyUsage=serverAuth
mk eku_many rsa "$S" -addext extendedKeyUsage=serverAuth,clientAuth,codeSigning,emailProtection,timeStamping,OCSPSigning,1.2.3.4.5.6
mk eku_any rsa "$S" -addext extendedKeyUsage=critical,anyExtendedKeyUsage
# --- SAN variants
mk san_dns rsa "$S" -addext subjectAltName=DNS:example.com
cat > $K/san.cnf <<EOC
[req]
distinguished_name=dn
x509_extensions=v3
prompt=no
[dn]
CN=Test
[v3]
subjectAltName=@alt
[alt]
DNS.1=a.example.com
DNS.2=*.example.com
email.1=a@example.com
URI.1=https://example.com/p?q=1
IP.1=192.0.2.1
IP.2=2001:db8::1
RID.1=1.2.3.4
dirName.1=dnsect
otherName.1=1.2.3.4;UTF8:other
otherName.2=1.3.6.1.4.1.311.20.2.3;UTF8:user@example.com
[dnsect]
C=GB
O=Org
CN=Alt Name
EOC
openssl req -x509 -new -key rsa.pem -config san.cnf -days 30 -outform DER -out $O/san_all.der 2>/dev/null && n=$((n+1)) || echo GENFAIL san_all
mk san_critical_emptysubj rsa "/" -addext subjectAltName=critical,DNS:only.example.com
mk san_ip_only rsa "$S" -addext subjectAltName=IP:10.0.0.1
mk ian rsa "$S" -addext issuerAltName=DNS:issuer.example.com,email:i@example.com
# --- identifiers
mk skid_hash rsa "$S" -addext subjectKeyIdentifier=hash
mk akid_keyid rsa "$S" -addext subjectKeyIdentifier=hash -addext authorityKeyIdentifier=keyid
mk akid_keyid_issuer rsa "$S" -addext subjectKeyIdentifier=hash -addext authorityKeyIdentifier=keyid,issuer:always
mk akid_issuer_only rsa "$S" -addext authorityKeyIdentifier=issuer:always
# --- constraints / policies
mk nc_permitted rsa "$S" -addext basicConstraints=CA:TRUE -addext "nameConstraints=critical,permitted;DNS:example.com,permitted;email:example.com,permitted;IP:192.168.0.0/255.255.0.0"
mk nc_excluded rsa "$S" -addext basicConstraints=CA:TRUE -addext "nameConstraints=excluded;DNS:bad.example.com,excluded;URI:.bad.example.com"
mk nc_both rsa "$S" -addext basicConstraints=CA:TRUE -addext "nameConstraints=permitted;DNS:ok.example.com,excluded;DNS:bad.ok.example.com"
mk pc_require rsa "$S" -addext basicConstraints=CA:TRUE -addext policyConstraints=requireExplicitPolicy:0
mk pc_inhibit rsa "$S" -addext basicConstraints=CA:TRUE -addext policyConstraints=inhibitPolicyMapping:2
mk pc_both rsa "$S" -addext basicConstraints=CA:TRUE -addext policyConstraints=requireExplicitPolicy:1,inhibitPolicyMapping:3
mk inhibit_any rsa "$S" -addext basicConstraints=CA:TRUE -addext inhibitAnyPolicy=critical,0
mk policies_oid rsa "$S" -addext certificatePolicies=1.2.3.4
mk policies_any rsa "$S" -addext certificatePolicies=anyPolicy
cat > $K/pol.cnf <<EOC
[req]
distinguished_name=dn
x509_extensions=v3
prompt=no
[dn]
CN=Test
[v3]
certificatePolicies=ia5org,1.2.3.4,1.2.3.5,@pol2
[pol2]
policyIdentifier=1.2.3.6
CPS.1=https://example.com/cps
userNotice.1=@notice
[notice]
explicitText=Explicit text
organization=Org
noticeNumbers=1,2,3
EOC
openssl req -x509 -new -key rsa.pem -config pol.cnf -days 30 -outform DER -out $O/policies_full.der 2>/dev/null && n=$((n+1)) || echo GENFAIL policies_full
mk policy_mappings rsa "$S" -addext basicConstraints=CA:TRUE -addext policyMappings=1.2.3.4:1.2.3.5,1.2.3.6:1.2.3.7
# --- distribution points / access
mk crldp_uri rsa "$S" -addext crlDistributionPoints=URI:http://example.com/a.crl
mk crldp_multi rsa "$S" -addext "crlDistributionPoints=URI:http://example.com/a.crl,URI:http://example.com/b.crl"
mk aia_ocsp rsa "$S" -addext authorityInfoAccess=OCSP\;URI:http://ocsp.example.com
mk aia_both rsa "$S" -addext "authorityInfoAccess=OCSP;URI:http://ocsp.example.com,caIssuers;URI:http://example.com/ca.der"
mk sia rsa "$S" -addext "subjectInfoAccess=caRepository;URI:http://example.com/repo"
mk freshest rsa "$S" -addext freshestCRL=URI:http://example.com/d.crl
mk idp rsa "$S" -addext issuingDistributionPoint=critical,onlyuser:TRUE 2>/dev/null
# --- misc extensions
mk nocheck rsa "$S" -addext noCheck=ocsp-nocheck 2>/dev/null
mk tlsfeature rsa "$S" -addext tlsfeature=status_request
mk netscape rsa "$S" -addext nsCertType=client,server,email,objsign,sslCA,emailCA,objCA -addext nsComment="a comment" -addext nsBaseUrl=http://example.com/
mk sct_poison rsa "$S" -addext 1.3.6.1.4.1.11129.2.4.3=critical,ASN1:NULL
mk many_ext rsa "$S" -addext basicConstraints=critical,CA:TRUE,pathlen:2 -addext keyUsage=critical,keyCertSign,cRLSign -addext subjectKeyIdentifier=hash -addext authorityKeyIdentifier=keyid:always -addext subjectAltName=DNS:a.example.com -addext extendedKeyUsage=serverAuth
echo "generated $n certs"
