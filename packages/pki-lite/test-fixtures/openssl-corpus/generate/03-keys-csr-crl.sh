#!/usr/bin/env bash
# Part of the OpenSSL corpus generator; run via ../generate.sh (needs AUDIT=<workdir>).
set -u
: "${AUDIT:?run via generate.sh}"
C=$AUDIT/corpus; K=$AUDIT/keys; W=$AUDIT/work; mkdir -p $C/{key,crl,csr,cms,p12,ocsp,ts} $W; cd $W
ok(){ echo -n; }
g() { local out=$1; shift; if "$@" >/dev/null 2>$W/err.txt; then :; else echo "GENFAIL $out: $(head -c 200 $W/err.txt | tr '\n' ' ')"; rm -f $out; fi; }
[ -f x25519.pem ] || openssl genpkey -algorithm x25519 -out x25519.pem
[ -f rsa4096.pem ] || openssl genrsa -out rsa4096.pem 3072 2>/dev/null
[ -f rsa512ex.pem ] || openssl genrsa -3 -out rsa512ex.pem 2048 2>/dev/null   # public exponent 3
# ---------------- KEYS ----------------
for k in rsa ec256 ec384 ec521 ed25519 ed448 rsapss; do
  g $C/key/pkcs8_$k.der openssl pkcs8 -topk8 -nocrypt -in $K/$k.pem -outform DER -out $C/key/pkcs8_$k.der
  g $C/key/spki_$k.der openssl pkey -in $K/$k.pem -pubout -outform DER -out $C/key/spki_$k.der
done
g $C/key/pkcs8_x25519.der openssl pkcs8 -topk8 -nocrypt -in x25519.pem -outform DER -out $C/key/pkcs8_x25519.der
g $C/key/spki_x25519.der openssl pkey -in x25519.pem -pubout -outform DER -out $C/key/spki_x25519.der
g $C/key/pkcs8_rsa3072.der openssl pkcs8 -topk8 -nocrypt -in rsa4096.pem -outform DER -out $C/key/pkcs8_rsa3072.der
g $C/key/pkcs8_rsa_e3.der openssl pkcs8 -topk8 -nocrypt -in rsa512ex.pem -outform DER -out $C/key/pkcs8_rsa_e3.der
g $C/key/rsaprivate_traditional.der openssl rsa -in $K/rsa.pem -traditional -outform DER -out $C/key/rsaprivate_traditional.der
g $C/key/rsapublic_pkcs1.der openssl rsa -in $K/rsa.pem -RSAPublicKey_out -outform DER -out $C/key/rsapublic_pkcs1.der
g $C/key/ecprivate_256.der openssl ec -in $K/ec256.pem -outform DER -out $C/key/ecprivate_256.der
g $C/key/ecprivate_384.der openssl ec -in $K/ec384.pem -outform DER -out $C/key/ecprivate_384.der
g $C/key/ecprivate_521.der openssl ec -in $K/ec521.pem -outform DER -out $C/key/ecprivate_521.der
g $C/key/ecprivate_nopub.der openssl ec -in $K/ec256.pem -no_public -outform DER -out $C/key/ecprivate_nopub.der
g $C/key/ecprivate_noparams.der openssl ec -in $K/ec256.pem -param_enc explicit -outform DER -out $C/key/ecprivate_explicitparams.der
g $C/key/ecpubkey_compressed.der openssl ec -in $K/ec256.pem -pubout -conv_form compressed -outform DER -out $C/key/spki_ec256_compressed.der
# encrypted pkcs8
openssl pkcs8 -topk8 -in $K/rsa.pem -passout pass:pw -v2 aes-256-cbc -outform DER -out $C/key/enc_pbes2_aes256_sha256.der 2>/dev/null
openssl pkcs8 -topk8 -in $K/rsa.pem -passout pass:pw -v2 aes-128-cbc -v2prf hmacWithSHA512 -outform DER -out $C/key/enc_pbes2_aes128_sha512.der 2>/dev/null
openssl pkcs8 -topk8 -in $K/rsa.pem -passout pass:pw -scrypt -outform DER -out $C/key/enc_scrypt.der 2>/dev/null
openssl pkcs8 -topk8 -in $K/ec256.pem -passout pass:pw -v2 aes-256-gcm -outform DER -out $C/key/enc_pbes2_gcm.der 2>/dev/null || true
openssl pkcs8 -topk8 -in $K/rsa.pem -passout pass:pw -v2 des3 -iter 1 -outform DER -out $C/key/enc_pbes2_3des_iter1.der 2>/dev/null
openssl pkcs8 -topk8 -in $K/rsa.pem -passout pass:pw -v1 PBE-SHA1-3DES -outform DER -out $C/key/enc_pbes1_3des.der 2>/dev/null
openssl pkcs8 -topk8 -in $K/rsa.pem -passout pass:pw -v2 aes-256-cbc -iter 1000000 -outform DER -out $C/key/enc_pbes2_bigiter.der 2>/dev/null
# ECDSA signatures (DER)
echo hello > msg.txt
for k in ec256 ec384 ec521; do openssl dgst -sha256 -sign $K/$k.pem -out $C/key/ecdsa_sig_$k.der msg.txt 2>/dev/null; done
# ---------------- CSR ----------------
cat > csr_attr.cnf <<EOC
[req]
distinguished_name=dn
attributes=attrs
req_extensions=exts
prompt=no
[dn]
CN=CSR Test
O=Org
[attrs]
challengePassword=secret
unstructuredName=unstructured
[exts]
subjectAltName=DNS:csr.example.com
basicConstraints=CA:FALSE
keyUsage=digitalSignature
EOC
for k in rsa ec256 ed25519; do g $C/csr/csr_plain_$k.der openssl req -new -key $K/$k.pem -subj "/CN=CSR $k" -outform DER -out $C/csr/csr_plain_$k.der; done
g $C/csr/csr_attrs.der openssl req -new -key $K/rsa.pem -config csr_attr.cnf -outform DER -out $C/csr/csr_attrs.der
g $C/csr/csr_ext_only.der openssl req -new -key $K/rsa.pem -subj "/CN=X" -addext subjectAltName=DNS:a.example,IP:10.0.0.1 -outform DER -out $C/csr/csr_ext_only.der
g $C/csr/csr_empty_subject.der openssl req -new -key $K/ec256.pem -subj "/" -addext subjectAltName=DNS:a.example -outform DER -out $C/csr/csr_empty_subject.der
g $C/csr/csr_pss.der openssl req -new -key $K/rsa.pem -subj "/CN=PSS" -sha256 -sigopt rsa_padding_mode:pss -outform DER -out $C/csr/csr_pss.der
g $C/csr/csr_sha512.der openssl req -new -key $K/ec384.pem -subj "/CN=E384" -sha512 -outform DER -out $C/csr/csr_sha512.der
# ---------------- CA + CRL ----------------
rm -rf ca && mkdir -p ca && cd ca && mkdir -p newcerts && : > index.txt && echo 01 > serial && echo 01 > crlnumber
cat > ca.cnf <<EOC
[ca]
default_ca=CA_default
[CA_default]
dir=.
database=index.txt
new_certs_dir=newcerts
serial=serial
crlnumber=crlnumber
default_md=sha256
default_days=30
default_crl_days=7
policy=pol
unique_subject=no
[pol]
commonName=supplied
[req]
distinguished_name=dn
prompt=no
[dn]
CN=Test CA
[v3_ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
[usr]
basicConstraints=CA:FALSE
[crl_ext_v2]
authorityKeyIdentifier=keyid:always
issuerAltName=issuer:copy
[crl_ext_idp]
authorityKeyIdentifier=keyid:always,issuer:always
issuingDistributionPoint=critical,@idp
[idp]
fullname=URI:http://example.com/ca.crl
onlyuser=TRUE
EOC
openssl req -x509 -new -key $K/rsa.pem -config ca.cnf -extensions v3_ca -days 365 -out ca.pem 2>/dev/null
sed -i "s#^\[CA_default\]#[CA_default]\ncertificate=ca.pem\nprivate_key=$K/rsa.pem#" ca.cnf
# CRLs: v1 and v2, with/without entries, with an IDP, GeneralizedTime dates
mkcrl() { name=$1; ext=$2; shift 2; sed "s/^\[CA_default\]/[CA_default]\ncrl_extensions=$ext/" ca.cnf > ca_$name.cnf; [ "$ext" = none ] && cp ca.cnf ca_$name.cnf; openssl ca -config ca_$name.cnf -gencrl "$@" -out $name.pem 2>/dev/null; openssl crl -in $name.pem -outform DER -out $C/crl/$name.der || echo "GENFAIL $name"; }
# empty CRLs come from a fresh database (no revokedCertificates field at all)
mkdir -p e && (cd e && : > index.txt && echo 01 > serial && echo 01 > crlnumber && mkdir -p newcerts && cp ../ca.pem . && cp ../ca.cnf ca.cnf \
  && openssl ca -config ca.cnf -gencrl -out ../crl_empty_v1.pem 2>/dev/null \
  && sed "s/^\[CA_default\]/[CA_default]\ncrl_extensions=crl_ext_v2/" ca.cnf > ca2.cnf && openssl ca -config ca2.cnf -gencrl -out ../crl_empty_v2.pem 2>/dev/null)
openssl crl -in crl_empty_v1.pem -outform DER -out $C/crl/crl_empty_v1.der; openssl crl -in crl_empty_v2.pem -outform DER -out $C/crl/crl_empty_v2.der
# issue certs, revoke with various reasons
for i in 1 2 3 4 5 6 7 8; do
  openssl req -new -key $K/ec256.pem -subj "/CN=Revoke $i" -out r$i.csr 2>/dev/null
  openssl ca -config ca.cnf -batch -in r$i.csr -extensions usr -out r$i.pem -notext 2>/dev/null
done
openssl ca -config ca.cnf -revoke r1.pem 2>/dev/null
openssl ca -config ca.cnf -revoke r2.pem -crl_reason keyCompromise 2>/dev/null
openssl ca -config ca.cnf -revoke r3.pem -crl_reason CACompromise 2>/dev/null
openssl ca -config ca.cnf -revoke r4.pem -crl_reason certificateHold 2>/dev/null
openssl ca -config ca.cnf -revoke r5.pem -crl_reason removeFromCRL 2>/dev/null
openssl ca -config ca.cnf -revoke r6.pem -crl_compromise 20240101000000Z 2>/dev/null
openssl ca -config ca.cnf -revoke r7.pem -crl_reason affiliationChanged 2>/dev/null
openssl ca -config ca.cnf -revoke r8.pem -crl_reason unspecified 2>/dev/null
mkcrl crl_v1_entries none
mkcrl crl_v2_entries crl_ext_v2
mkcrl crl_v2_idp crl_ext_idp
mkcrl crl_gentime crl_ext_v2 -crl_lastupdate 20500101000000Z -crl_nextupdate 20600101000000Z
mkcrl crl_dates crl_ext_v2 -crl_lastupdate 20240101000000Z -crl_nextupdate 20240201000000Z
cd ..
