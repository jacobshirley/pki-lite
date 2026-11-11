#!/usr/bin/env bash
# Part of the OpenSSL corpus generator; run via ../generate.sh (needs AUDIT=<workdir>).
set -u
: "${AUDIT:?run via generate.sh}"
C=$AUDIT/corpus; K=$AUDIT/keys; W=$AUDIT/work/more; mkdir -p $W $C/{cms,p12,ocsp,ts}; cd $W
CA=$AUDIT/work/ca
# leaf certs for each key type (signed by CA for chain tests)
cat > leaf.cnf <<EOC
[req]
distinguished_name=dn
prompt=no
[dn]
CN=Leaf
[usr]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=emailProtection,clientAuth
subjectKeyIdentifier=hash
subjectAltName=email:leaf@example.com
EOC
for k in rsa ec256 ed25519; do
  openssl req -new -key $K/$k.pem -subj "/CN=Leaf $k" -out leaf_$k.csr 2>/dev/null
  openssl x509 -req -in leaf_$k.csr -CA $CA/ca.pem -CAkey $K/rsa.pem -CAcreateserial -days 30 -extfile leaf.cnf -extensions usr -out leaf_$k.pem 2>/dev/null || echo "GENFAIL leaf_$k"
done
echo "Hello, CMS world" > msg.txt; head -c 5000 /dev/urandom > big.bin; : > empty.txt
g() { local out=$1; shift; if "$@" 2>$W/err.txt; then :; else echo "GENFAIL $(basename $out): $(head -c 200 $W/err.txt | tr '\n' ' ')"; rm -f $out; fi; }
S="-signer leaf_rsa.pem -inkey $K/rsa.pem"
# ---- CMS SignedData
g $C/cms/sd_attached_rsa.der openssl cms -sign -in msg.txt $S -outform DER -binary -nodetach -out $C/cms/sd_attached_rsa.der
g $C/cms/sd_detached_rsa.der openssl cms -sign -in msg.txt $S -outform DER -binary -out $C/cms/sd_detached_rsa.der
g $C/cms/sd_noattr.der openssl cms -sign -in msg.txt $S -outform DER -noattr -nodetach -out $C/cms/sd_noattr.der
g $C/cms/sd_nocerts.der openssl cms -sign -in msg.txt $S -outform DER -nocerts -nodetach -out $C/cms/sd_nocerts.der
g $C/cms/sd_certfile_chain.der openssl cms -sign -in msg.txt $S -certfile $CA/ca.pem -outform DER -nodetach -out $C/cms/sd_certfile_chain.der
g $C/cms/sd_keyid.der openssl cms -sign -in msg.txt $S -keyid -outform DER -nodetach -out $C/cms/sd_keyid.der
g $C/cms/sd_ec.der openssl cms -sign -in msg.txt -signer leaf_ec256.pem -inkey $K/ec256.pem -outform DER -nodetach -out $C/cms/sd_ec.der
g $C/cms/sd_ed25519.der openssl cms -sign -in msg.txt -signer leaf_ed25519.pem -inkey $K/ed25519.pem -md sha512 -outform DER -nodetach -out $C/cms/sd_ed25519.der
g $C/cms/sd_pss.der openssl cms -sign -in msg.txt $S -keyopt rsa_padding_mode:pss -outform DER -nodetach -out $C/cms/sd_pss.der
g $C/cms/sd_sha512.der openssl cms -sign -in msg.txt $S -md sha512 -outform DER -nodetach -out $C/cms/sd_sha512.der
g $C/cms/sd_multi.der openssl cms -sign -in msg.txt $S -signer leaf_ec256.pem -inkey $K/ec256.pem -outform DER -nodetach -out $C/cms/sd_multi.der
g $C/cms/sd_stream_ber.der openssl cms -sign -in big.bin $S -outform DER -nodetach -stream -binary -out $C/cms/sd_stream_ber.der
g $C/cms/sd_empty_content.der openssl cms -sign -in empty.txt $S -outform DER -nodetach -binary -out $C/cms/sd_empty_content.der
g $C/cms/sd_big.der openssl cms -sign -in big.bin $S -outform DER -nodetach -binary -out $C/cms/sd_big.der
g $C/cms/sd_nosmimecap.der openssl cms -sign -in msg.txt $S -nosmimecap -outform DER -nodetach -out $C/cms/sd_nosmimecap.der
g $C/cms/sd_econtent_type.der openssl cms -sign -in msg.txt $S -econtent_type 1.2.3.4.5 -outform DER -nodetach -binary -out $C/cms/sd_econtent_type.der
g $C/cms/sd_certsonly.der openssl crl2pkcs7 -nocrl -certfile $CA/ca.pem -certfile leaf_rsa.pem -outform DER -out $C/cms/sd_certsonly.der
g $C/cms/sd_certs_crl.der openssl crl2pkcs7 -in $CA/crl_v1_entries.pem -certfile $CA/ca.pem -outform DER -out $C/cms/sd_certs_crl.der
g $C/cms/sd_resign.der openssl cms -resign -in $C/cms/sd_attached_rsa.der -inform DER -signer leaf_ec256.pem -inkey $K/ec256.pem -outform DER -out $C/cms/sd_resign.der
# ---- EnvelopedData / others
R="-recip leaf_rsa.pem"
g $C/cms/ed_rsa_aes256.der openssl cms -encrypt -in msg.txt $R -aes256 -outform DER -out $C/cms/ed_rsa_aes256.der
g $C/cms/ed_rsa_aes128.der openssl cms -encrypt -in msg.txt $R -aes128 -outform DER -out $C/cms/ed_rsa_aes128.der
g $C/cms/ed_rsa_3des.der openssl cms -encrypt -in msg.txt $R -des3 -outform DER -out $C/cms/ed_rsa_3des.der
g $C/cms/ed_rsa_gcm.der openssl cms -encrypt -in msg.txt $R -aes-256-gcm -outform DER -out $C/cms/ed_rsa_gcm.der
g $C/cms/ed_rsa_keyid.der openssl cms -encrypt -in msg.txt $R -keyid -aes256 -outform DER -out $C/cms/ed_rsa_keyid.der
g $C/cms/ed_rsa_oaep.der openssl cms -encrypt -in msg.txt $R -keyopt rsa_padding_mode:oaep -aes256 -outform DER -out $C/cms/ed_rsa_oaep.der
g $C/cms/ed_rsa_oaep_sha256.der openssl cms -encrypt -in msg.txt $R -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -aes256 -outform DER -out $C/cms/ed_rsa_oaep_sha256.der
g $C/cms/ed_ec_kari.der openssl cms -encrypt -in msg.txt -recip leaf_ec256.pem -aes256 -outform DER -out $C/cms/ed_ec_kari.der
g $C/cms/ed_multi.der openssl cms -encrypt -in msg.txt -recip leaf_rsa.pem -recip leaf_ec256.pem -aes256 -outform DER -out $C/cms/ed_multi.der
g $C/cms/ed_stream.der openssl cms -encrypt -in big.bin $R -aes256 -binary -stream -outform DER -out $C/cms/ed_stream.der
g $C/cms/ed_pwri.der openssl cms -encrypt -in msg.txt -pwri_password secretpw -aes256 -outform DER -out $C/cms/ed_pwri.der
g $C/cms/ed_kekri.der openssl cms -encrypt -in msg.txt -secretkey 000102030405060708090a0b0c0d0e0f -secretkeyid 01 -aes128 -outform DER -out $C/cms/ed_kekri.der
g $C/cms/ed_empty.der openssl cms -encrypt -in empty.txt $R -aes256 -binary -outform DER -out $C/cms/ed_empty.der
g $C/cms/encdata.der openssl cms -EncryptedData_encrypt -in msg.txt -secretkey 000102030405060708090a0b0c0d0e0f -aes128 -outform DER -out $C/cms/encdata.der
g $C/cms/digest.der openssl cms -digest_create -in msg.txt -md sha256 -outform DER -out $C/cms/digest.der
g $C/cms/authenveloped.der openssl cms -encrypt -in msg.txt $R -aes-256-gcm -outform DER -out $C/cms/authenveloped.der
# ---- PKCS12
P="-passout pass:pw"
g $C/p12/default.p12 openssl pkcs12 -export -inkey $K/rsa.pem -in leaf_rsa.pem $P -out $C/p12/default.p12
g $C/p12/chain.p12 openssl pkcs12 -export -inkey $K/rsa.pem -in leaf_rsa.pem -certfile $CA/ca.pem -name "Friendly Name" $P -out $C/p12/chain.p12
g $C/p12/ec.p12 openssl pkcs12 -export -inkey $K/ec256.pem -in leaf_ec256.pem $P -out $C/p12/ec.p12
g $C/p12/ed25519.p12 openssl pkcs12 -export -inkey $K/ed25519.pem -in leaf_ed25519.pem $P -out $C/p12/ed25519.p12
g $C/p12/legacy_3des.p12 openssl pkcs12 -export -inkey $K/rsa.pem -in leaf_rsa.pem -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 $P -out $C/p12/legacy_3des.p12
g $C/p12/nopass.p12 openssl pkcs12 -export -inkey $K/rsa.pem -in leaf_rsa.pem -passout pass: -out $C/p12/nopass.p12
g $C/p12/nomac.p12 openssl pkcs12 -export -inkey $K/rsa.pem -in leaf_rsa.pem -nomac $P -out $C/p12/nomac.p12
g $C/p12/nokeys.p12 openssl pkcs12 -export -nokeys -in leaf_rsa.pem -certfile $CA/ca.pem $P -out $C/p12/nokeys.p12
g $C/p12/nocerts.p12 openssl pkcs12 -export -nocerts -inkey $K/rsa.pem $P -out $C/p12/nocerts.p12
g $C/p12/aes256_sha512.p12 openssl pkcs12 -export -inkey $K/rsa.pem -in leaf_rsa.pem -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha512 $P -out $C/p12/aes256_sha512.p12
g $C/p12/iter1.p12 openssl pkcs12 -export -inkey $K/rsa.pem -in leaf_rsa.pem -iter 1 -macsaltlen 8 $P -out $C/p12/iter1.p12
g $C/p12/keypbe_none.p12 openssl pkcs12 -export -inkey $K/rsa.pem -in leaf_rsa.pem -keypbe NONE -certpbe NONE $P -out $C/p12/keypbe_none.p12
g $C/p12/localkeyid.p12 openssl pkcs12 -export -inkey $K/rsa.pem -in leaf_rsa.pem -name n -caname ca1 -caname ca2 -certfile $CA/ca.pem $P -out $C/p12/localkeyid.p12
# ---- OCSP
cp $CA/index.txt idx.txt; sed -i '/^R\t[0-9A-Z]*\t[0-9A-Z,a-zA-Z]*\t0[1-8]\t/!b' idx.txt
openssl ocsp -issuer $CA/ca.pem -cert $CA/r1.pem -reqout $C/ocsp/req_basic.der -no_nonce 2>/dev/null || echo GENFAIL req_basic
openssl ocsp -issuer $CA/ca.pem -cert $CA/r1.pem -reqout $C/ocsp/req_nonce.der 2>/dev/null
openssl ocsp -issuer $CA/ca.pem -cert $CA/r1.pem -cert $CA/r2.pem -cert $CA/r3.pem -reqout $C/ocsp/req_multi.der 2>/dev/null
openssl ocsp -issuer $CA/ca.pem -cert $CA/r1.pem -sha512 -no_nonce -reqout $C/ocsp/req_sha512.der 2>/dev/null
openssl ocsp -issuer $CA/ca.pem -serial 0x99 -reqout $C/ocsp/req_unknown_serial.der -no_nonce 2>/dev/null
openssl ocsp -issuer $CA/ca.pem -cert $CA/r1.pem -reqout $C/ocsp/req_signed.der -signer leaf_rsa.pem -signkey $K/rsa.pem 2>/dev/null || echo GENFAIL req_signed
# responses via index
resp() { name=$1; shift; openssl ocsp -index idx.txt -CA $CA/ca.pem -rsigner $CA/ca.pem -rkey $K/rsa.pem -reqin $1 -respout $C/ocsp/$name.der "${@:2}" >/dev/null 2>$W/err.txt || echo "GENFAIL $name $(head -c 150 $W/err.txt | tr '\n' ' ')"; }
resp resp_revoked $C/ocsp/req_basic.der
resp resp_nonce $C/ocsp/req_nonce.der
resp resp_multi $C/ocsp/req_multi.der
resp resp_unknown $C/ocsp/req_unknown_serial.der
resp resp_nextupdate $C/ocsp/req_basic.der -nmin 60
resp resp_ndays $C/ocsp/req_nonce.der -ndays 3 -resp_no_certs
resp resp_keyid $C/ocsp/req_nonce.der -resp_key_id
# good: issue a not-revoked cert
openssl req -new -key $K/ec256.pem -subj "/CN=Good" -out good.csr 2>/dev/null
cat > idx2.txt < /dev/null
echo -e "V\t261211124034Z\t\t0A\tunknown\t/CN=Good" >> idx2.txt
openssl x509 -req -in good.csr -CA $CA/ca.pem -CAkey $K/rsa.pem -set_serial 0x0A -days 30 -out good.pem 2>/dev/null
openssl ocsp -issuer $CA/ca.pem -cert good.pem -reqout good_req.der -no_nonce 2>/dev/null
openssl ocsp -index idx2.txt -CA $CA/ca.pem -rsigner $CA/ca.pem -rkey $K/rsa.pem -reqin good_req.der -respout $C/ocsp/resp_good.der >/dev/null 2>&1 || echo GENFAIL resp_good
# error responses by hand
printf '\x30\x03\x0a\x01\x01' > $C/ocsp/resp_malformed_request.der
printf '\x30\x03\x0a\x01\x02' > $C/ocsp/resp_internal_error.der
printf '\x30\x03\x0a\x01\x03' > $C/ocsp/resp_try_later.der
printf '\x30\x03\x0a\x01\x05' > $C/ocsp/resp_sig_required.der
printf '\x30\x03\x0a\x01\x06' > $C/ocsp/resp_unauthorized.der
ls $C/cms | wc -l; ls $C/p12 | wc -l; ls $C/ocsp | wc -l
