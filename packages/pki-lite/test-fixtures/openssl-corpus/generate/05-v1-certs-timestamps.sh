#!/usr/bin/env bash
# Part of the OpenSSL corpus generator; run via ../generate.sh (needs AUDIT=<workdir>).
# X.509 v1 certificates and RFC 3161 time-stamping (queries, replies, tokens).
set -u
: "${AUDIT:?run via generate.sh}"
C=$AUDIT/corpus; K=$AUDIT/keys; W=$AUDIT/work/v1ts; mkdir -p $W $C/{cert,ts}; cd $W
CA=$AUDIT/work/ca
g() { local out=$1; shift; if "$@" 2>$W/err.txt; then :; else echo "GENFAIL $(basename $out): $(head -c 200 $W/err.txt | tr '\n' ' ')"; rm -f $out; fi; }

# ---- X.509 v1 certificates
# OpenSSL 3 only writes v3 certificates, so take the TBSCertificate of an extension-less
# v3 one, drop its version field ([0] INTEGER 2 -> absent, i.e. v1), sign that with
# `openssl dgst` and assemble the certificate. Every byte is still OpenSSL's.
hex() { xxd -p "$1" | tr -d '\n'; }
der_len() { # length in DER, hex
  local n=$1
  if ((n < 128)); then printf '%02x' $n
  elif ((n < 256)); then printf '81%02x' $n
  else printf '82%04x' $n; fi
}
tlv() { printf '%s%s%s' "$1" "$(der_len $((${#2} / 2)))" "$2"; } # tag hex-content
skip_tlv() { # hex -> length in hex chars of its first TLV
  local h=$1 l=$((16#${1:2:2}))
  if ((l < 128)); then echo $((4 + l * 2))
  else local nb=$((l & 127)); echo $((4 + nb * 2 + 16#${h:4:$((nb * 2))} * 2)); fi
}
content() { # hex of a TLV -> its content
  local h=$1 l=$((16#${1:2:2}))
  if ((l < 128)); then echo "${h:4}"; else echo "${h:$((4 + (l & 127) * 2))}"; fi
}
v1cert() { # name key digest [extra openssl req args...]: a self-signed v1 certificate
  local name=$1 key=$2 md=$3; shift 3
  openssl req -x509 -new -key $K/$key.pem -subj "/CN=V1 $key" -days 30 -noenc -config /dev/null \
    -addext subjectKeyIdentifier=none -addext authorityKeyIdentifier=none -addext basicConstraints=CA:FALSE \
    "$@" -outform DER -out v3.der 2>err.txt || { echo "GENFAIL $name: $(head -c 200 err.txt)"; return; }
  local cert tbs body rest alg version tbs1 sig
  cert=$(content "$(hex v3.der)")
  tbs=${cert:0:$(skip_tlv $cert)}; alg=${cert:${#tbs}}; alg=${alg:0:$(skip_tlv $alg)}
  body=$(content $tbs); version=a003020102
  [ "${body:0:10}" = $version ] || { echo "GENFAIL $name: no v3 version field"; return; }
  rest=${body:10}
  # the basicConstraints extension (needed to get an extension-less TBS from `req`) goes too
  local fields="" f
  while [ -n "$rest" ]; do
    f=${rest:0:$(skip_tlv $rest)}; rest=${rest:${#f}}
    [ "${f:0:2}" = a3 ] || fields+=$f
  done
  tbs1=$(tlv 30 "$fields"); echo -n $tbs1 | xxd -r -p > tbs.der
  if [ "$md" = none ]; then
    openssl pkeyutl -sign -rawin -inkey $K/$key.pem -in tbs.der -out sig.bin 2>err.txt
  else
    openssl dgst -$md -sign $K/$key.pem -out sig.bin tbs.der 2>err.txt
  fi || { echo "GENFAIL $name: $(head -c 200 err.txt)"; return; }
  sig=$(tlv 03 "00$(hex sig.bin)")
  echo -n "$(tlv 30 "$tbs1$alg$sig")" | xxd -r -p > $C/cert/$name.der
  openssl x509 -inform DER -in $C/cert/$name.der -noout -text | grep -q 'Version: 1 (0x0)' \
    || echo "GENFAIL $name: not v1"
  openssl verify -CAfile <(openssl x509 -inform DER -in $C/cert/$name.der) \
    <(openssl x509 -inform DER -in $C/cert/$name.der) >/dev/null 2>&1 || echo "GENFAIL $name: bad signature"
}
v1cert v1_rsa rsa sha256
v1cert v1_ec256 ec256 sha256
v1cert v1_ed25519 ed25519 none
v1cert v1_rsa_sha1 rsa sha1 -sha1

# ---- RFC 3161 time-stamping
cat > tsa_ext.cnf <<EOC
[tsa]
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping
subjectKeyIdentifier=hash
EOC
for k in rsa ec256; do
  openssl req -new -key $K/$k.pem -subj "/CN=TSA $k" -out tsa_$k.csr 2>/dev/null
  openssl x509 -req -in tsa_$k.csr -CA $CA/ca.pem -CAkey $K/rsa.pem -CAcreateserial -days 30 \
    -extfile tsa_ext.cnf -extensions tsa -out tsa_$k.pem 2>/dev/null || echo "GENFAIL tsa_$k"
done
echo "Hello, TSA world" > data.txt
tsacnf() { # name signer key digest [extra config lines...]
  local name=$1 signer=$2 key=$3 md=$4; shift 4
  { echo "[tsa]"; echo "default_tsa=t"; echo "[t]"; echo "serial=$W/tsaserial"
    echo "signer_cert=$W/tsa_$signer.pem"; echo "certs=$CA/ca.pem"; echo "signer_key=$K/$key.pem"
    echo "signer_digest=$md"; echo "default_policy=1.2.3.4.1"; echo "other_policies=1.2.3.4.2"
    echo "digests=sha1,sha256,sha384,sha512"; for l in "$@"; do echo "$l"; done; } > $name.cnf
}
echo 01 > tsaserial
tsacnf plain rsa rsa sha256
tsacnf full rsa rsa sha256 "accuracy=secs:1,millisecs:500,microsecs:100" "ordering=yes" "tsa_name=yes" "ess_cert_id_chain=yes"
tsacnf essv2 rsa rsa sha256 "ess_cert_id_alg=sha256"
tsacnf ec ec256 ec256 sha384
# queries
g $C/ts/q_sha256_nonce_cert.der openssl ts -query -data data.txt -sha256 -cert -out $C/ts/q_sha256_nonce_cert.der
g $C/ts/q_sha1.der openssl ts -query -data data.txt -sha1 -out $C/ts/q_sha1.der
g $C/ts/q_sha512_no_nonce.der openssl ts -query -data data.txt -sha512 -no_nonce -cert -out $C/ts/q_sha512_no_nonce.der
g $C/ts/q_policy.der openssl ts -query -data data.txt -sha256 -tspolicy 1.2.3.4.2 -cert -out $C/ts/q_policy.der
g $C/ts/q_bad_policy.der openssl ts -query -data data.txt -sha256 -tspolicy 1.2.3.4.99 -out $C/ts/q_bad_policy.der
# replies (r_<query>_<config>) and the bare tokens
reply() { # name query config
  g $C/ts/$1.der openssl ts -reply -config $3.cnf -queryfile $C/ts/$2.der -out $C/ts/$1.der
}
reply r_granted q_sha256_nonce_cert plain
reply r_nocerts q_sha1 plain
reply r_no_nonce q_sha512_no_nonce plain
reply r_policy q_policy plain
reply r_full q_sha256_nonce_cert full
reply r_essv2 q_sha256_nonce_cert essv2
reply r_ec q_sha256_nonce_cert ec
reply r_rejected q_bad_policy plain
for r in granted full ec; do
  g $C/ts/tok_$r.der openssl ts -reply -in $C/ts/r_$r.der -token_out -out $C/ts/tok_$r.der
done
# sanity: OpenSSL accepts its own granted replies
for r in granted nocerts no_nonce policy full essv2 ec; do
  q=$(case $r in nocerts) echo q_sha1;; no_nonce) echo q_sha512_no_nonce;; policy) echo q_policy;; *) echo q_sha256_nonce_cert;; esac)
  untrusted=$( [ $r = ec ] && echo tsa_ec256.pem || echo tsa_rsa.pem )
  openssl ts -verify -queryfile $C/ts/$q.der -in $C/ts/r_$r.der -CAfile $CA/ca.pem -untrusted $untrusted >/dev/null 2>&1 \
    || echo "GENFAIL r_$r: does not verify"
done
