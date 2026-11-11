#!/usr/bin/env bash
# Part of the OpenSSL corpus generator; run via ../generate.sh (needs AUDIT=<workdir>).
set -u
: "${AUDIT:?run via generate.sh}"
O=$AUDIT/corpus/cert; K=$AUDIT/keys; cd $K
n=0
gen() { # name cnf [extra]
  local name=$1 cnf=$2; shift 2
  if openssl req -x509 -new -key $K/rsa.pem -config $cnf -days 30 "$@" -outform DER -out $O/$name.der 2>$O/$name.err; then rm -f $O/$name.err; n=$((n+1)); else echo "GENFAIL $name: $(head -c 300 $O/$name.err)"; rm -f $O/$name.der; fi
}
cat > dp2.cnf <<EOC
[req]
distinguished_name=dn
x509_extensions=v3
prompt=no
[dn]
CN=Test
[v3]
crlDistributionPoints=dp1,dp2,dp3
freshestCRL=URI:http://example.com/delta.crl
authorityInfoAccess=OCSP;URI:http://ocsp.example.com,caIssuers;URI:http://example.com/ca.der
subjectInfoAccess=caRepository;URI:http://example.com/repo,timeStamping;URI:http://tsa.example.com
[dp1]
fullname=URI:http://example.com/full.crl
reasons=keyCompromise,CACompromise,affiliationChanged,superseded,cessationOfOperation,certificateHold,privilegeWithdrawn,AACompromise
CRLissuer=dirName:crlissuer
[dp2]
relativename=rdn
CRLissuer=dirName:crlissuer
[dp3]
fullname=URI:http://example.com/b.crl,DNS:crl.example.com
[rdn]
CN=Relative
[crlissuer]
CN=CRL Issuer
O=Org
EOC
gen dp_full dp2.cnf
cat > unk.cnf <<EOC
[req]
distinguished_name=dn
x509_extensions=v3
prompt=no
[dn]
CN=Test
[v3]
1.2.3.4.5=ASN1:UTF8:hello
1.2.3.4.6=critical,ASN1:SEQUENCE:seq
1.2.3.4.7=DER:0500
[seq]
a=INTEGER:5
b=OID:1.2.3
EOC
gen unknown_ext unk.cnf
cat > noext.cnf <<EOC
[req]
distinguished_name=dn
prompt=no
[dn]
CN=Test
EOC
gen no_exts noext.cnf
# --- name variety
nm() { # name, dn-section-body, [extra opts line in req]
  local extra="${3:-}"
  cat > nm_$1.cnf <<EOC
[req]
distinguished_name=dn
prompt=no
$extra
[dn]
$2
EOC
  gen name_$1 nm_$1.cnf
}
nm single "CN=Only CN"
nm full "C=GB
ST=State
L=Locality
O=Organisation
OU=Unit
CN=Common Name
emailAddress=a@example.com
serialNumber=12345
DC=example
UID=user1
title=Dr
GN=Given
SN=Sur
initials=X
postalCode=SW1A
street=1 Test Street
businessCategory=Retail
dnQualifier=dnq
pseudonym=pseud" "string_mask=utf8only"
nm printable "C=GB
O=Printable Org
CN=Printable CN" "string_mask=pkix"
nm utf8 "C=GB
O=Ünïcödé Örg
CN=日本語 テスト" "string_mask=utf8only
utf8=yes"
nm bmp "CN=BMP Name" "string_mask=MASK:0x2000"
nm t61 "CN=T61 Name" "string_mask=MASK:0x4"
nm ia5mail "CN=Test
emailAddress=user@example.com"
nm long "CN=$(python3 -c "print('A'*64)")
O=$(python3 -c "print('B'*64)")"
nm spaces "CN=  leading and trailing  
O=Org , with; special+chars"
cat > nm_multi.cnf <<EOC
[req]
distinguished_name=dn
prompt=no
[dn]
0.C=GB
0.O=First Org
1.O=Second Org
3.O=Third
0.OU=A
1.OU=B
CN=Multi
EOC
gen name_multi nm_multi.cnf
# multi-valued RDN via -subj +
openssl req -x509 -new -key rsa.pem -subj "/C=GB/CN=Multi+O=ValuedRDN+OU=Part3" -days 30 -outform DER -out $O/name_multivalued_rdn.der 2>/dev/null && n=$((n+1)) || echo GENFAIL name_multivalued_rdn
openssl req -x509 -new -key rsa.pem -subj "/" -days 30 -addext subjectAltName=DNS:x.example -outform DER -out $O/name_empty.der 2>/dev/null && n=$((n+1)) || echo GENFAIL name_empty
# --- validity
for nb_na in "19700101000000Z 20491231235959Z validity_utc_max" "20500101000000Z 20600101000000Z validity_gen" "19500101000000Z 20491231235959Z validity_pre1970" "20240229120000Z 20280229120000Z validity_leap" "20000101000000Z 99991231235959Z validity_9999" "20491231235959Z 20500101000000Z validity_boundary"; do
  set -- $nb_na
  openssl req -x509 -new -key rsa.pem -subj "/CN=V" -not_before $1 -not_after $2 -outform DER -out $O/$3.der 2>$O/$3.err && { n=$((n+1)); rm -f $O/$3.err; } || echo "GENFAIL $3 $(head -c 200 $O/$3.err)"
done
# --- serials
for s in 1 127 128 255 256 32767 32768 0x7f 0x80 0xff 0x0100 0x00ffffffffffffffffffffffffffffffffffffff 0x7fffffffffffffffffffffffffffffffffffffff 0x8000000000000000000000000000000000000000 ; do
  openssl req -x509 -new -key rsa.pem -subj "/CN=S" -set_serial $s -days 30 -outform DER -out "$O/serial_$s.der" 2>$O/ser.err && n=$((n+1)) || echo "GENFAIL serial_$s $(head -c 200 $O/ser.err)"
done; rm -f $O/ser.err
# --- one SAN entry per GeneralName type (isolates which types a parser handles)
san1() { # name, alt-section line
  printf '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=SAN\n[v3]\nsubjectAltName=@alt\n[alt]\n%s\n[dnsect]\nC=GB\nO=Org\nCN=Alt\n' "$2" > san_$1.cnf
  gen san1_$1 san_$1.cnf
}
san1 dns "DNS.1=a.example.com"
san1 email "email.1=a@example.com"
san1 uri "URI.1=https://example.com/p?q=1"
san1 ip4 "IP.1=192.0.2.1"
san1 ip6 "IP.1=2001:db8::1"
san1 rid "RID.1=1.2.3.4"
san1 dirname "dirName.1=dnsect"
san1 othername "otherName.1=1.3.6.1.4.1.311.20.2.3;UTF8:user@example.com"
san1 two_dns "DNS.1=a.example.com
DNS.2=b.example.com"
echo "generated2 $n"
