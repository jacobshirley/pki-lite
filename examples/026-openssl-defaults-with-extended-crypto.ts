// Decrypting what OpenSSL produces by default (RSA PKCS#1 v1.5 and 3DES)

import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo.js'
import { EnvelopedData } from 'pki-lite/pkcs7/EnvelopedData.js'
import { PFX } from 'pki-lite/pkcs12/PFX.js'

console.log('=== OpenSSL defaults with the extended crypto package ===\n')

const fromBase64 = (text: string) =>
    Uint8Array.from(atob(text.replace(/\s/g, '')), (c) => c.charCodeAt(0))

// `openssl cms -encrypt -aes256 -recip cert.pem` wraps the content key with RSA
// PKCS#1 v1.5, which WebCrypto does not offer.
const cmsBase64 = `MIIBrgYJKoZIhvcNAQcDoIIBnzCCAZsCAQAxggFGMIIBQgIBADAqMBIxEDAOBgNV
BAMMB1Rlc3QgQ0ECFFE2yTfw/ZHSau6Z8W8G1snvhr58MA0GCSqGSIb3DQEBAQUA
BIIBAAoCju/D489GfEcvW//inPaORt6TXYiWiefuLzrrhhnSGn6GtgEHsd/LCZnr
bY3m9XvqvGNR3Ey94Zrl6+eqxCLNG9rSvv3CSwVXioGPpN99yRvK8iwb2IYPSoc6
ETV4ZWQFiKbbf+J4q3Qjlakl1R56iUILnz/WhWa6JLvZe2x7IinyORlAiRbXVgiA
di8TgKMSgU/AJtHKwSA250DHWd1nAgV8Q8tqmnv3Op/1qm1Zs3RWfPGgAse84uDd
xy0kOFlxzx9xTx77fSJxqjzyTFC1zCF+2VLVJ9lSMbfdg9MAcgEP2VUWW+wPDMWI
lADf77QlpSHxn5sjqlHEEtHlMq8wTAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQ
xhtaAE3WlTdY04Ulu4DTAYAgdCG01G+Nk2QtWlCEm3f/O2PgBenjtUO3/M3PohI4
t1g=`
const privateKey = PrivateKeyInfo.fromPem(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCJYd/Fq93u7e7W
Xy8iZvVVNN4uVXhc4mX4FPO65ShKJ3Bw0XciUws7vUDxLRx3GIhQ+diCpgEkUbr1
8enF7nngO//eJQDc+5tPRDOUR5s6UL7Gj+hfAllxT339NoKoMuauHz25ca0PWc0y
y4XQx3Pdkinp0aGnimGeTKkaPuXiQr6tTjZCJ9SzWR7oCJwXSBiJ2c9fkBi8oNoU
+kqHjgd0R5ex2gNjKPjTpfP5Ff8Oq2gg1KkSTPmSgPjEMw+sNLOh3yTZpdNaeVms
baT5z92faYQ+POfcUa+xYkEgvvaQAngI8T5nQiR7b4zgrJEuEgw8G/GFq69rejBi
NZOvbjGPAgMBAAECggEACcwsRcV6h+TPFi8RRk5PwRpf8q+kwaxht54Nkxlu/07Y
aCtVaDds7dSS55WfLz0q0j+R5HYLTyLxsZg64vidbNOf7UtNSEqR/8auOQJxpxMw
GoAT2IbAiIyx6wIysjp4ahg58i+Rty5hLHYISTnti502FldIGec2tq/ilXJr5EVh
4jOWXXQ8PVc33agBDf2Br06/S2urQiAxCnx9ewjndB/H+w+PXrreMfKm/ZbUwU/1
TSnWvB1yT+z1yJsertlM0me3LnpHIIrFLX8FvfOPKTa+Gcs6kq7Kyw7s8qSkPGKg
Z3yFv4Qzolh75PiQQYGek4JMtIPw09E95nrYoDQF1QKBgQC9ALwkpemwN/Z3oZFl
5b+DbO+VXqz7whsowURKr+9TEi0hB0vIM4CvNUJ6DaM30MRydVm6Z0a+Y55Z381L
IR4OunN7uOG8ILxKNyEUeW2fU3kcV5AyiFYVWdm0FpiIjzUkvn9yrtx7hwjOh8Wz
hlWfyFnobCgNpYjwBDIJ5kqN0wKBgQC6FMchjl7b2UlyTrdUib38V8gK6GDTZKXR
KvLvqiMjJqcUEwYWZjnE0ozL9zKjcut/5F0Keh7PXD2a/+rJVnGA1XZKfzvBQpAG
YPCfv4LtdHefjGitqihFiLnRpfJ069vhDjK9Ow+YHAFBFXXUS1mSctC6+d/xNRUK
9eUiJwVr1QKBgBfg9+RJcfTpnSIQL6aIGGIqaTqd84z7QSMtB8vH3pzINxttKI3q
s99vAy8Yef6bSbaMTQHX+oAjZeZE+FL9pCaIN/7xpNN371IRFQTZMphmm26RQY6g
2v9nkrHGCQ93yGcUClYa8ZBJxzsQvFGqLzc4wOM0hvryZxKr9QZ7KgAxAoGAXRwy
fAb6TjXOu4TJ1WJLD255KYQXlw9grWY5Q1U12cvohHH0dNbYBzV3wEPEMec6Ebea
Grj6m7XDGcD+oZpAlz+4vhQmOVDuMlLldHnmsJy7krk2U9e16P0+RbostPakAlwR
ZYCdD/bLZd6wI/dELbSH31dTCCYQjnh2G/28h7UCgYAjWats6wG1V2yCpF35+RXg
C4FDK2izwoQafdpsvWFx00ce4WEeiJTBjUZ/Iec5ZbQ2jW3f2Z0BKBd3lovJkagi
GndtOxfMvOylDc9/S63Q2Mnwcu6RVgMtg0Mb1BD3ReBMmO9zCsoYNo5+m48otUA6
y78dk/1k3Ju2FAiCapL/vw==
-----END PRIVATE KEY-----`)

// `openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES`: password "pw"
const legacyPfxBase64 = `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
EGLpy1PI5e2D528FkHbE+cECAggA`

const envelopedData = EnvelopedData.fromCms(fromBase64(cmsBase64))

// With only the default provider, RSA PKCS#1 v1.5 key transport is not available
try {
    await envelopedData.decrypt(privateKey)
    console.log('Default provider: decrypted (unexpected)')
} catch {
    console.log('Default provider: cannot decrypt (no RSA PKCS#1 v1.5)')
}

// Importing the extended package installs a provider that adds RSA PKCS#1 v1.5, 3DES, MD5
// and more. Do this once at start-up; it applies to all of pki-lite.
await import('pki-lite-crypto-extended')

const plaintext = await envelopedData.decrypt(privateKey)
console.log(
    'Extended provider: decrypted ->',
    JSON.stringify(new TextDecoder().decode(plaintext).trimEnd()), // OpenSSL adds a CRLF
)

// The same provider reads the legacy 3DES-encrypted PKCS#12 files many tools still write
const pfx = PFX.fromDer(fromBase64(legacyPfxBase64))
const { privateKeys, certificates } = await pfx.extractItems('pw')
console.log(
    `3DES PKCS#12: ${privateKeys.length} private key, ${certificates.length} certificate`,
)
console.log(
    '  Certificate:',
    certificates[0].tbsCertificate.subject.toHumanString(),
)
