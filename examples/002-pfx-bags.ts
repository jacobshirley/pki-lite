// Parsing a PFX and extracting bags, private keys, and certificates

import { PFX } from 'pki-lite/pkcs12/PFX.js'

const pem = `-----BEGIN PKCS12-----
{your pfx data here}
-----END PKCS12-----`

const pfx = PFX.fromPem(pem)
console.log('PFX version:', pfx.version)
console.log('Has MAC data:', !!pfx.macData)

const bags = await pfx.getBags('test')
console.log(`Found ${bags.length} bags`)

const privateKeys = await pfx.getPrivateKeys('test')
console.log(`Found ${privateKeys.length} private keys`)
privateKeys.forEach((key, index) => {
    console.log(`Private Key ${index + 1}:`, key.getPrivateKey().toPem())
})

const certificates = await pfx.getX509Certificates('test')
console.log(`Found ${certificates.length} certificates`)
certificates.forEach((cert, index) => {
    console.log(`Certificate ${index + 1}:`, cert.toPem())
})
