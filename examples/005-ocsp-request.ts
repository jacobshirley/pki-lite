// Creating an OCSP request and parsing the response

import { Certificate } from 'pki-lite/x509/Certificate.js'

const certPem =
    '-----BEGIN CERTIFICATE-----{your certificate here}-----END CERTIFICATE-----'
const issuerCertPem =
    '-----BEGIN CERTIFICATE-----{your issuer certificate here}-----END CERTIFICATE-----'
const certificate = Certificate.fromPem(certPem)

// NB: This will only work if the OCSP responder is accessible
const ocsp = await certificate.requestOcsp({
    issuerCertificate: Certificate.fromPem(issuerCertPem),
})

if (!ocsp) {
    console.log('No OCSP response found')
} else {
    console.log('OCSP Response:', ocsp.toString())
}
