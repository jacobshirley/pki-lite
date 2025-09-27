// Requesting a CRL (using a certificate's CRL distribution points)

import { Certificate } from 'pki-lite/x509/Certificate.js'

const certPem = `-----BEGIN CERTIFICATE-----{your certificate here}-----END CERTIFICATE-----`
const certificate = Certificate.fromPem(certPem)

// NB: This will only work if the CRL distribution point is accessible
const crl = await certificate.requestCrl()
if (!crl) {
    console.log('No CRL found')
} else {
    console.log('Successfully found CRL', crl.toString())
}
