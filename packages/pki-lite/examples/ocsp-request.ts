import { Certificate } from '../src/x509/Certificate.js'
import { AuthorityInfoAccess } from '../src/x509/extensions/AuthorityInfoAccess.js'
import { rsaSigningKeys } from '../test-fixtures/signing-keys/rsa-2048/index.js'

const certificate = Certificate.fromPem(rsaSigningKeys.certPem)
const aias = certificate.tbsCertificate.getExtensionsByName(
    'AUTHORITY_INFO_ACCESS',
)

for (const aia of aias) {
    console.log(
        'AIAs:',
        aia.extnValue
            .parseAs(AuthorityInfoAccess)
            .map((ad) => ad.accessLocation),
    )
}

// NB: This will only work if the OCSP responder is accessible
const ocsp = await certificate.requestOcsp({
    issuerCertificate: Certificate.fromPem(rsaSigningKeys.caCertPem),
})

if (!ocsp) {
    console.log('No OCSP response found')
} else {
    console.log('OCSP Response:', ocsp.toString())
}
