import { Certificate } from '../src/x509/Certificate.js'
import { CRLDistributionPoints } from '../src/x509/extensions/CRLDistributionPoints.js'
import { rsaSigningKeys } from '../test-fixtures/signing-keys/rsa-2048/index.js'

const certificate = Certificate.fromPem(rsaSigningKeys.certPem)
const crlDps = certificate.tbsCertificate.getExtensionsByName(
    'CRL_DISTRIBUTION_POINTS',
)

for (const dp of crlDps) {
    const crl = dp.extnValue.parseAs(CRLDistributionPoints)
    console.log(
        'CRL Distribution Point Extension:',
        crl[0].distributionPoint?.[0].toHumanString(),
    )
}

// NB: This will only work if the CRL distribution point is accessible
const crl = await certificate.requestCrl()
if (!crl) {
    console.log('No CRL found')
} else {
    console.log('Successfully found CRL', crl.toString())
}
