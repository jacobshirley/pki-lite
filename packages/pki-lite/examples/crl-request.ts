import { Certificate } from '../src/x509/Certificate.js'
import { CRLDistributionPoints } from '../src/x509/extensions/CRLDistributionPoints.js'
import { rsaSigningKeys } from '../test-fixtures/signing-keys/rsa-2048/index.js'

const _fetch = globalThis.fetch
globalThis.fetch = (url, init) => {
    return new Promise((resolve, reject) => {
        if (url === 'http://localhost:8080/ca.crl') {
            // Example CRL in PEM format (replace with a real CRL for actual use)
            resolve(new Response(rsaSigningKeys.caCrl, { status: 200 }))
        } else {
            reject(new Error('Not Found'))
        }
    })
}

async function requestCrl() {
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

    const crl = await certificate.requestCrl()
    if (!crl) {
        console.log('No CRL found')
        return
    }
    console.log('Successfully found CRL', crl.toString())
}

await requestCrl()
globalThis.fetch = _fetch
