import { Certificate } from '../src/x509/Certificate.js'
import { AuthorityInfoAccess } from '../src/x509/extensions/AuthorityInfoAccess.js'
import { rsaSigningKeys } from '../test-fixtures/signing-keys/rsa-2048/index.js'

const _fetch = globalThis.fetch
globalThis.fetch = (url, init) => {
    return new Promise((resolve, reject) => {
        if (url === 'http://localhost:8080/ocsp') {
            resolve(new Response(rsaSigningKeys.ocspResponse, { status: 200 }))
        } else {
            reject(new Error('Not Found: ' + url))
        }
    })
}

async function requestOcsp() {
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

    const ocsp = await certificate.requestOcsp({
        issuerCertificate: Certificate.fromPem(rsaSigningKeys.caCertPem),
    })

    if (!ocsp) {
        console.log('No OCSP response found')
        return
    }
    console.log('OCSP Response:', ocsp.toString())
}

await requestOcsp()
globalThis.fetch = _fetch
