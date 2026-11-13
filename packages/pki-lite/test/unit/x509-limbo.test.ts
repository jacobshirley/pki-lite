import { describe, expect, test } from 'vitest'
import { Certificate } from '../../src/x509/Certificate.js'
import { CertificateList } from '../../src/x509/CertificateList.js'
import { CertificateValidator } from '../../src/core/CertificateValidator.js'
import {
    LimboCase,
    limboBlobs,
    limboCases,
} from '../../test-fixtures/x509-limbo/limbo.js'

/**
 * x509-limbo (https://github.com/C2SP/x509-limbo): a large, current suite of X.509 path
 * validation cases with their expected results, run here the way limbo's harnesses for
 * other libraries do: each case's trust anchors, intermediates, leaf, validation time,
 * CRLs and expected peer name, through CertificateValidator.
 */

const der = (index: number) =>
    Uint8Array.from(atob(limboBlobs[index]), (c) => c.charCodeAt(0))

/**
 * Cases pki-lite does not run, each with the reason: things outside an RFC 5280
 * validator (the CA/Browser Forum Web PKI profile) or not implemented by design.
 */
function skipReason(c: LimboCase): string | undefined {
    const features = c.features ?? []
    if (features.includes('has-mldsa')) {
        return 'ML-DSA (RFC 9881) is not supported'
    }
    if (
        features.some(
            (f) =>
                f.startsWith('pedantic-webpki') ||
                f === 'pedantic-public-suffix-wildcard',
        )
    ) {
        return 'a "pedantic" CA/Browser Forum (Web PKI) rule, not RFC 5280'
    }
    if (
        c.id.startsWith('webpki::') &&
        !c.id.startsWith('webpki::san::') &&
        !c.id.startsWith('webpki::cn::')
    ) {
        return 'a CA/Browser Forum (Web PKI) profile rule, not RFC 5280'
    }
    return undefined
}

/**
 * Cases pki-lite does not pass yet, each with the reason. They run with `test.fails`, so
 * fixing one makes its test fail with "expected to fail": delete the entry then.
 */
const PEER_NAME =
    'CertificateValidator cannot check the expected peer name (DNS name or IP address against the leaf subjectAltName, RFC 9525).'
const EKU =
    'CertificateValidator cannot require an extended key usage of the leaf.'
const MAX_DEPTH =
    'CertificateValidator cannot limit the number of intermediates.'
const PATH_BUILDING =
    'Path building takes the first chain it finds and does not backtrack to another when that one fails.'
const DOS =
    'No limit on name constraint checking work: a technically valid but pathological chain (thousands of names against thousands of constraints) is accepted, where implementations reject it to avoid quadratic blowup.'
const FRACTIONAL =
    'Validity is compared to the millisecond, but RFC 5280 validity has whole-second granularity: a time 5 ms after notAfter is still within it.'
const CRL_PARSE = 'A very large CRL fails to parse.'
const CRL_PROFILE =
    'The RFC 5280 CRL profile is not enforced (cRLNumber present and non-critical, no duplicate entries).'
const PROFILE =
    'The RFC 5280 certificate profile is not enforced (extension criticality and presence, serial numbers, name forms, ...).'

const KNOWN_ISSUES: Record<string, string> = {
    'crl::structure::crl-very-large': CRL_PARSE,
    'crl::structure::crl-duplicate-revoked-serial': CRL_PROFILE,
    'crl::crlnumber-missing': CRL_PROFILE,
    'crl::crlnumber-critical': CRL_PROFILE,
    'cve::cve-2024-0567': PATH_BUILDING,
    'pathlen::max-chain-depth-0-exhausted': MAX_DEPTH,
    'pathlen::max-chain-depth-1-exhausted': MAX_DEPTH,
    'pathological::multiple-chains-expired-intermediate': PATH_BUILDING,
    'pathological::nc-dos-2': DOS,
    'pathological::nc-dos-3': DOS,
    'rfc5280::aki::critical-aki': PROFILE,
    'rfc5280::aki::leaf-missing-aki': PROFILE,
    'rfc5280::aki::intermediate-missing-aki': PROFILE,
    'rfc5280::aki::cross-signed-root-missing-aki': PROFILE,
    'rfc5280::eku::ee-wrong-eku': EKU,
    'rfc5280::eku::ee-eku-empty': PROFILE,
    'rfc5280::nc::permitted-dns-match-noncritical': PROFILE,
    'rfc5280::nc::permitted-empty-sequence-excluded-nonempty': PROFILE,
    'rfc5280::nc::permitted-nonempty-excluded-empty-sequence': PROFILE,
    'rfc5280::nc::invalid-dnsname-leading-period': PROFILE,
    'rfc5280::nc::not-allowed-in-ee-noncritical': PROFILE,
    'rfc5280::nc::not-allowed-in-ee-critical': PROFILE,
    'rfc5280::nc::nc-permits-invalid-dns-san': PROFILE,
    'rfc5280::nc::nc-permits-invalid-email-san': PROFILE,
    'rfc5280::nc::nc-forbids-alternate-chain-ica': PATH_BUILDING,
    'rfc5280::nc::nc-forbids-same-chain-ica': PATH_BUILDING,
    'rfc5280::pc::ica-noncritical-pc': PROFILE,
    'rfc5280::san::malformed': PROFILE,
    'rfc5280::san::noncritical-with-empty-subject': PROFILE,
    'rfc5280::san::underscore-dns': PROFILE,
    'rfc5280::san::ip-in-dns': PEER_NAME,
    'rfc5280::serial::too-long': PROFILE,
    'rfc5280::serial::zero': PROFILE,
    'rfc5280::ski::root-missing-ski': PROFILE,
    'rfc5280::ski::intermediate-missing-ski': PROFILE,
    'rfc5280::validity::notafter-fractional': FRACTIONAL,
    'rfc5280::ca-empty-subject': PROFILE,
    'rfc5280::unknown-critical-extension-root': PROFILE,
    'rfc5280::root-non-critical-basic-constraints': PROFILE,
    'rfc5280::leaf-ku-keycertsign': PROFILE,
    'rfc5280::ee-critical-aia-invalid': PROFILE,
    'rfc5280::duplicate-extensions': PROFILE,
    'rfc5280::ca-as-leaf-wrong-san': PEER_NAME,
    'webpki::cn::ipv4-hex-mismatch': PEER_NAME,
    'webpki::cn::ipv4-leading-zeros-mismatch': PEER_NAME,
    'webpki::cn::ipv6-uppercase-mismatch': PEER_NAME,
    'webpki::cn::ipv6-uncompressed-mismatch': PEER_NAME,
    'webpki::cn::ipv6-non-rfc5952-mismatch': PEER_NAME,
    'webpki::cn::punycode-not-in-san': PEER_NAME,
    'webpki::cn::utf8-vs-punycode-mismatch': PEER_NAME,
    'webpki::cn::not-in-san': PEER_NAME,
    'webpki::cn::case-mismatch': PEER_NAME,
    'webpki::san::mismatch-domain-san': PEER_NAME,
    'webpki::san::mismatch-subdomain-san': PEER_NAME,
    'webpki::san::mismatch-subdomain-apex-san': PEER_NAME,
    'webpki::san::mismatch-apex-subdomain-san': PEER_NAME,
    'webpki::san::wildcard-embedded-leftmost-san': PEER_NAME,
    'webpki::san::wildcard-not-in-leftmost-san': PEER_NAME,
    'webpki::san::wildcard-match-across-labels-san': PEER_NAME,
    'webpki::san::wildcard-embedded-ulabel-san': PEER_NAME,
    'webpki::san::unicode-emoji-san': PEER_NAME,
    'webpki::san::no-san': PEER_NAME,
    'webpki::san::san-critical-with-nonempty-subject': PEER_NAME,
    'webpki::san::san-wildcard-only': PEER_NAME,
    'webpki::san::san-wildcard-only-tld': PEER_NAME,
}

async function validate(c: LimboCase) {
    const crls = c.crls.map((i) => CertificateList.fromDer(der(i)))
    return new CertificateValidator().validate(
        Certificate.fromDer(der(c.peer)),
        {
            validateChain: true,
            trustAnchors: c.trusted.map((i) => ({
                certificate: Certificate.fromDer(der(i)),
            })),
            otherCertificates: c.untrusted.map((i) =>
                Certificate.fromDer(der(i)),
            ),
            validationTime: c.validationTime
                ? new Date(c.validationTime)
                : undefined,
            checkCRL: crls.length > 0,
        },
        crls.length > 0 ? { crls } : undefined,
    )
}

describe('x509-limbo', () => {
    for (const c of limboCases) {
        const skip = skipReason(c)
        const name = `${c.id}: ${c.expected}`
        if (skip) {
            test.skip(`${name} (${skip})`, () => {})
            continue
        }
        ;(KNOWN_ISSUES[c.id] ? test.fails : test)(name, async () => {
            let result
            try {
                result = await validate(c)
            } catch (error) {
                // a parse error is a rejection
                expect('FAILURE', String(error)).toBe(c.expected)
                return
            }
            expect(
                result.isValid ? 'SUCCESS' : 'FAILURE',
                `${c.description}\n${result.status}: ${result.messages.join('; ')}`,
            ).toBe(c.expected)
        })
    }
})
