/**
 * Name constraints (RFC 5280 4.2.1.10 and 6.1) on real certificates: every chain here is
 * issued by the OpenSSL CLI with OpenSSL's own nameConstraints and subjectAltName
 * extensions, and each scenario is checked against both pki-lite's validator and
 * `openssl verify`. The expected verdicts are written out from RFC 5280, so a
 * disagreement shows which side is wrong.
 *
 * Both implementations also check a subject common name that looks like a host name
 * against dNSName constraints when the certificate has no dNSName (RFC 5280 does not
 * ask for this, but TLS clients fall back to the CN, so it is the safe reading).
 */
import fs from 'fs'
import path from 'path'
import { randomUUID } from 'crypto'
import { beforeAll, describe, expect, test } from 'vitest'
import { runOpenSSL } from '../../test-fixtures/openSsl.js'
import { CertificateValidator } from '../../src/core/CertificateValidator.js'
import { Certificate } from '../../src/x509/Certificate.js'

/** One CA below the root */
type CaSpec = {
    /** subject DN in OpenSSL's /A=b/C=d form (no spaces), default /CN=<name> */
    subject?: string
    /** nameConstraints entries, e.g. 'DNS:example.com' or 'dirName:Acme' */
    permitted?: string[]
    excluded?: string[]
}

type Scenario = {
    name: string
    /** CAs from the one below the root down to the leaf's issuer */
    cas: CaSpec[]
    /** leaf subject DN in OpenSSL's /A=b/C=d form (no spaces) */
    leafSubject?: string
    /** leaf subjectAltName entries, e.g. 'DNS:www.example.com' */
    leafSan?: string[]
    /** directory name sections used by dirName: entries, e.g. { Acme: 'C=GB\nO=Acme' } */
    dirs?: Record<string, string>
    valid: boolean
}

const scenarios: Scenario[] = [
    // --- dNSName ---------------------------------------------------------------------
    {
        name: 'DNS: a subdomain of a permitted domain',
        cas: [{ permitted: ['DNS:example.com'] }],
        leafSan: ['DNS:www.example.com'],
        valid: true,
    },
    {
        name: 'DNS: the permitted domain itself',
        cas: [{ permitted: ['DNS:example.com'] }],
        leafSan: ['DNS:example.com'],
        valid: true,
    },
    {
        name: 'DNS: a name outside the permitted domain',
        cas: [{ permitted: ['DNS:example.com'] }],
        leafSan: ['DNS:www.example.org'],
        valid: false,
    },
    {
        name: 'DNS: a suffix match that is not on a label boundary',
        cas: [{ permitted: ['DNS:example.com'] }],
        leafSan: ['DNS:badexample.com'],
        valid: false,
    },
    {
        name: 'DNS: an excluded subtree inside a permitted one',
        cas: [
            {
                permitted: ['DNS:example.com'],
                excluded: ['DNS:internal.example.com'],
            },
        ],
        leafSan: ['DNS:db.internal.example.com'],
        valid: false,
    },
    {
        name: 'DNS: every name must be permitted, not just one',
        cas: [{ permitted: ['DNS:example.com'] }],
        leafSan: ['DNS:www.example.com', 'DNS:www.attacker.net'],
        valid: false,
    },
    {
        name: 'DNS: constraints on other name types leave dNSNames alone',
        cas: [{ permitted: ['email:example.com'] }],
        leafSan: ['DNS:anything.example.net'],
        valid: true,
    },
    // --- the subject common name -----------------------------------------------------
    {
        name: 'CN: a host-like common name outside the constraint, without a dNSName',
        cas: [{ permitted: ['DNS:example.com'] }],
        leafSubject: '/CN=www.attacker.net',
        valid: false,
    },
    {
        name: 'CN: a host-like common name inside the constraint, without a dNSName',
        cas: [{ permitted: ['DNS:example.com'] }],
        leafSubject: '/CN=www.example.com',
        valid: true,
    },
    {
        name: 'CN: a common name that is not a host name is not a dNSName',
        cas: [{ permitted: ['DNS:example.com'] }],
        leafSubject: '/CN=Alice_Example',
        valid: true,
    },
    // --- rfc822Name ------------------------------------------------------------------
    {
        name: 'email: a mailbox at the permitted domain',
        cas: [{ permitted: ['email:example.com'] }],
        leafSan: ['email:alice@example.com'],
        valid: true,
    },
    {
        name: 'email: a bare domain does not include its subdomains',
        cas: [{ permitted: ['email:example.com'] }],
        leafSan: ['email:alice@mail.example.com'],
        valid: false,
    },
    {
        name: 'email: a leading dot permits the subdomains',
        cas: [{ permitted: ['email:.example.com'] }],
        leafSan: ['email:alice@mail.example.com'],
        valid: true,
    },
    {
        name: 'email: a leading dot does not permit the domain itself',
        cas: [{ permitted: ['email:.example.com'] }],
        leafSan: ['email:alice@example.com'],
        valid: false,
    },
    {
        name: 'email: a full mailbox permits only that mailbox',
        cas: [{ permitted: ['email:alice@example.com'] }],
        leafSan: ['email:bob@example.com'],
        valid: false,
    },
    {
        name: 'email: an emailAddress in the subject DN is constrained too',
        cas: [{ permitted: ['email:example.com'] }],
        leafSubject: '/CN=Mallory/emailAddress=mallory@attacker.net',
        valid: false,
    },
    // --- iPAddress -------------------------------------------------------------------
    {
        name: 'IP: an IPv4 address inside the permitted range',
        cas: [{ permitted: ['IP:10.0.0.0/255.0.0.0'] }],
        leafSan: ['IP:10.1.2.3'],
        valid: true,
    },
    {
        name: 'IP: an IPv4 address outside the permitted range',
        cas: [{ permitted: ['IP:10.0.0.0/255.0.0.0'] }],
        leafSan: ['IP:192.168.1.1'],
        valid: false,
    },
    {
        name: 'IP: an excluded range inside a permitted one',
        cas: [
            {
                permitted: ['IP:10.0.0.0/255.0.0.0'],
                excluded: ['IP:10.1.0.0/255.255.0.0'],
            },
        ],
        leafSan: ['IP:10.1.2.3'],
        valid: false,
    },
    {
        name: 'IP: an IPv6 address inside the permitted range',
        cas: [{ permitted: ['IP:2001:db8::/ffff:ffff::'] }],
        leafSan: ['IP:2001:db8::1'],
        valid: true,
    },
    {
        name: 'IP: an IPv6 address outside the permitted range',
        cas: [{ permitted: ['IP:2001:db8::/ffff:ffff::'] }],
        leafSan: ['IP:2001:db9::1'],
        valid: false,
    },
    {
        name: 'IP: an IPv4 range does not admit an IPv6 address',
        cas: [{ permitted: ['IP:10.0.0.0/255.0.0.0'] }],
        leafSan: ['IP:2001:db8::1'],
        valid: false,
    },
    // --- directoryName ---------------------------------------------------------------
    {
        name: 'dirName: a subject inside the permitted subtree',
        cas: [{ permitted: ['dirName:acme'] }],
        dirs: { acme: 'C=GB\nO=Acme' },
        leafSubject: '/C=GB/O=Acme/CN=leaf',
        valid: true,
    },
    {
        name: 'dirName: a subject outside the permitted subtree',
        cas: [{ permitted: ['dirName:acme'] }],
        dirs: { acme: 'C=GB\nO=Acme' },
        leafSubject: '/C=GB/O=Other/CN=leaf',
        valid: false,
    },
    {
        name: 'dirName: a subject inside an excluded subtree',
        cas: [{ excluded: ['dirName:acme'] }],
        dirs: { acme: 'C=GB\nO=Acme' },
        leafSubject: '/C=GB/O=Acme/OU=Sales/CN=leaf',
        valid: false,
    },
    // --- uniformResourceIdentifier ---------------------------------------------------
    {
        name: 'URI: a host constraint matches that host only',
        cas: [{ permitted: ['URI:example.com'] }],
        leafSan: ['URI:https://example.com/path'],
        valid: true,
    },
    {
        name: 'URI: a host constraint does not include subdomains',
        cas: [{ permitted: ['URI:example.com'] }],
        leafSan: ['URI:https://www.example.com/path'],
        valid: false,
    },
    {
        name: 'URI: a leading dot permits the subdomains',
        cas: [{ permitted: ['URI:.example.com'] }],
        leafSan: ['URI:https://www.example.com/path'],
        valid: true,
    },
    // --- several CAs -----------------------------------------------------------------
    {
        name: 'chain: constraints from two CAs both apply (intersection)',
        cas: [
            { permitted: ['DNS:example.com'] },
            { permitted: ['DNS:www.example.com'] },
        ],
        leafSan: ['DNS:api.example.com'],
        valid: false,
    },
    {
        name: 'chain: a name inside both CAs constraints',
        cas: [
            { permitted: ['DNS:example.com'] },
            { permitted: ['DNS:www.example.com'] },
        ],
        leafSan: ['DNS:a.www.example.com'],
        valid: true,
    },
    {
        name: 'chain: a lower CA cannot widen what a higher one permits',
        cas: [
            { permitted: ['DNS:example.com'] },
            { permitted: ['DNS:example.org'] },
        ],
        leafSan: ['DNS:www.example.org'],
        valid: false,
    },
    {
        name: 'chain: the constraints apply to the next CA certificate too',
        cas: [
            { permitted: ['dirName:acme'] },
            { subject: '/C=GB/O=Other/CN=SubCA' },
        ],
        dirs: { acme: 'C=GB\nO=Acme' },
        leafSubject: '/C=GB/O=Acme/CN=leaf',
        valid: false,
    },
]

/** The extension config for a CA, plus any directory-name sections it refers to. */
function caConfig(ca: CaSpec, dirs: Record<string, string> = {}): string {
    const lines = [
        'basicConstraints=critical,CA:TRUE',
        'keyUsage=critical,keyCertSign,cRLSign',
    ]
    const subtrees = [
        ...(ca.permitted ?? []).map((name) => `permitted;${name}`),
        ...(ca.excluded ?? []).map((name) => `excluded;${name}`),
    ]
    if (subtrees.length) {
        lines.push(`nameConstraints=critical,${subtrees.join(',')}`)
    }
    return [`[ext]`, ...lines, ...dirSections(dirs)].join('\n') + '\n'
}

function leafConfig(san?: string[]): string {
    const lines = ['basicConstraints=CA:FALSE']
    if (san?.length) lines.push(`subjectAltName=${san.join(',')}`)
    return `[ext]\n${lines.join('\n')}\n`
}

const dirSections = (dirs: Record<string, string>) =>
    Object.entries(dirs).flatMap(([name, body]) => [`[${name}]`, body])

describe(
    'name constraints on OpenSSL-issued chains',
    { timeout: 120_000 },
    () => {
        /** keys shared by every scenario: root, CA 1, CA 2, leaf */
        let base: string
        const names = ['root', 'ca1', 'ca2', 'leaf']

        beforeAll(async () => {
            // runOpenSSL joins its arguments into a shell line: no spaces in paths or names
            base = path.resolve(
                `${import.meta.dirname}/../../test-fixtures/tmp/name-constraints-${randomUUID()}`,
            )
            fs.mkdirSync(base, { recursive: true })
            for (const name of names) {
                await runOpenSSL(
                    [
                        'genpkey',
                        '-algorithm',
                        'EC',
                        '-pkeyopt',
                        'ec_paramgen_curve:P-256',
                        '-out',
                        `${base}/${name}.key`,
                    ],
                    base,
                )
            }
            await runOpenSSL(
                [
                    'req',
                    '-x509',
                    '-new',
                    '-key',
                    `${base}/root.key`,
                    '-subj',
                    '/CN=NameConstraintsRoot',
                    '-days',
                    '30',
                    '-addext',
                    'basicConstraints=critical,CA:TRUE',
                    '-addext',
                    'keyUsage=critical,keyCertSign,cRLSign',
                    '-out',
                    `${base}/root.pem`,
                ],
                base,
            )
        }, 120_000) // a few OpenSSL runs, each a docker container in CI

        /**
         * Issues the scenario's chain with OpenSSL. Everything stays in the shared folder
         * (files prefixed per scenario): with docker, OpenSSL writes the keys as root and
         * only it can read them.
         */
        async function issue(scenario: Scenario) {
            const id = randomUUID().slice(0, 8)
            const file = (name: string, ext = 'pem') =>
                name === 'root'
                    ? `${base}/root.pem`
                    : `${base}/${id}-${name}.${ext}`
            const sign = async (
                subject: string,
                dn: string,
                issuer: string,
                config: string,
            ) => {
                await runOpenSSL(
                    [
                        'req',
                        '-new',
                        '-key',
                        `${base}/${subject}.key`,
                        '-subj',
                        dn,
                        '-out',
                        file(subject, 'csr'),
                    ],
                    base,
                )
                fs.writeFileSync(file(subject, 'cnf'), config)
                await runOpenSSL(
                    [
                        'x509',
                        '-req',
                        '-in',
                        file(subject, 'csr'),
                        '-CA',
                        file(issuer),
                        '-CAkey',
                        `${base}/${issuer}.key`,
                        '-days',
                        '30',
                        '-extfile',
                        file(subject, 'cnf'),
                        '-extensions',
                        'ext',
                        '-out',
                        file(subject),
                    ],
                    base,
                )
            }
            let issuer = 'root'
            for (const [index, ca] of scenario.cas.entries()) {
                const name = `ca${index + 1}`
                await sign(
                    name,
                    ca.subject ?? `/CN=NameConstraintsCA${index + 1}`,
                    issuer,
                    caConfig(ca, scenario.dirs),
                )
                issuer = name
            }
            await sign(
                'leaf',
                scenario.leafSubject ?? '/CN=leaf',
                issuer,
                leafConfig(scenario.leafSan),
            )

            const intermediates = scenario.cas.map((_, i) => `ca${i + 1}`)
            const untrusted = file('untrusted')
            fs.writeFileSync(
                untrusted,
                intermediates
                    .map((n) => fs.readFileSync(file(n), 'utf8'))
                    .join(''),
            )
            const pem = (name: string) =>
                Certificate.fromPem(fs.readFileSync(file(name), 'utf8'))
            return {
                files: { root: file('root'), untrusted, leaf: file('leaf') },
                root: pem('root'),
                intermediates: intermediates.map(pem),
                leaf: pem('leaf'),
            }
        }

        async function opensslAccepts(files: {
            root: string
            untrusted: string
            leaf: string
        }): Promise<{ accepted: boolean; output: string }> {
            try {
                await runOpenSSL(
                    [
                        'verify',
                        '-CAfile',
                        files.root,
                        '-untrusted',
                        files.untrusted,
                        files.leaf,
                    ],
                    base,
                )
                return { accepted: true, output: '' }
            } catch (error) {
                return { accepted: false, output: String(error) }
            }
        }

        for (const scenario of scenarios) {
            test(scenario.name, async () => {
                const chain = await issue(scenario)
                const result = await new CertificateValidator().validate(
                    chain.leaf,
                    {
                        validateChain: true,
                        trustAnchors: [{ certificate: chain.root }],
                        otherCertificates: chain.intermediates,
                    },
                )
                const openssl = await opensslAccepts(chain.files)

                expect(result.isValid, result.messages.join('; ')).toBe(
                    scenario.valid,
                )
                expect(openssl.accepted, openssl.output).toBe(scenario.valid)
                if (!scenario.valid) {
                    // rejected for the name constraint, not some unrelated reason
                    expect(result.messages.join('; ')).toMatch(
                        /name constraint/i,
                    )
                    expect(openssl.output).toMatch(/name constraint|subtree/i)
                }
            })
        }
    },
)
