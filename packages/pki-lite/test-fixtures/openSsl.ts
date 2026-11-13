import { spawn, spawnSync } from 'child_process'
import { randomUUID } from 'crypto'
import fs from 'fs'

function getTempFolder(): string {
    const tmpFolder = `${import.meta.dirname}/tmp/${randomUUID()}`
    if (!fs.existsSync(tmpFolder)) {
        fs.mkdirSync(tmpFolder, { recursive: true })
    }
    return tmpFolder
}

const hasCommand = (command: string) =>
    spawnSync(command, ['--version'], { stdio: 'ignore' }).status === 0

// CI runs OpenSSL from a pinned docker image; where docker is unavailable (e.g. a dev
// machine without it) fall back to an `openssl` on PATH.
const useDocker = hasCommand('docker')

/**
 * Runs OpenSSL in `debugFolder` and returns its exit code and output, whether or not it
 * succeeded (for tests of what OpenSSL rejects). File arguments must be inside
 * `debugFolder`.
 */
export async function runOpenSSLResult(
    args: string[],
    debugFolder: string,
): Promise<{ code: number; stdout: Buffer; stderr: string }> {
    return new Promise((resolve) => {
        const relativeArgs = args.map((x) => x.replace(debugFolder + '/', ''))
        const openssl = useDocker
            ? `docker run --rm -v ${debugFolder}:/data -w /data alpine/openssl:latest`
            : 'openssl'
        fs.writeFileSync(
            debugFolder + '/debug.sh',
            `${openssl} ${relativeArgs.join(' ')}`,
            {
                mode: 0o755,
            },
        )

        const child = spawn('./debug.sh', { cwd: debugFolder, shell: true })

        const output: Buffer[] = []
        const error: Buffer[] = []

        child.stdout.on('data', (chunk) => output.push(chunk))
        child.stderr.on('data', (chunk) => error.push(chunk))

        child.on('close', (code) =>
            resolve({
                code: code ?? -1,
                stdout: Buffer.concat(output),
                stderr: Buffer.concat(error).toString(),
            }),
        )
    })
}

export async function runOpenSSL(
    args: string[],
    debugFolder: string,
): Promise<Buffer> {
    const { code, stdout, stderr } = await runOpenSSLResult(args, debugFolder)
    if (code !== 0) {
        throw new Error(
            `OpenSSL exited with code ${code}: [args: ${args.join(' ')}] ${stderr}`,
        )
    }
    return stdout
}

export async function opensslValidate(options: {
    signature: Uint8Array
    caCertPem?: string
    data?: Uint8Array
}): Promise<void> {
    const { signature, caCertPem, data } = options

    const tmpFolder = getTempFolder()
    const signaturePath = `${tmpFolder}/signature.der`
    const dataPath = `${tmpFolder}/data.bin`
    const caCertPath = `${tmpFolder}/caCert.pem`

    fs.writeFileSync(signaturePath, signature)
    data && fs.writeFileSync(dataPath, data)
    caCertPem && fs.writeFileSync(caCertPath, caCertPem)

    if (!fs.existsSync(signaturePath)) {
        throw new Error('Signature file not found')
    }
    if (caCertPem && !fs.existsSync(caCertPath)) {
        throw new Error('CA certificate file not found')
    }
    if (data && !fs.existsSync(dataPath)) {
        throw new Error('Data file not found')
    }

    const args = [
        'cms',
        '-verify',
        '-inform',
        'DER',
        '-in',
        signaturePath,
        ...(caCertPem ? ['-CAfile', caCertPath] : []),
        ...(data ? ['-content', dataPath] : []),
    ].flat()

    const result = await runOpenSSL(args, tmpFolder)
    if (!result.length) {
        throw new Error('Signature validation failed')
    }
}

export async function opensslCmsToText(signature: Uint8Array): Promise<string> {
    const tmpFolder = getTempFolder()
    const signaturePath = `${tmpFolder}/signature.der`

    fs.writeFileSync(signaturePath, signature)

    const args = [
        'cms',
        '-inform',
        'DER',
        '-in',
        signaturePath,
        '-noverify',
        '-cmsout',
        '-print',
    ]

    const result = await runOpenSSL(args, tmpFolder)
    if (!result.length) {
        throw new Error('Failed to convert CMS to text')
    }

    return result.toString()
}

export async function opensslCmsDecrypt(options: {
    envelopedData: Uint8Array
    recipientCertificatePem: string
    recipientPrivateKeyPem: string
}): Promise<{
    success: boolean
    /** The decrypted content, when decryption succeeded */
    plaintext?: Uint8Array
    error?: string
}> {
    const { envelopedData, recipientCertificatePem, recipientPrivateKeyPem } =
        options

    const tmpFolder = getTempFolder()
    const envelopedDataPath = `${tmpFolder}/envelopedData.der`
    const recipientCertificatePath = `${tmpFolder}/recipient.pem`
    const recipientPrivateKeyPath = `${tmpFolder}/recipient.key`

    fs.writeFileSync(envelopedDataPath, envelopedData)
    fs.writeFileSync(recipientCertificatePath, recipientCertificatePem)
    fs.writeFileSync(recipientPrivateKeyPath, recipientPrivateKeyPem)

    const args = [
        'cms',
        '-decrypt',
        '-inform',
        'DER',
        '-in',
        envelopedDataPath,
        '-out',
        `${tmpFolder}/decrypted.bin`,
        '-recip',
        recipientCertificatePath,
        '-inkey',
        recipientPrivateKeyPath,
    ]

    try {
        await runOpenSSL(args, tmpFolder)

        return {
            success: true,
            plaintext: new Uint8Array(
                fs.readFileSync(`${tmpFolder}/decrypted.bin`),
            ),
        }
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        }
    }
}

export async function opensslAsn1Parse(asn1Data: Uint8Array): Promise<any> {
    const tmpFolder = getTempFolder()
    const asn1Path = `${tmpFolder}/data.der`

    fs.writeFileSync(asn1Path, asn1Data)

    const args = ['cms', '-inform', 'DER', '-in', asn1Path, '-cmsout', '-print']

    const result = await runOpenSSL(args, tmpFolder)
    if (!result.length) {
        throw new Error('Failed to parse ASN.1 data')
    }

    return result.toString()
}

export async function opensslVerifyCertificate(options: {
    certificate: Uint8Array | string
    caCertificate?: Uint8Array | string
    selfSigned?: boolean
}): Promise<{
    success: boolean
    error?: string
}> {
    const { certificate, caCertificate, selfSigned } = options

    const tmpFolder = getTempFolder()
    const certPath = `${tmpFolder}/cert.pem`
    const caCertPath = `${tmpFolder}/ca.pem`

    // Write certificate
    if (typeof certificate === 'string') {
        fs.writeFileSync(certPath, certificate)
    } else {
        // Convert DER to PEM if needed
        const pem = `-----BEGIN CERTIFICATE-----\n${Buffer.from(certificate)
            .toString('base64')
            .match(/.{1,64}/g)
            ?.join('\n')}\n-----END CERTIFICATE-----\n`
        fs.writeFileSync(certPath, pem)
    }

    // Write CA certificate if provided
    if (caCertificate) {
        if (typeof caCertificate === 'string') {
            fs.writeFileSync(caCertPath, caCertificate)
        } else {
            const pem = `-----BEGIN CERTIFICATE-----\n${Buffer.from(
                caCertificate,
            )
                .toString('base64')
                .match(/.{1,64}/g)
                ?.join('\n')}\n-----END CERTIFICATE-----\n`
            fs.writeFileSync(caCertPath, pem)
        }
    }

    const args = [
        'verify',
        ...(selfSigned ? ['-CAfile', certPath] : []),
        ...(caCertificate ? ['-CAfile', caCertPath] : []),
        certPath,
    ]

    try {
        const output = await runOpenSSL(args, tmpFolder)
        const result = output.toString()

        // OpenSSL verify returns "<path>: OK" on success
        if (result.includes('OK')) {
            return { success: true }
        }

        return {
            success: false,
            error: result,
        }
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        }
    }
}

/**
 * Parses a PKCS#12 (PFX) file with OpenSSL using the given password and
 * returns the extracted PEM contents (concatenated certificates and key).
 */
export async function opensslPkcs12Parse(options: {
    pfx: Uint8Array
    password: string
}): Promise<{
    success: boolean
    output?: string
    error?: string
}> {
    const tmpFolder = getTempFolder()
    const pfxPath = `${tmpFolder}/in.p12`
    fs.writeFileSync(pfxPath, options.pfx)

    const args = [
        'pkcs12',
        '-in',
        pfxPath,
        '-password',
        `pass:${options.password}`,
        '-nodes',
    ]

    try {
        const output = await runOpenSSL(args, tmpFolder)
        return { success: true, output: output.toString() }
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        }
    }
}

/**
 * Has OpenSSL parse a PKCS#10 certificate request and verify its self-signature.
 * Returns the `-text` rendering so callers can check the contents.
 */
export async function opensslVerifyCsr(options: { csr: string }): Promise<{
    success: boolean
    text?: string
    error?: string
}> {
    const tmpFolder = getTempFolder()
    fs.writeFileSync(`${tmpFolder}/csr.pem`, options.csr)

    try {
        const output = await runOpenSSL(
            ['req', '-in', 'csr.pem', '-noout', '-verify', '-text'],
            tmpFolder,
        )
        // "Certificate request self-signature verify OK" goes to stderr, so a zero
        // exit status is what tells us the request parsed and verified.
        return { success: true, text: output.toString() }
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        }
    }
}

/** The certificates of {@link opensslOcspPki} */
export type OcspPkiName =
    | 'ca'
    | 'good'
    | 'revoked'
    | 'responder'
    | 'notResponder'
    | 'otherCa'
    | 'otherCaSameSerial'

/**
 * A small PKI made with OpenSSL for OCSP tests, plus OpenSSL as an OCSP client and
 * responder over it:
 *
 * - `ca` issues `good` (serial 1001), `revoked` (1002, revoked for keyCompromise on
 *   2025-01-01), `responder` (a delegated responder: extendedKeyUsage OCSPSigning) and
 *   `notResponder` (no OCSPSigning)
 * - `otherCa` issues `otherCaSameSerial`, with the same serial as `revoked` (1002), which
 *   `otherCa`'s responder reports as good
 */
export async function opensslOcspPki() {
    const dir = getTempFolder()
    const p = (name: string) => `${dir}/${name}`
    const run = (args: string[]) => runOpenSSL(args, dir)

    const selfSigned = async (name: string, cn: string) =>
        run([
            'req',
            '-x509',
            '-newkey',
            'rsa:2048',
            '-nodes',
            '-sha256',
            '-keyout',
            p(`${name}.key`),
            '-out',
            p(`${name}.pem`),
            '-days',
            '3650',
            '-subj',
            `/CN=${cn}`,
            '-addext',
            'basicConstraints=critical,CA:TRUE',
            '-addext',
            'keyUsage=critical,keyCertSign,cRLSign',
        ])
    const issue = async (
        name: string,
        issuer: string,
        serial: string,
        extensions: string[],
    ) => {
        await run([
            'req',
            '-newkey',
            'rsa:2048',
            '-nodes',
            '-sha256',
            '-keyout',
            p(`${name}.key`),
            '-out',
            p(`${name}.csr`),
            '-subj',
            `/CN=${name}`,
        ])
        fs.writeFileSync(p(`${name}.ext`), extensions.join('\n') + '\n')
        await run([
            'x509',
            '-req',
            '-sha256',
            '-in',
            p(`${name}.csr`),
            '-CA',
            p(`${issuer}.pem`),
            '-CAkey',
            p(`${issuer}.key`),
            '-set_serial',
            `0x${serial}`,
            '-days',
            '365',
            '-extfile',
            p(`${name}.ext`),
            '-out',
            p(`${name}.pem`),
        ])
    }

    await selfSigned('ca', 'OcspTestCA')
    await selfSigned('otherCa', 'OcspOtherCA')
    const leaf = [
        'basicConstraints=CA:FALSE',
        'keyUsage=critical,digitalSignature',
    ]
    await issue('good', 'ca', '1001', leaf)
    await issue('revoked', 'ca', '1002', leaf)
    await issue('responder', 'ca', '1003', [
        ...leaf,
        'extendedKeyUsage=OCSPSigning',
    ])
    await issue('notResponder', 'ca', '1004', leaf)
    await issue('otherCaSameSerial', 'otherCa', '1002', leaf)

    // openssl ca database: status, expiry, revocation date[,reason], serial, file, DN
    const row = (fields: string[]) => fields.join('\t') + '\n'
    fs.writeFileSync(
        p('ca.index'),
        row(['V', '351231235959Z', '', '1001', 'unknown', '/CN=good']) +
            row([
                'R',
                '351231235959Z',
                '250101000000Z,keyCompromise',
                '1002',
                'unknown',
                '/CN=revoked',
            ]) +
            row([
                'V',
                '351231235959Z',
                '',
                '1003',
                'unknown',
                '/CN=responder',
            ]) +
            row([
                'V',
                '351231235959Z',
                '',
                '1004',
                'unknown',
                '/CN=notResponder',
            ]),
    )
    fs.writeFileSync(
        p('otherCa.index'),
        row([
            'V',
            '351231235959Z',
            '',
            '1002',
            'unknown',
            '/CN=otherCaSameSerial',
        ]),
    )

    // Read the keys through OpenSSL: with docker they belong to root and are mode 0600
    const names: OcspPkiName[] = [
        'ca',
        'good',
        'revoked',
        'responder',
        'notResponder',
        'otherCa',
        'otherCaSameSerial',
    ]
    const keys = new Map<OcspPkiName, string>()
    for (const name of names) {
        keys.set(
            name,
            (await run(['pkey', '-in', p(`${name}.key`)])).toString(),
        )
    }

    let counter = 0
    const tmp = (ext: string) => p(`tmp-${++counter}.${ext}`)

    return {
        pem: (name: OcspPkiName) => fs.readFileSync(p(`${name}.pem`), 'utf8'),
        key: (name: OcspPkiName) => keys.get(name)!,

        /** An OCSP request made by OpenSSL (no nonce) for `cert`, issued by `issuer` */
        async request(options: {
            cert: OcspPkiName
            issuer?: OcspPkiName
            hash?: 'sha1' | 'sha256'
        }): Promise<Uint8Array> {
            const out = tmp('req')
            await run([
                'ocsp',
                '-no_nonce',
                `-${options.hash ?? 'sha1'}`,
                '-issuer',
                p(`${options.issuer ?? 'ca'}.pem`),
                '-cert',
                p(`${options.cert}.pem`),
                '-reqout',
                out,
            ])
            return new Uint8Array(fs.readFileSync(out))
        },

        /** The text OpenSSL prints for a request (`ocsp -req_text`) */
        async requestText(request: Uint8Array): Promise<string> {
            const file = tmp('req')
            fs.writeFileSync(file, request)
            return (
                await run(['ocsp', '-reqin', file, '-req_text', '-noverify'])
            ).toString()
        },

        /**
         * OpenSSL's answer to `request` as the responder for `ca` (or `otherCa`), signed
         * by `signer` (the CA itself by default)
         */
        async respond(options: {
            request: Uint8Array
            ca?: 'ca' | 'otherCa'
            signer?: OcspPkiName
            /** identify the responder by key hash rather than by name */
            byKey?: boolean
        }): Promise<Uint8Array> {
            const ca = options.ca ?? 'ca'
            const signer = options.signer ?? ca
            const reqFile = tmp('req')
            const out = tmp('resp')
            fs.writeFileSync(reqFile, options.request)
            await run([
                'ocsp',
                '-index',
                p(`${ca}.index`),
                '-CA',
                p(`${ca}.pem`),
                '-rsigner',
                p(`${signer}.pem`),
                '-rkey',
                p(`${signer}.key`),
                '-reqin',
                reqFile,
                '-respout',
                out,
                '-ndays',
                '7',
                ...(options.byKey ? ['-resp_key_id'] : []),
            ])
            return new Uint8Array(fs.readFileSync(out))
        },

        /**
         * Checks `response` as an OCSP client for `cert` (issued by `issuer`), trusting
         * `ca`: whether OpenSSL verifies the response, and the status it reports.
         */
        async verify(options: {
            response: Uint8Array
            cert: OcspPkiName
            issuer?: OcspPkiName
        }): Promise<{ verified: boolean; status?: string; output: string }> {
            const respFile = tmp('resp')
            fs.writeFileSync(respFile, options.response)
            const issuer = options.issuer ?? 'ca'
            const result = await runOpenSSLResult(
                [
                    'ocsp',
                    '-respin',
                    respFile,
                    '-issuer',
                    p(`${issuer}.pem`),
                    '-cert',
                    p(`${options.cert}.pem`),
                    '-CAfile',
                    p(`${issuer}.pem`),
                ],
                dir,
            )
            const output = result.stdout.toString() + result.stderr
            const status = output.match(
                new RegExp(`${options.cert}\\.pem: (good|revoked|unknown)`),
            )?.[1]
            return {
                verified: output.includes('Response verify OK'),
                status,
                output,
            }
        },
    }
}
