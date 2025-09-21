import { spawn } from 'child_process'
import fs from 'fs'

export async function runOpenSSL(args: string[]): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const child = spawn('openssl', args)
        const output: Buffer[] = []
        const error: Buffer[] = []

        child.stdout.on('data', (chunk) => output.push(chunk))
        child.stderr.on('data', (chunk) => error.push(chunk))

        child.on('close', (code) => {
            if (code === 0) {
                resolve(Buffer.concat(output))
            } else {
                reject(
                    new Error(
                        `OpenSSL exited with code ${code}: [args: ${args.join(' ')}] ${Buffer.concat(error).toString()}`,
                    ),
                )
            }
        })
    })
}

export async function opensslValidate(options: {
    signature: Uint8Array
    caCert?: Uint8Array
    data?: Uint8Array
}): Promise<void> {
    const { signature, caCert, data } = options

    const tmpFile = fs.mkdtempSync('/tmp/openssl-')
    const signaturePath = `${tmpFile}/signature.der`
    const dataPath = `${tmpFile}/data.bin`
    const caCertPath = `${tmpFile}/caCert.pem`

    fs.writeFileSync(signaturePath, signature)
    data && fs.writeFileSync(dataPath, data)
    caCert && fs.writeFileSync(caCertPath, caCert)

    const args = [
        'cms',
        '-verify',
        '-inform',
        'DER',
        '-in',
        signaturePath,
        ...(caCert ? ['-CAfile', caCertPath] : []),
        ...(data ? ['-content', dataPath] : []),
    ].flat()

    const result = await runOpenSSL(args)
    if (!result.length) {
        throw new Error('Signature validation failed')
    }
}

export async function opensslCmsToText(signature: Uint8Array): Promise<string> {
    const tmpFile = fs.mkdtempSync('/tmp/openssl-')
    const signaturePath = `${tmpFile}/signature.der`

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

    const result = await runOpenSSL(args)
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
    data: Uint8Array
    error?: string
}> {
    const { envelopedData, recipientCertificatePem, recipientPrivateKeyPem } =
        options

    const tmpFile = fs.mkdtempSync('/tmp/openssl-')
    const envelopedDataPath = `${tmpFile}/envelopedData.der`
    const recipientCertificatePath = `${tmpFile}/recipient.pem`
    const recipientPrivateKeyPath = `${tmpFile}/recipient.key`

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
        `${tmpFile}/decrypted.bin`,
        '-recip',
        recipientCertificatePath,
        '-inkey',
        recipientPrivateKeyPath,
    ]

    try {
        const output = await runOpenSSL(args)

        return {
            success: true,
            data: fs.readFileSync(`${tmpFile}/decrypted.bin`),
        }
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
            data: fs.readFileSync(`${tmpFile}/decrypted.bin`),
        }
    }
}

export async function opensslAsn1Parse(asn1Data: Uint8Array): Promise<any> {
    const tmpFile = fs.mkdtempSync('/tmp/openssl-')
    const asn1Path = `${tmpFile}/data.der`

    fs.writeFileSync(asn1Path, asn1Data)

    const args = ['cms', '-inform', 'DER', '-in', asn1Path, '-cmsout', '-print']

    const result = await runOpenSSL(args)
    if (!result.length) {
        throw new Error('Failed to parse ASN.1 data')
    }

    return result.toString()
}
