import { spawn } from 'child_process'
import { randomUUID } from 'crypto'
import fs from 'fs'

function getTempFolder(): string {
    const tmpFolder = `${import.meta.dirname}/tmp/${randomUUID()}`
    if (!fs.existsSync(tmpFolder)) {
        fs.mkdirSync(tmpFolder, { recursive: true })
    }
    return tmpFolder
}

export async function runOpenSSL(args: string[], debugFolder: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const dockerOpenssl = `docker run --rm -v ${debugFolder}:/data -w /data alpine/openssl:latest`
        fs.writeFileSync(debugFolder + '/debug.sh', `${dockerOpenssl} ${args.map(x => x.replace(debugFolder + '/', '')).join(' ')}`, {
            mode: 0o755,
        })

        const child = spawn('./debug.sh', { cwd: debugFolder, shell: true })

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
    data: Uint8Array
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
        const output = await runOpenSSL(args, tmpFolder)

        return {
            success: true,
            data: fs.readFileSync(`${tmpFolder}/decrypted.bin`),
        }
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
            data: fs.readFileSync(`${tmpFolder}/decrypted.bin`),
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
