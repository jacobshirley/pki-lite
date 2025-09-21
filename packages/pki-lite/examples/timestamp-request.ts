import { DigestAlgorithmIdentifier } from '../src/algorithms/AlgorithmIdentifier.js'
import { MessageImprint } from '../src/timestamp/MessageImprint.js'
import { TimeStampReq } from '../src/timestamp/TimeStampReq.js'

// 1. Create a message to be timestamped (usually this would be a signature)
const messageToTimestamp = new TextEncoder().encode('Hello, World!')

// 2. Create a hash of the message using SHA-256
const hashBuffer = await crypto.subtle.digest('SHA-256', messageToTimestamp)
const hashBytes = new Uint8Array(hashBuffer)

console.log(
    'Message hash (SHA-256):',
    Array.from(hashBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(''),
)

// 3. Create the MessageImprint
const hashAlgorithm = DigestAlgorithmIdentifier.digestAlgorithm('SHA-256')
const messageImprint = new MessageImprint({
    hashAlgorithm: hashAlgorithm,
    hashedMessage: hashBytes,
})

// 4. Create the TimeStampReq
const nonce = crypto.getRandomValues(new Uint8Array(8)) // Random 8-byte nonce
const tsReq = TimeStampReq.create({
    messageImprint,
    certReq: true, // Request certificates in the response
    nonce: nonce,
})

console.log('TimeStampReq created:')
console.log('- Version:', tsReq.version)
console.log('- Hash Algorithm:', tsReq.messageImprint.hashAlgorithm.algorithm)
console.log('- Certificate Requested:', tsReq.certReq)

// 5. Generate the DER encoding for sending to a TSA server
const derEncoded = tsReq.toDer()
console.log('DER encoded request size:', derEncoded.length, 'bytes')

const response = await tsReq.request({
    url: 'https://freetsa.org/tsr',
    timeout: 10000,
})

console.log('Response status:', response.status.getStatusDescription())

if (response.isSuccess()) {
    console.log('Timestamp token received!')
    const tokenDer = response.getTimeStampTokenDer()
    if (tokenDer) {
        console.log('Token size:', tokenDer.length, 'bytes')
    }
}

// 7. Demonstrate parsing a TimeStampReq from DER
const parsedReq = TimeStampReq.fromDer(derEncoded)
console.log('Parsed request version:', parsedReq.version)
console.log('Parsed request certReq:', parsedReq.certReq)

console.log('TimeStampResp created:')
console.log('- Status:', response.status.getStatusDescription())
console.log('- Success:', response.isSuccess())
console.log('- Has token:', !!response.timeStampToken)

const respDer = response.toDer()
console.log('DER encoded response size:', respDer.length, 'bytes')
