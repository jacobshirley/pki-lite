import { EnvelopedData } from '../../src/pkcs7/EnvelopedData.js'
import { Certificate } from '../../src/x509/Certificate.js'
import { describe, test, expect } from 'vitest'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'
import {
    opensslCmsDecrypt,
    opensslCmsToText,
    opensslValidate,
} from '../../test-fixtures/openSsl.js'
import { PrivateKeyInfo } from '../../src/keys/PrivateKeyInfo.js'
import { SignedData } from '../../src/pkcs7/SignedData.js'
import { SigningCertificateV2 } from '../../src/x509/attributes/SigningCertificateV2.js'
import { Attribute } from '../../src/x509/Attribute.js'
import { CertificateList } from '../../src/x509/CertificateList.js'
import { OCSPResponse } from '../../src/ocsp/OCSPResponse.js'
import { ContentInfo } from '../../src/pkcs7/ContentInfo.js'
import { OIDs } from '../../src/core/OIDs.js'
import { UTCTime } from '../../src/asn1/UTCTime.js'
import { ecP256SigningKeys } from '../../test-fixtures/signing-keys/ec-p256/index.js'

describe('OpenSSL compatibility', { timeout: 60000 }, () => {
    describe('EnvelopedData', () => {
        test('Envelope Data should be decryptable with OpenSSL', async () => {
            const data = 'Hello World'

            const envelopedData = (
                await EnvelopedData.builder()
                    .setData(data)
                    .addRecipient({
                        certificate: Certificate.fromPem(
                            rsaSigningKeys.certPem,
                        ),
                    })
                    .build()
            ).toCms()

            const der = envelopedData.toDer()

            const parsed = EnvelopedData.fromCms(envelopedData)
            const decrypted = await parsed.decrypt(
                PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem),
            )
            expect(new TextDecoder().decode(decrypted)).toEqual(data)

            const res = await opensslCmsDecrypt({
                envelopedData: der,
                recipientCertificatePem: rsaSigningKeys.certPem,
                recipientPrivateKeyPem: rsaSigningKeys.privateKeyPem,
            })

            if (res.error) {
                throw new Error(res.error)
            }
        })
    })

    describe('SignedData', () => {
        test('Create RSASSA_PKCS1_v1_5/SHA-256 Signed Data signature with CRLs and OCSP responses', async () => {
            const data = new TextEncoder().encode('test')
            const signedData = await SignedData.builder()
                .setData(data)
                .addSigner({
                    privateKeyInfo: PrivateKeyInfo.fromDer(
                        rsaSigningKeys.privateKey,
                    ),
                    certificate: Certificate.fromDer(rsaSigningKeys.cert),
                    encryptionAlgorithm: {
                        type: 'RSASSA_PKCS1_v1_5',
                        params: {
                            hash: 'SHA-256',
                        },
                    },
                    signedAttrs: [
                        Attribute.signingTime(new Date('2025-08-24T12:00:00Z')),
                        Attribute.signingLocation({
                            countryName: 'US',
                            localityName: 'Local',
                            postalAddress: '12345',
                        }),
                        Attribute.signingCertificateV2(
                            await SigningCertificateV2.fromCertificates({
                                certificates: [
                                    Certificate.fromDer(rsaSigningKeys.cert),
                                ],
                            }),
                        ),
                    ],
                })
                .addCrl(CertificateList.fromPem(rsaSigningKeys.caCrlPem))
                .addOcsp(OCSPResponse.fromDer(rsaSigningKeys.ocspResponse))
                .detached()
                .build()

            const verified = await signedData.verify({ data })
            expect(verified).toEqual({
                valid: true,
                signerInfo: signedData.signerInfos[0],
            })

            const derEncoded = new ContentInfo({
                contentType: OIDs.PKCS7.SIGNED_DATA,
                content: signedData,
            }).toDer()

            // Use OpenSSL to validate the signed data using the ContentInfo wrapper
            await opensslValidate({
                signature: derEncoded, // Use the ContentInfo wrapper
                data,
                caCertPem: rsaSigningKeys.caCertPem,
            })

            const cmsStructure = await opensslCmsToText(derEncoded)
            expect(cmsStructure).toMatchInlineSnapshot(`
              "CMS_ContentInfo: 
                contentType: pkcs7-signedData (1.2.840.113549.1.7.2)
                d.signedData: 
                  version: 5
                  digestAlgorithms:
                      algorithm: sha256 (2.16.840.1.101.3.4.2.1)
                      parameter: <ABSENT>
                  encapContentInfo: 
                    eContentType: pkcs7-data (1.2.840.113549.1.7.1)
                    eContent: <ABSENT>
                  certificates:
                    d.certificate: 
                      cert_info: 
                        version: 2
                        serialNumber: 0x0726DAC7F46E2747C424C4225CB43FDDD2AFAA1A
                        signature: 
                          algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                          parameter: NULL
                        issuer:           C=US, ST=Test, L=Local, O=MyOrg, OU=CA, CN=MyRootCA
                        validity: 
                          notBefore: Oct  1 19:05:30 2025 GMT
                          notAfter: Oct  1 19:05:30 2026 GMT
                        subject:           C=US, ST=Test, L=Local, O=MyOrg, OU=Signing, CN=John Doe
                        key:           X509_PUBKEY: 
                          algor: 
                            algorithm: rsaEncryption (1.2.840.113549.1.1.1)
                            parameter: NULL
                          public_key:  (0 unused bits)
                            0000 - 30 82 01 0a 02 82 01 01-00 b8 90 bb 63 13   0...........c.
                            000e - f3 5e 51 19 31 bd 50 cf-9f 18 27 f9 2d 2e   .^Q.1.P...'.-.
                            001c - 19 b2 17 0b a8 df c0 9e-bb b5 bc ff e3 ea   ..............
                            002a - 5e 84 a0 00 53 71 b7 07-60 40 c4 9d 94 c9   ^...Sq..\`@....
                            0038 - 8b 68 09 17 62 9d 10 59-f6 75 02 95 6c 83   .h..b..Y.u..l.
                            0046 - b5 2f c8 de 84 9f 01 90-85 36 96 db 7a 38   ./.......6..z8
                            0054 - eb 0f 32 6b e6 b2 1d 0f-7b 92 51 a8 e8 c5   ..2k....{.Q...
                            0062 - 2e a6 3a d3 9f 0c a7 99-8b 89 2a ed 71 62   ..:.......*.qb
                            0070 - 67 bd 62 7b 08 87 e0 7d-d1 0d 16 67 5d bb   g.b{...}...g].
                            007e - 13 91 52 e5 0c aa fb 1c-69 26 77 af c1 aa   ..R.....i&w...
                            008c - 49 0c 1c 07 c7 e3 be 24-a0 99 54 4b 5f 74   I......$..TK_t
                            009a - 65 70 50 eb c2 b9 63 d4-9f 35 bf 8c bc d4   epP...c..5....
                            00a8 - 1c 47 f3 bb cb 72 83 1a-ab f0 24 ee 4f b8   .G...r....$.O.
                            00b6 - 7d d6 39 57 4c b9 63 e0-d9 24 52 a8 c5 11   }.9WL.c..$R...
                            00c4 - 74 f0 09 8f 10 c2 2c aa-ea 4d e9 6f 77 04   t.....,..M.ow.
                            00d2 - 1f 98 38 86 cb 6a 63 36-44 87 c2 80 f0 31   ..8..jc6D....1
                            00e0 - f6 6c d2 f7 f2 13 fb b1-e5 15 e0 71 29 85   .l.........q).
                            00ee - 76 9f 10 92 1e a0 cf bb-49 ce dc ee 21 d3   v.......I...!.
                            00fc - 99 51 3d 65 9b 79 cb 3e-b0 4b 7e f0 87 02   .Q=e.y.>.K~...
                            010a - 03 01 00 01                                 ....
                        issuerUID: <ABSENT>
                        subjectUID: <ABSENT>
                        extensions:
                            object: X509v3 Basic Constraints (2.5.29.19)
                            critical: FALSE
                            value: 
                              0000 - 30 00                                    0.

                            object: X509v3 Key Usage (2.5.29.15)
                            critical: FALSE
                            value: 
                              0000 - 03 02 06 c0                              ....

                            object: X509v3 Extended Key Usage (2.5.29.37)
                            critical: FALSE
                            value: 
                              0000 - 30 14 06 08 2b 06 01 05-05 07 03 04 06   0...+........
                              000d - 08 2b 06 01 05 05 07 03-03               .+.......

                            object: X509v3 CRL Distribution Points (2.5.29.31)
                            critical: FALSE
                            value: 
                              0000 - 30 24 30 22 a0 20 a0 1e-86 1c 68 74 74   0$0". ....htt
                              000d - 70 3a 2f 2f 6c 6f 63 61-6c 68 6f 73 74   p://localhost
                              001a - 3a 38 30 38 30 2f 63 61-2e 63 72 6c      :8080/ca.crl

                            object: Authority Information Access (1.3.6.1.5.5.7.1.1)
                            critical: FALSE
                            value: 
                              0000 - 30 81 81 30 28 06 08 2b-06 01 05 05 07   0..0(..+.....
                              000d - 30 02 86 1c 68 74 74 70-3a 2f 2f 6c 6f   0...http://lo
                              001a - 63 61 6c 68 6f 73 74 3a-38 30 38 30 2f   calhost:8080/
                              0027 - 63 61 2e 63 72 74 30 26-06 08 2b 06 01   ca.crt0&..+..
                              0034 - 05 05 07 30 01 86 1a 68-74 74 70 3a 2f   ...0...http:/
                              0041 - 2f 6c 6f 63 61 6c 68 6f-73 74 3a 38 30   /localhost:80
                              004e - 38 30 2f 6f 63 73 70 30-2d 06 08 2b 06   80/ocsp0-..+.
                              005b - 01 05 05 07 30 01 86 21-68 74 74 70 3a   ....0..!http:
                              0068 - 2f 2f 6c 6f 63 61 6c 68-6f 73 74 3a 38   //localhost:8
                              0075 - 30 38 30 2f 6f 63 73 70-2d 62 61 63 6b   080/ocsp-back
                              0082 - 75 70                                    up

                            object: X509v3 Subject Key Identifier (2.5.29.14)
                            critical: FALSE
                            value: 
                              0000 - 04 14 b2 66 14 17 61 8a-03 ef 86 7c 09   ...f..a....|.
                              000d - 2a 15 4b 31 22 4b 7a b5-37               *.K1"Kz.7

                            object: X509v3 Authority Key Identifier (2.5.29.35)
                            critical: FALSE
                            value: 
                              0000 - 30 16 80 14 10 21 ab 93-d5 b7 99 9f 76   0....!......v
                              000d - e0 42 ef 98 1e 78 a7 e5-42 21 f5         .B...x..B!.
                      sig_alg: 
                        algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                        parameter: NULL
                      signature:  (0 unused bits)
                        0000 - 3c 0a 31 2c 37 79 ed 79-c1 99 e1 38 b4 e6 29   <.1,7y.y...8..)
                        000f - b9 53 f5 57 76 33 c4 cf-0a fb c0 a8 d3 17 12   .S.Wv3.........
                        001e - 07 1f 3a 23 8f 02 33 4c-48 f0 28 d6 26 13 e0   ..:#..3LH.(.&..
                        002d - 0e 6b 4b b0 85 b8 7f ae-8a e0 29 82 80 f9 63   .kK.......)...c
                        003c - 45 f7 96 6d a5 f4 0f 19-05 92 8e c7 5a 04 59   E..m........Z.Y
                        004b - d6 28 9d 49 6e d9 37 15-48 80 a5 69 2f c1 79   .(.In.7.H..i/.y
                        005a - 82 34 48 2c 6b c6 43 8f-89 a4 d2 09 fd 39 19   .4H,k.C......9.
                        0069 - 60 9a 11 36 03 f8 e4 d6-67 9e 6c fd 57 21 9a   \`..6....g.l.W!.
                        0078 - c7 af 6c c0 63 04 2f 65-e0 78 d9 76 33 60 44   ..l.c./e.x.v3\`D
                        0087 - f4 58 73 62 15 fe 7c 97-be 0d 31 10 8a cb c6   .Xsb..|...1....
                        0096 - 32 70 64 04 6f 65 1e 7f-ab 83 a1 75 43 10 82   2pd.oe.....uC..
                        00a5 - 81 8d 78 23 51 21 bc 8e-c4 9a 93 c6 a0 e2 be   ..x#Q!.........
                        00b4 - 79 f2 40 ad 44 0c 01 2e-6b a8 45 39 6e cc 67   y.@.D...k.E9n.g
                        00c3 - 33 4d 2e 8d c7 4d 65 a8-62 d4 d5 c7 59 c7 a8   3M...Me.b...Y..
                        00d2 - f7 a7 3f 14 ff db 17 db-31 89 da 28 12 71 8e   ..?.....1..(.q.
                        00e1 - a2 1d 47 25 2c 28 f5 21-9e c5 a4 3a 0b 6a e4   ..G%,(.!...:.j.
                        00f0 - e6 b5 d0 2a 21 17 1a 21-f0 25 56 d3 33 b3 d3   ...*!..!.%V.3..
                        00ff - 90 ab 7f 87 8d c1 ea 2f-a6 88 0f 7f 4a c8 18   ......./....J..
                        010e - 02 2b 53 d5 2a 53 96 05-b7 06 8f 81 b6 96 b6   .+S.*S.........
                        011d - c3 c3 f5 74 84 8f 79 0d-f0 17 3e 14 77 30 d5   ...t..y...>.w0.
                        012c - 4a e6 d8 ba b7 4b d8 55-f4 67 18 fc 37 98 fd   J....K.U.g..7..
                        013b - 50 c9 04 02 f6 09 9f 39-8d 47 e0 d2 d3 59 01   P......9.G...Y.
                        014a - b0 4c 1c 6a ca 0c bc c7-3f ef 47 b7 88 7f 97   .L.j....?.G....
                        0159 - 1c 7f 56 a6 43 2f e5 53-40 57 dc 49 26 7a 1a   ..V.C/.S@W.I&z.
                        0168 - 6f cf 92 c0 75 8c b4 ee-e0 77 58 c5 44 c5 49   o...u....wX.D.I
                        0177 - c8 b7 be 25 aa 3a d9 8d-0d 9c 96 a9 7f bd b4   ...%.:.........
                        0186 - 12 66 10 cf 9c c5 8f 37-43 f0 1e cd 26 39 7f   .f.....7C...&9.
                        0195 - 3f 12 60 8c a8 0e 65 32-ee 07 f3 c2 19 f4 cb   ?.\`...e2.......
                        01a4 - 38 28 0c fc 3f 62 7a 18-09 a5 69 cf 30 6b 2c   8(..?bz...i.0k,
                        01b3 - f5 42 70 d1 29 39 bf e4-23 5b 28 8e e4 3f 20   .Bp.)9..#[(..? 
                        01c2 - a6 ab d7 31 0d f3 24 7b-2b d0 7d 2d 8a a4 fb   ...1..\${+.}-...
                        01d1 - e9 61 f5 67 26 df 49 d3-0c 87 b4 ce 15 d5 0f   .a.g&.I........
                        01e0 - 86 a3 e0 e7 78 0c 2b ba-d7 e5 20 33 79 d9 46   ....x.+... 3y.F
                        01ef - c5 38 fd ed 54 c1 9f 29-f9 b7 91 bd 10 33 bc   .8..T..).....3.
                        01fe - ba 75                                          .u
                  crls:
                    d.crl: 
                      crl: 
                        version: 1
                        sig_alg: 
                          algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                          parameter: NULL
                        issuer:           C=US, ST=Test, L=Local, O=MyOrg, OU=CA, CN=MyRootCA
                        lastUpdate: Oct  1 19:05:30 2025 GMT
                        nextUpdate: Oct 31 19:05:30 2025 GMT
                        revoked:
                          <ABSENT>
                        extensions:
                            object: X509v3 CRL Number (2.5.29.20)
                            critical: FALSE
                            value: 
                              0000 - 02 01 01                                 ...
                      sig_alg: 
                        algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                        parameter: NULL
                      signature:  (0 unused bits)
                        0000 - 71 c4 7d f2 40 72 09 bd-0b b0 c4 83 49 a8 1f   q.}.@r......I..
                        000f - 2d b2 95 ff 82 ea 8c b1-49 e0 b1 fe df d1 3c   -.......I.....<
                        001e - 38 63 fc 66 67 58 5b 05-72 10 b3 85 b2 21 0a   8c.fgX[.r....!.
                        002d - 52 67 5d 94 43 d8 e3 5b-1b 4c af 57 4f e7 0f   Rg].C..[.L.WO..
                        003c - c6 93 f0 a2 64 d9 6d 36-65 f7 b3 65 72 7e 25   ....d.m6e..er~%
                        004b - fc 52 13 86 31 21 4a 91-55 7e 3a 46 7f b1 eb   .R..1!J.U~:F...
                        005a - 6d 30 f7 dc 8e 46 60 c1-88 ae 3c b1 ff 2d 4a   m0...F\`...<..-J
                        0069 - 80 87 cc 46 ae 6d 19 23-d8 90 ac 18 60 93 38   ...F.m.#....\`.8
                        0078 - 19 dd 71 9e db f2 f8 9b-c4 4a 33 20 4b b8 27   ..q......J3 K.'
                        0087 - 7f e4 31 b7 51 fc fc b1-11 79 91 11 dc 8c 5b   ..1.Q....y....[
                        0096 - 56 4e 60 ae 17 84 65 04-31 1b 44 fc f0 30 a4   VN\`...e.1.D..0.
                        00a5 - 2d ea 9b 1b 77 c6 15 e1-ce 90 92 30 ca 6b a5   -...w......0.k.
                        00b4 - 50 b5 f6 8e 83 03 e1 86-4d e3 86 28 1e c7 fd   P.......M..(...
                        00c3 - 3c 71 ca ba 81 d2 30 f8-f1 a3 81 fe d1 2e 36   <q....0.......6
                        00d2 - 6a f3 8b 19 c5 3a 06 6c-78 62 c5 e8 f9 f4 ea   j....:.lxb.....
                        00e1 - 9c 39 4f ce a2 2a f9 e2-57 38 73 55 97 74 eb   .9O..*..W8sU.t.
                        00f0 - a5 37 85 4a 7f 5c a5 c1-26 79 b6 20 7e 21 23   .7.J.\\..&y. ~!#
                        00ff - 31 13 bb b4 b1 b9 af e6-d6 9c 78 27 7b 8c 98   1.........x'{..
                        010e - 71 19 36 df fd 51 d8 f5-de e2 f9 a0 15 ce 8a   q.6..Q.........
                        011d - 6d 2e ab 95 8e 56 32 34-4c 4c c2 1f 9a 68 9b   m....V24LL...h.
                        012c - c8 56 58 e6 1b f2 fc 3e-09 94 96 04 0b 05 87   .VX....>.......
                        013b - cc e2 9f ee 33 ae a1 3d-ca b0 2f 86 ed 0e d0   ....3..=../....
                        014a - 0a be 21 4f 48 60 8a 5f-b1 eb a6 f6 aa 73 f8   ..!OH\`._.....s.
                        0159 - 23 4c 13 45 3c 6b c6 08-ef 05 7d 5e d1 1a f3   #L.E<k....}^...
                        0168 - 1d 36 bc 65 2e 4d aa 18-fc 21 60 b8 56 2c b5   .6.e.M...!\`.V,.
                        0177 - 47 e2 09 06 36 a3 ae 4c-87 de c6 6e af c8 71   G...6..L...n..q
                        0186 - 8c f8 48 15 9f 0e 4f 2f-04 5f 0e 7a 55 e9 b5   ..H...O/._.zU..
                        0195 - 79 39 1c ff 76 9e 3e 1d-9b 33 89 8e 1d e6 45   y9..v.>..3....E
                        01a4 - 10 79 11 78 33 0d b6 f6-df 5f 37 d7 4a ff 55   .y.x3...._7.J.U
                        01b3 - 7c 03 b4 d7 79 16 7f 2f-87 08 f1 5e 68 22 96   |...y../...^h".
                        01c2 - e5 f3 53 01 14 82 90 96-39 6c aa 3f a3 cb cb   ..S.....9l.?...
                        01d1 - c4 1b 7a 69 85 00 fa b9-1a 2b 8c dc ab 0e 36   ..zi.....+....6
                        01e0 - 90 a7 07 0b 09 5d 10 28-2a 8c 48 69 d0 b4 c6   .....].(*.Hi...
                        01ef - 1c 4c 83 2f 04 54 8f 72-50 e7 aa bb a6 0f c2   .L./.T.rP......
                        01fe - a3 e3                                          ..

                    d.other: 
                      otherRevInfoFormat: undefined (1.3.6.1.5.5.7.16.2)
                      otherRevInfo: SEQUENCE:
                  0:d=0  hl=4 l=1797 cons: SEQUENCE          
                  4:d=1  hl=2 l=   1 prim:  ENUMERATED        :00
                  7:d=1  hl=4 l=1790 cons:  cont [ 0 ]        
                 11:d=2  hl=4 l=1786 cons:   SEQUENCE          
                 15:d=3  hl=2 l=   9 prim:    OBJECT            :Basic OCSP Response
                 26:d=3  hl=4 l=1771 prim:    OCTET STRING      [HEX DUMP]:308206E730820104A1663064310B3009060355040613025553310D300B06035504080C0454657374310E300C06035504070C054C6F63616C310E300C060355040A0C054D794F7267310D300B060355040B0C044F4353503117301506035504030C0E4F43535020526573706F6E646572180F32303235313030313139303533305A30643062304D300906052B0E03021A05000414C3015D4847D542630BDFE6900831B54D0686BDF604141021AB93D5B7999F76E042EF981E78A7E54221F502140726DAC7F46E2747C424C4225CB43FDDD2AFAA1A8200180F32303235313030313139303533305AA1233021301F06092B060105050730010204120410043674E832CDE57EC3B22590FC759490300D06092A864886F70D01010B0500038201010031E3D574696839F3B3852FE7E5C3B30BF88F8AD6D03A55A05A53FEE21A2675433B68C484832B0C11CD21214ADF750027664967740F4666D97FDFC991684F27DB4A5C2EF932722D631433AF356D3B6023EA6BF4C60D7B2B890FF7E7C7EF8CE77191000634A83462DFF916C32237AC2E7B3AA682AF8CBC5A082EB8388054197CC86D18AD2418EA903E67A757A32E3787E17686BC28484747F646A8C752CA71218BC8DC71DC9318C072EA569CFCF629BAD07544B9157F1092B37A9C0CF18099D0CA4AAA19FFD98984C63F25803F542A0FEE0CEAF58FE1731B370CC85899D097C9BEC8CB7E1851FB80F875800E7691C1215CF4F40245E716466029FB09574A84F781A08204C7308204C3308204BF308202A7A00302010202140726DAC7F46E2747C424C4225CB43FDDD2AFAA1B300D06092A864886F70D01010B0500305C310B3009060355040613025553310D300B06035504080C0454657374310E300C06035504070C054C6F63616C310E300C060355040A0C054D794F7267310B3009060355040B0C0243413111300F06035504030C084D79526F6F7443413020170D3235313030313139303533305A180F32303533303231363139303533305A3064310B3009060355040613025553310D300B06035504080C0454657374310E300C06035504070C054C6F63616C310E300C060355040A0C054D794F7267310D300B060355040B0C044F4353503117301506035504030C0E4F43535020526573706F6E64657230820122300D06092A864886F70D01010105000382010F003082010A0282010100B408DE563DE2F8B6C3DCC8ADE84609DD0AAD7DBE50BAFB69BAB9387A51B419FA67130610D99C27F5FB7C77F93B2B46BCF2760662A991A3E3DE553C5E83E76F358820BB4E5E844073D76252ECDE28D6E33AAF6ED183C7968369317A5A2C0AD445E6FB9299AB852AA75862D2ECF880ACFB9027F289C9600E67A6C60B1671D0C1A92C3FCB4384B8662B2CD6486FDFD87F26423CD2724532B697DE60910E3567C7A4412FFA921619D7D5810AD3E05FC1F3DE6336C739D44847A84419A1583A69F151DB8AB968DA8699D4A92F7FB4069206B17D71B7A25F89341266872127F5D1C3230B5B077072D5867DD04155806842428421A8554D73DDD4A1A684F09A84FCE47D0203010001A36F306D30090603551D1304023000300B0603551D0F04040302078030130603551D25040C300A06082B06010505070309301D0603551D0E04160414D85C086804FEA7E50FF156781C09064EBE214191301F0603551D230418301680141021AB93D5B7999F76E042EF981E78A7E54221F5300D06092A864886F70D01010B050003820201003CF6A479AC51A2F33712A1F4D0EDB008217C0F8AB4F69473005929D3B8E724A7F4E8D3F97B3FC4754643FF4AAA646EAB53156B7C25C57EB1C19756794682D73C6ED164891F80315908DC06C0F9DD9ED6870EBDF64F142698615C8741F067713720A1D05E205F685C0108C86D91318B2752B63E7A2BD3D38349A0B1C4D88269777A5DF5A799E9AE0A34A1B09C9A9EBCA432821D67F5D4771DE6F9AA02FB747453D0BE4C37470CEF6178F9E0DBAF491D134DD7CFF343F4AE22236043607B204A1E454FE253B98DBB3677612127BFA479C42EB0FBDB857AC02F797796602EF3A1AD78DF8629D5BBB83ABFAF7630521308BAE4423DF035D06B2C41D1D6BA157494C1384D3D4F7EBA61319835A002A880FAB97336B4BF19B653D0FF29F41DCBFFA38C8E753519E7712835176E046B8D0CCD5E92865D800CFFDD2EC6C65ADCD7A5470F086199E56FA6CE076C205D5E1EE93FCA15ADD60D76B2BD174684448090D4D9EEFB3C72859ADE835EFD5787CC1B8FA55119940DD8FFB131CF16D42E2664D043E3810682F14ED50782E4DAAAB646D09731A8914FB23F1971E31668F6563CBBD6050F8905101F848EA812C3EC6F69CF6797834C3F9EDC533A84C62E21F9E369BE8AC918F7B8A71527C0CBD284DECC02CB08E772936C1BBF57196EA9E2B9E4DCE1BCF5888C1AC8D52AE7D34854D7892895AA4A575232B78FF11E048F740F5D5D0C40
                  signerInfos:
                      version: 1
                      d.issuerAndSerialNumber: 
                        issuer:           C=US, ST=Test, L=Local, O=MyOrg, OU=CA, CN=MyRootCA
                        serialNumber: 0x0726DAC7F46E2747C424C4225CB43FDDD2AFAA1A
                      digestAlgorithm: 
                        algorithm: sha256 (2.16.840.1.101.3.4.2.1)
                        parameter: <ABSENT>
                      signedAttrs:
                          object: signingTime (1.2.840.113549.1.9.5)
                          set:
                            UTCTIME:Aug 24 12:00:00 2025 GMT

                          object: id-smime-aa-ets-signerLocation (1.2.840.113549.1.9.16.2.17)
                          set:
                            SEQUENCE:
                  0:d=0  hl=2 l=  26 cons: SEQUENCE          
                  2:d=1  hl=2 l=   4 cons:  cont [ 0 ]        
                  4:d=2  hl=2 l=   2 prim:   UTF8STRING        :US
                  8:d=1  hl=2 l=   7 cons:  cont [ 1 ]        
                 10:d=2  hl=2 l=   5 prim:   UTF8STRING        :Local
                 17:d=1  hl=2 l=   9 cons:  cont [ 2 ]        
                 19:d=2  hl=2 l=   7 cons:   SEQUENCE          
                 21:d=3  hl=2 l=   5 prim:    UTF8STRING        :12345

                          object: id-smime-aa-signingCertificateV2 (1.2.840.113549.1.9.16.2.47)
                          set:
                            SEQUENCE:
                  0:d=0  hl=3 l= 175 cons: SEQUENCE          
                  3:d=1  hl=3 l= 172 cons:  SEQUENCE          
                  6:d=2  hl=3 l= 169 cons:   SEQUENCE          
                  9:d=3  hl=2 l=  11 cons:    SEQUENCE          
                 11:d=4  hl=2 l=   9 prim:     OBJECT            :sha256
                 22:d=3  hl=2 l=  32 prim:    OCTET STRING      [HEX DUMP]:FA94CADCEC73C914AD79475737731C4C1E1A8575030DD3511DA992264708A69C
                 56:d=3  hl=2 l= 120 cons:    SEQUENCE          
                 58:d=4  hl=2 l=  96 cons:     SEQUENCE          
                 60:d=5  hl=2 l=  94 cons:      cont [ 4 ]        
                 62:d=6  hl=2 l=  92 cons:       SEQUENCE          
                 64:d=7  hl=2 l=  11 cons:        SET               
                 66:d=8  hl=2 l=   9 cons:         SEQUENCE          
                 68:d=9  hl=2 l=   3 prim:          OBJECT            :countryName
                 73:d=9  hl=2 l=   2 prim:          PRINTABLESTRING   :US
                 77:d=7  hl=2 l=  13 cons:        SET               
                 79:d=8  hl=2 l=  11 cons:         SEQUENCE          
                 81:d=9  hl=2 l=   3 prim:          OBJECT            :stateOrProvinceName
                 86:d=9  hl=2 l=   4 prim:          UTF8STRING        :Test
                 92:d=7  hl=2 l=  14 cons:        SET               
                 94:d=8  hl=2 l=  12 cons:         SEQUENCE          
                 96:d=9  hl=2 l=   3 prim:          OBJECT            :localityName
                101:d=9  hl=2 l=   5 prim:          UTF8STRING        :Local
                108:d=7  hl=2 l=  14 cons:        SET               
                110:d=8  hl=2 l=  12 cons:         SEQUENCE          
                112:d=9  hl=2 l=   3 prim:          OBJECT            :organizationName
                117:d=9  hl=2 l=   5 prim:          UTF8STRING        :MyOrg
                124:d=7  hl=2 l=  11 cons:        SET               
                126:d=8  hl=2 l=   9 cons:         SEQUENCE          
                128:d=9  hl=2 l=   3 prim:          OBJECT            :organizationalUnitName
                133:d=9  hl=2 l=   2 prim:          UTF8STRING        :CA
                137:d=7  hl=2 l=  17 cons:        SET               
                139:d=8  hl=2 l=  15 cons:         SEQUENCE          
                141:d=9  hl=2 l=   3 prim:          OBJECT            :commonName
                146:d=9  hl=2 l=   8 prim:          UTF8STRING        :MyRootCA
                156:d=4  hl=2 l=  20 prim:     INTEGER           :0726DAC7F46E2747C424C4225CB43FDDD2AFAA1A

                          object: messageDigest (1.2.840.113549.1.9.4)
                          set:
                            OCTET STRING:
                              0000 - 9f 86 d0 81 88 4c 7d 65-9a 2f ea a0 c5   .....L}e./...
                              000d - 5a d0 15 a3 bf 4f 1b 2b-0b 82 2c d1 5d   Z....O.+..,.]
                              001a - 6c 15 b0 f0 0a 08                        l.....

                          object: contentType (1.2.840.113549.1.9.3)
                          set:
                            OBJECT:pkcs7-data (1.2.840.113549.1.7.1)
                      signatureAlgorithm: 
                        algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                        parameter: NULL
                      signature: 
                        0000 - 23 63 00 c1 1d ba 8a c3-29 23 33 04 ca 7a df   #c......)#3..z.
                        000f - 46 69 ed 5c b5 f3 54 91-67 9e 2e 0c 77 ce a4   Fi.\\..T.g...w..
                        001e - 94 0e 1e 93 56 73 89 ee-49 4f 80 b5 cf 7d 9e   ....Vs..IO...}.
                        002d - d7 d0 2c 9d 7f 3f c1 cb-d3 f0 1d c6 d6 82 3c   ..,..?........<
                        003c - cc 2b 18 1a 03 7c e1 a5-74 69 d1 6c e4 68 cb   .+...|..ti.l.h.
                        004b - d2 39 d6 66 c6 bf 22 19-6d f1 d5 93 e5 aa e8   .9.f..".m......
                        005a - 5a ec bf bb 19 a3 cd ed-eb 43 dd fd f9 9e 61   Z........C....a
                        0069 - 4a d6 f0 00 0d 31 a7 c7-48 2a a8 7b c9 a0 31   J....1..H*.{..1
                        0078 - 3d e7 f4 fd 3b 28 33 f3-44 63 b2 dd a6 b1 ff   =...;(3.Dc.....
                        0087 - 0e 9d b1 81 e0 6b 52 cd-bf fe 59 e6 24 da 0a   .....kR...Y.$..
                        0096 - 4c 58 75 5d d9 06 c6 e6-6d 60 cc d2 1f 65 5b   LXu]....m\`...e[
                        00a5 - 61 f7 e1 77 80 a0 44 a9-3d ad bc 9c 92 8d cf   a..w..D.=......
                        00b4 - 9d 87 d8 28 40 7f c3 f5-7a f1 51 4e 3d db 07   ...(@...z.QN=..
                        00c3 - e7 7f e4 c3 04 63 2d b1-8f 33 41 bb ef 14 54   .....c-..3A...T
                        00d2 - ed b2 96 2f 53 42 31 c2-b9 a2 79 62 60 b9 9f   .../SB1...yb\`..
                        00e1 - b7 24 3b cb d3 2c 23 a4-0f 64 86 75 68 b7 9d   .$;..,#..d.uh..
                        00f0 - c4 d8 30 d3 47 91 90 88-27 63 d5 bc 9b 7f 6b   ..0.G...'c....k
                        00ff - bc                                             .
                      unsignedAttrs:
                        <ABSENT>
              "
            `)
        })

        test('Create RSA-PSS/SHA-256 Signed Data signature', async () => {
            const data = new TextEncoder().encode('test')
            const signedData = await SignedData.builder()
                .setData(data)
                .addSigner({
                    privateKeyInfo: PrivateKeyInfo.fromDer(
                        rsaSigningKeys.privateKey,
                    ),
                    certificate: Certificate.fromDer(rsaSigningKeys.cert),
                    encryptionAlgorithm: {
                        type: 'RSA_PSS',
                        params: {
                            saltLength: 32,
                            hash: 'SHA-256',
                        },
                    },
                    signedAttrs: [],
                })
                .addCrl(CertificateList.fromDer(rsaSigningKeys.caCrl))
                .detached()
                .build()

            const verified = await signedData.verify({ data })
            expect(verified).toEqual({
                valid: true,
                signerInfo: signedData.signerInfos[0],
            })

            const derEncoded = new ContentInfo({
                contentType: OIDs.PKCS7.SIGNED_DATA,
                content: signedData,
            }).toDer()

            // Use OpenSSL to validate the signed data using the ContentInfo wrapper
            await opensslValidate({
                signature: derEncoded, // Use the ContentInfo wrapper
                data,
                caCertPem: rsaSigningKeys.caCertPem,
            })
        })

        test('Create ECDSA/SHA-256 Signed Data signature', async () => {
            const data = new TextEncoder().encode('test')
            const signedData = await SignedData.builder()
                .setData(data)
                .addSigner({
                    privateKeyInfo: PrivateKeyInfo.fromDer(
                        ecP256SigningKeys.privateKey,
                    ),
                    certificate: Certificate.fromDer(ecP256SigningKeys.cert),
                    encryptionAlgorithm: {
                        type: 'ECDSA',
                        params: {
                            hash: 'SHA-256',
                            namedCurve: 'P-256',
                        },
                    },
                    signedAttrs: [
                        new Attribute({
                            type: OIDs.PKCS9.SIGNING_TIME,
                            values: [new UTCTime({ time: new Date() })],
                        }),
                    ],
                })
                .detached()
                .build()

            /*signedData.signerInfos[0].signedAttrs = new SignerInfo.SignedAttributes(
            new Attribute(OIDs.PKCS9.SIGNING_TIME, [new UTCDate(new Date('2021'))]),
        )*/

            const derEncoded = new ContentInfo({
                contentType: OIDs.PKCS7.SIGNED_DATA,
                content: signedData,
            }).toDer()

            // Use OpenSSL to validate the signed data using the ContentInfo wrapper
            await opensslValidate({
                signature: derEncoded, // Use the ContentInfo wrapper
                data,
                caCertPem: ecP256SigningKeys.caCertPem,
            })

            const verified = await signedData.verify({
                data,
                certificateValidation: true,
            })
            expect(verified).toEqual({
                valid: true,
                signerInfo: signedData.signerInfos[0],
            })
        })
    })
})
