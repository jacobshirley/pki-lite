import { EnvelopedData } from '../../src/pkcs7/EnvelopedData.js'
import { Certificate } from '../../src/x509/Certificate.js'
import { describe, test, expect } from 'vitest'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'
import {
    opensslCmsDecrypt,
    opensslCmsToText,
    opensslPkcs12Parse,
    opensslValidate,
    opensslVerifyCertificate,
} from '../../test-fixtures/openSsl.js'
import { PrivateKeyInfo } from '../../src/keys/PrivateKeyInfo.js'
import { SignedData } from '../../src/pkcs7/SignedData.js'
import { SigningCertificateV2 } from '../../src/x509/attributes/SigningCertificateV2.js'
import { Attribute } from '../../src/x509/Attribute.js'
import { Extension } from '../../src/x509/Extension.js'
import { CertificateList } from '../../src/x509/CertificateList.js'
import { OCSPResponse } from '../../src/ocsp/OCSPResponse.js'
import { ContentInfo } from '../../src/pkcs7/ContentInfo.js'
import { OIDs } from '../../src/core/OIDs.js'
import { UTCTime } from '../../src/asn1/UTCTime.js'
import { ecP256SigningKeys } from '../../test-fixtures/signing-keys/ec-p256/index.js'
import { PFX } from '../../src/pkcs12/PFX.js'

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
                        serialNumber: 0x5CC1A4638F8BA92232262F95191EC815A98093E9
                        signature: 
                          algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                          parameter: NULL
                        issuer:           C=US, ST=Test, L=Local, O=MyOrg, OU=CA, CN=MyRootCA
                        validity: 
                          notBefore: Oct  7 17:03:25 2026 GMT
                          notAfter: Nov 26 17:03:25 9692 GMT
                        subject:           C=US, ST=Test, L=Local, O=MyOrg, OU=Signing, CN=John Doe
                        key:           X509_PUBKEY: 
                          algor: 
                            algorithm: rsaEncryption (1.2.840.113549.1.1.1)
                            parameter: NULL
                          public_key:  (0 unused bits)
                            0000 - 30 82 01 0a 02 82 01 01-00 d5 2d 07 98 41   0.........-..A
                            000e - b4 92 32 fb 76 10 57 90-74 11 64 33 1e 85   ..2.v.W.t.d3..
                            001c - 2e 7e 8a 17 a6 4e 24 d2-98 70 c9 f9 0e 8e   .~...N$..p....
                            002a - be d8 be 1e 2b f7 46 5b-06 ac 5d ee a0 96   ....+.F[..]...
                            0038 - 2d be d4 bd 53 eb 02 3f-fe c0 45 1e 1c d5   -...S..?..E...
                            0046 - 8a d2 8f 07 db e2 c3 aa-54 74 c4 71 59 46   ........Tt.qYF
                            0054 - 15 09 0f 3d ce 11 74 78-2b 52 aa 21 bf 38   ...=..tx+R.!.8
                            0062 - 1a 3b b5 cd 4c 62 19 f6-04 15 12 8d 4a c9   .;..Lb......J.
                            0070 - b5 9f 8a 43 1f 28 21 8b-18 d8 d5 2b 18 4c   ...C.(!....+.L
                            007e - ee 58 a7 4c 77 25 80 d4-62 cc 43 3b d0 13   .X.Lw%..b.C;..
                            008c - 73 14 d7 f1 78 57 44 8b-9c d8 01 5d 1d d2   s...xWD....]..
                            009a - a8 2a 4a f4 4e 02 99 0d-ae 2d c6 08 48 6f   .*J.N....-..Ho
                            00a8 - 36 8c e8 9a d8 63 88 9c-e1 02 e5 4f ae 3e   6....c.....O.>
                            00b6 - b1 2f d1 a7 8d 2a 58 aa-a3 b9 8d b5 b3 84   ./...*X.......
                            00c4 - 58 72 0f 88 b5 f1 a6 d0-1b 3a 2b 76 97 57   Xr.......:+v.W
                            00d2 - 27 44 ea 93 6c fa 8e 46-9e 00 10 ad 0b e9   'D..l..F......
                            00e0 - b7 04 a5 cd 40 be 9c 66-0a 1e b7 4e bd 29   ....@..f...N.)
                            00ee - d1 01 c8 b5 9c 56 aa 43-a3 53 40 7e 54 88   .....V.C.S@~T.
                            00fc - 61 bd 09 71 d2 72 da c4-c4 60 00 5c d9 02   a..q.r...\`.\\..
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
                              0000 - 04 14 ae 63 77 21 3c ee-c1 4f 5e fb 97   ...cw!<..O^..
                              000d - 4c b3 fb 0c d7 c7 fa 2d-71               L......-q

                            object: X509v3 Authority Key Identifier (2.5.29.35)
                            critical: FALSE
                            value: 
                              0000 - 30 16 80 14 86 17 4e b6-4c 96 1d a9 f9   0.....N.L....
                              000d - e5 7c fc 8b 62 c9 4a e3-cd 29 08         .|..b.J..).
                      sig_alg: 
                        algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                        parameter: NULL
                      signature:  (0 unused bits)
                        0000 - ac ac 91 a1 44 e5 cc 92-7f 82 7d 8f 25 6a d0   ....D.....}.%j.
                        000f - b5 f3 90 0b de 5a 79 ff-5c 15 da e1 fb d2 a9   .....Zy.\\......
                        001e - e3 27 34 85 b0 c3 41 1f-1c eb 11 e5 e6 51 cc   .'4...A......Q.
                        002d - 7a d8 2c ad 46 30 67 2f-45 26 8c 09 45 0d 5f   z.,.F0g/E&..E._
                        003c - 01 ff 37 08 03 cb db f8-57 f3 bd b5 b7 89 93   ..7.....W......
                        004b - b5 d0 cc 5a 6b 52 a9 e4-b9 b9 2c 1c fe ec 5e   ...ZkR....,...^
                        005a - 0c 24 70 6b 52 55 67 eb-d7 df e5 e9 31 fa 0f   .$pkRUg.....1..
                        0069 - 18 b5 b6 f8 09 ff 35 b7-73 b7 04 77 75 d4 51   ......5.s..wu.Q
                        0078 - fb a0 e5 91 84 3f 26 de-d7 e9 f7 57 79 65 f0   .....?&....Wye.
                        0087 - 31 af d2 66 08 76 fc 67-e7 10 ca 44 33 de ed   1..f.v.g...D3..
                        0096 - 88 db 8d d0 05 3d aa a6-f6 0a d6 28 ae aa 81   .....=.....(...
                        00a5 - 40 57 9a 48 f6 ad b1 c3-cc 0a 48 bd 00 70 6e   @W.H......H..pn
                        00b4 - d5 fe ed ce 94 93 d1 7e-82 3e 6c 82 d3 8d 96   .......~.>l....
                        00c3 - 19 88 82 51 43 78 2e de-81 b3 f6 f3 6d 7a 1c   ...QCx......mz.
                        00d2 - ef ca df 89 d0 99 03 57-1f 8e 7e 9a 18 6c 0c   .......W..~..l.
                        00e1 - 58 3d 2e 29 c3 2d ce 5e-a3 db ca 21 68 9d a8   X=.).-.^...!h..
                        00f0 - ab f2 1e 64 5a 89 bd 0d-30 ec b0 69 c0 0a 84   ...dZ...0..i...
                        00ff - 16 5e 4b 55 a0 64 ab 30-5a 3d 08 69 6d 82 cc   .^KU.d.0Z=.im..
                        010e - bd e0 5e 32 54 fd 8a fb-a6 90 00 18 16 c3 d1   ..^2T..........
                        011d - 9e 8a c4 f9 fa 6f 60 2e-44 93 8d 4e 0d 22 e2   .....o\`.D..N.".
                        012c - 59 82 46 54 73 68 2d 7d-22 10 10 55 0f a1 97   Y.FTsh-}"..U...
                        013b - 49 9b e3 1c 38 7a b8 2a-6d da bb 5f c1 e0 5b   I...8z.*m.._..[
                        014a - e2 36 5d 2a 15 e1 06 e8-ce bb db a1 ad 59 41   .6]*.........YA
                        0159 - 24 b1 62 39 a7 f6 57 3f-32 e1 f1 5c 54 5b fb   $.b9..W?2..\\T[.
                        0168 - a0 44 82 38 bc 39 68 36-7d d7 4f 2b dd 33 4c   .D.8.9h6}.O+.3L
                        0177 - 62 94 ba e2 51 2b 90 1b-bf 15 b4 0e 8d 3c 5f   b...Q+.......<_
                        0186 - 22 6e e8 18 4e bb c0 c6-5d c4 3b 7b e7 c6 66   "n..N...].;{..f
                        0195 - c2 20 b0 76 33 8d e7 0f-8b 62 9d 9f da f5 49   . .v3....b....I
                        01a4 - 9a eb 59 41 b8 bb 53 e4-7b 49 d6 f3 63 6d b2   ..YA..S.{I..cm.
                        01b3 - 54 d3 c9 19 0f ac 7e f2-e5 ae 5e bb bf 69 23   T.....~...^..i#
                        01c2 - f3 36 e0 2a 2a 8b 6e 22-f5 5b 6d 05 82 60 7c   .6.**.n".[m..\`|
                        01d1 - 6b b2 15 af d9 db 09 1b-91 71 34 d2 b8 ad 60   k........q4...\`
                        01e0 - 58 6f 6d 2f 22 65 59 c5-88 7d 82 54 87 79 72   Xom/"eY..}.T.yr
                        01ef - d6 19 30 f5 5c 95 0e 7a-87 c3 d4 6f 18 ce 2c   ..0.\\..z...o..,
                        01fe - f8 cb                                          ..
                  crls:
                    d.crl: 
                      crl: 
                        version: 1
                        sig_alg: 
                          algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                          parameter: NULL
                        issuer:           C=US, ST=Test, L=Local, O=MyOrg, OU=CA, CN=MyRootCA
                        lastUpdate: Oct  7 17:03:25 2026 GMT
                        nextUpdate: Sep  1 17:03:25 2048 GMT
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
                        0000 - 7b a8 1c 76 47 bb 4c 80-8f c7 6f eb 41 a4 26   {..vG.L...o.A.&
                        000f - 74 8b 2d 81 af d7 fb 53-b6 ce 37 c8 cc 49 64   t.-....S..7..Id
                        001e - f6 df bc 61 68 18 f6 b9-2c d9 b2 02 22 cb d4   ...ah...,..."..
                        002d - 65 9e 11 89 ba fd 91 74-9a 4f 04 4f ea 97 a2   e......t.O.O...
                        003c - 5e dd 81 b1 cd f4 ad b8-c0 ed a8 d4 95 f0 56   ^.............V
                        004b - 3b 6b 5b 2b a2 d6 7b 6f-bd 5e 1f 83 5f 2b a0   ;k[+..{o.^.._+.
                        005a - c5 43 82 bb ae 51 2b fe-42 50 28 b9 d8 f8 11   .C...Q+.BP(....
                        0069 - 42 aa e4 0d a1 15 4d 0d-10 0d 66 3e c5 08 df   B.....M...f>...
                        0078 - 15 61 b3 72 12 d9 8f 08-bd 06 d0 b1 e7 fa 57   .a.r..........W
                        0087 - 24 49 56 44 86 30 8b ab-c9 4b 2b fe 32 93 a7   $IVD.0...K+.2..
                        0096 - 0e ad ff 24 7e a7 7b de-1f c1 f5 b9 67 cb 8d   ...$~.{.....g..
                        00a5 - 4b d1 42 f4 e6 be 11 13-50 b8 3a 43 e6 b4 a9   K.B.....P.:C...
                        00b4 - c3 ef 82 8c d5 3d 42 50-25 fb 0f f1 d1 0b e1   .....=BP%......
                        00c3 - bc dd 60 44 27 4f 2e 7d-77 c5 18 23 4c 78 40   ..\`D'O.}w..#Lx@
                        00d2 - 68 b9 ec 40 e0 bb 0f d8-af 59 15 72 01 eb b2   h..@.....Y.r...
                        00e1 - ab 8b 30 a8 35 ce 02 1c-1c 8a e8 8e dd c7 b5   ..0.5..........
                        00f0 - a9 5f 95 69 1b dd 91 0b-d0 38 d1 66 21 9a 37   ._.i.....8.f!.7
                        00ff - 1e f4 31 8a cf b4 1b e7-99 bd d5 f7 54 90 63   ..1.........T.c
                        010e - 48 3b 29 20 d9 ad 72 43-d9 ec c6 a1 a5 2f e4   H;) ..rC...../.
                        011d - bf 93 48 6b 08 e9 f1 06-fb 26 4a 0f 77 59 90   ..Hk.....&J.wY.
                        012c - cc 58 e9 1c 73 61 3d 35-a3 b0 a7 dd 35 2b 97   .X..sa=5....5+.
                        013b - 59 fd 30 1d 7a e4 da 86-df c6 7e b9 ea 1a 65   Y.0.z.....~...e
                        014a - 8a 94 1a 64 2e bf 2a 36-13 52 ab fe af 99 c1   ...d..*6.R.....
                        0159 - cc b9 50 bc 16 70 49 7e-c2 b3 41 ac e3 91 91   ..P..pI~..A....
                        0168 - 7a 38 1c ec 66 8c 6f 48-94 50 9b 8a 40 c9 8b   z8..f.oH.P..@..
                        0177 - 53 47 59 25 98 c1 a3 74-96 01 1c 4d e2 0c e4   SGY%...t...M...
                        0186 - ff 8f 9b 1f d9 22 cf 6b-1f 56 47 11 55 55 7c   .....".k.VG.UU|
                        0195 - bd c9 ca 16 38 33 04 9e-d6 ed b6 76 87 21 be   ....83.....v.!.
                        01a4 - 33 21 ff f2 3e c3 3b 87-ec 86 90 5a d7 f4 75   3!..>.;....Z..u
                        01b3 - a9 46 8a 67 39 10 73 19-95 0b 85 4b 0d aa da   .F.g9.s....K...
                        01c2 - 8e 6d 7e 87 fc 27 54 a4-81 f0 a1 f6 53 f9 b0   .m~..'T.....S..
                        01d1 - 30 01 a0 ab 91 89 01 d4-ea 50 d5 06 61 8c 50   0........P..a.P
                        01e0 - b9 6e a7 ec f3 3b 88 36-50 9b 10 0d 17 fa 92   .n...;.6P......
                        01ef - da e2 ae 8a 16 43 14 26-4d 51 98 4e b9 02 72   .....C.&MQ.N..r
                        01fe - d2 6f                                          .o

                    d.other: 
                      otherRevInfoFormat: undefined (1.3.6.1.5.5.7.16.2)
                      otherRevInfo: SEQUENCE:
                  0:d=0  hl=4 l=1797 cons: SEQUENCE          
                  4:d=1  hl=2 l=   1 prim:  ENUMERATED        :00
                  7:d=1  hl=4 l=1790 cons:  cont [ 0 ]        
                 11:d=2  hl=4 l=1786 cons:   SEQUENCE          
                 15:d=3  hl=2 l=   9 prim:    OBJECT            :Basic OCSP Response
                 26:d=3  hl=4 l=1771 prim:    OCTET STRING      [HEX DUMP]:308206E730820104A1663064310B3009060355040613025553310D300B06035504080C0454657374310E300C06035504070C054C6F63616C310E300C060355040A0C054D794F7267310D300B060355040B0C044F4353503117301506035504030C0E4F43535020526573706F6E646572180F32303236313030373137303332355A30643062304D300906052B0E03021A05000414C3015D4847D542630BDFE6900831B54D0686BDF6041486174EB64C961DA9F9E57CFC8B62C94AE3CD290802145CC1A4638F8BA92232262F95191EC815A98093E98200180F32303236313030373137303332355AA1233021301F06092B0601050507300102041204107FEBFA49ECFC424FC42FAD1C16A208E9300D06092A864886F70D01010B050003820101009AD650DF60F9DC6EEA33EF130CA302B75B1D4B26BFCB7D0FF174ED33B71524E6DDFC2A0ABC7279C547DD266F27C23894199FDA04EDAD324EF99574FFBB737F0FFBB882739D273BDD9EEAD65A56D2CA2A3CDB6470E2AE62BEF9902ABD67C4D855CDA613A0D73D7FE2B24B41857D2DBAE967B5DF36422AF3312CA85B1F6D8069A5D07996FAFAE05875B06DDEACFEDF1ECBBDA000F5D36319946AB32A53B464976CEE3B75AD3C0135C255F3752AC5F40A0D315585BCFDA47A45DC162A9637E822042A0186A3D4C8AEB1F6348D74BC109EF6DD2951B28B49C83F921BED6CA14447BBEC03B1B44E1AEC079CECFF127166104C051E705CD6ED2658A9F534ACFCF68EF6A08204C7308204C3308204BF308202A7A00302010202145CC1A4638F8BA92232262F95191EC815A98093EA300D06092A864886F70D01010B0500305C310B3009060355040613025553310D300B06035504080C0454657374310E300C06035504070C054C6F63616C310E300C060355040A0C054D794F7267310B3009060355040B0C0243413111300F06035504030C084D79526F6F7443413020170D3236313030373137303332355A180F39363932313132363137303332355A3064310B3009060355040613025553310D300B06035504080C0454657374310E300C06035504070C054C6F63616C310E300C060355040A0C054D794F7267310D300B060355040B0C044F4353503117301506035504030C0E4F43535020526573706F6E64657230820122300D06092A864886F70D01010105000382010F003082010A0282010100BD46B26EE97F0540138993A2AEC1668E9CCA3A323B115F4B48304160E806D5D6E847874E95C6F02D691167F6D0CCCFBA4C25F716922E9D46DD4847A35C189603417342902F9AC87EE1432809E5A5516A4FE519BF84E7A340B478BDCB951615219FA077F166F55040E2D063059837D6FFECFCF521D9FD675EB4466D2A480E2CB8F7BD9D3077B2CA22B4C018D5659F816C756164024DCF5B72DDC5B18B820A779886FD2282C427F559044F31BBEB6169077958D9BD6C0DA6C85B9CF1A12A3AB41DCF74960EB782AAA6616853AC5BB208ABC618A356402967EE3A9309C168EE4AC81ED13C7E6EF98D2AB288E0527BFE1CF6C990388A2BE34DD644E215BEB2625DC90203010001A36F306D30090603551D1304023000300B0603551D0F04040302078030130603551D25040C300A06082B06010505070309301D0603551D0E04160414E117B144BCA62C5D6AE36F260C44788167F7D390301F0603551D2304183016801486174EB64C961DA9F9E57CFC8B62C94AE3CD2908300D06092A864886F70D01010B050003820201001D75E4B35C8F617178A0036125E138DB8C0A770B4E690D188F5DD8A4E2CA5504C5537BFD48D9AE22D03F8C6A4FDB1938F5CFCDC77A18975B463EEC4D20DFAD3C8938DF0C7BF35D5C8D14198843DF89A5A48780CFF8F3F1108153BA57BC6131155DED0D1E83A0AA8CE0D035D2334B021F8A4726A1E1BCFCE6D02214402731F615AE25CE2C846E47BEB76776352BFBFFBE2383385157EDC94C43EB3C2E8734E33563CA3CA7A104D615A452D46B087D42139D5AB9F8FEAC9F6843374AE917BC24D89C2D7BF16ECCDF0761281F3046A5D729A3A894991A023C63A42385893AC0902C2E4936260CCD39F0E5969BDA7E2AF8716A821E2CEE5E0CE81B996F8A2596F23D9A98EE31E55F2F8BB7F2290E8C0036A39C29BEBC1C29E76033FD1F5EE069DA1167C99340692E8D2BA50E16C945A16E613C404CDB9A2E72401DBE566E83F42259E433B150E832B0CE88AF14365A21F62A9654383168DD2B951776DE2601E4E06AE2949E3C1B1B786F8915AB85337303DD84D95AE3C091BABF482F14BAE89BB7675D0C2CBBCCB9A484FF45C6EFA9FB6474FC5E1FC49D4E534D4805FA4EBC30C4E4A106B4FE315E98B187C2060995F87DD2B0706430BFE849CD9FF872C7F76CEF4C196299E0A89DC272FB37895B52145DDF824439D3F136E8A5188C083EF0FC4D55732BCA4B5ADAAA7B304D2F26667A9130B906EBEF228798D3EFB410A0B5274C4F
                  signerInfos:
                      version: 1
                      d.issuerAndSerialNumber: 
                        issuer:           C=US, ST=Test, L=Local, O=MyOrg, OU=CA, CN=MyRootCA
                        serialNumber: 0x5CC1A4638F8BA92232262F95191EC815A98093E9
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
                 22:d=3  hl=2 l=  32 prim:    OCTET STRING      [HEX DUMP]:DB43762D61ACF6DC9505569D8BA762BACDA0B7AE5C73E0ED3F88A71B09C53B5B
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
                156:d=4  hl=2 l=  20 prim:     INTEGER           :5CC1A4638F8BA92232262F95191EC815A98093E9

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
                        0000 - 22 bd 92 fa 5b 08 4c 5a-63 02 7e 4c fb 7d 1f   "...[.LZc.~L.}.
                        000f - 6d 8b b5 9e 70 16 e3 b8-cb 5c 6c ce 13 7d 04   m...p....\\l..}.
                        001e - d2 98 58 30 8b f3 15 1f-f2 af 3b b9 2a 84 ce   ..X0......;.*..
                        002d - b0 9a bf ab 38 e5 3d 63-dd 1c 1c b4 0a 51 86   ....8.=c.....Q.
                        003c - b7 b6 cf dc 0d 9b 18 d8-be 4e 6f 25 00 68 9b   .........No%.h.
                        004b - 27 9b b2 b7 57 03 d9 be-b7 12 3e c0 5c c5 12   '...W.....>.\\..
                        005a - ff 88 ab f2 e6 6c 0e 34-87 92 e5 34 98 1c 97   .....l.4...4...
                        0069 - 42 5f 43 20 bb 8c 6d 4e-fd ac 14 dd 6c 23 84   B_C ..mN....l#.
                        0078 - 8e ff fc 96 04 59 d8 6d-27 60 45 40 8c 2f 33   .....Y.m'\`E@./3
                        0087 - cd 51 d7 14 9a a8 34 d6-b4 6d c4 2a d7 8f 59   .Q....4..m.*..Y
                        0096 - aa 52 33 9c 86 dd 66 e5-bb ca 6b 6f ca e9 62   .R3...f...ko..b
                        00a5 - 80 ee bc 1d 10 c7 5e bc-1a 57 d4 e2 ab d6 ae   ......^..W.....
                        00b4 - 92 01 7e 8b 02 70 1f 1a-45 0e 16 5c e5 30 65   ..~..p..E..\\.0e
                        00c3 - f8 a5 a5 4c 76 9a fc 42-be 9f e6 f8 68 f5 14   ...Lv..B....h..
                        00d2 - 64 d4 bc 4d 48 d8 7b 15-8a ff 7f 35 27 c6 43   d..MH.{....5'.C
                        00e1 - 2d ac d8 04 d2 2d b3 5f-9f c3 09 99 cd cc 5f   -....-._......_
                        00f0 - 79 ff 60 a0 91 ca 62 c6-80 bd 15 c0 5c 13 47   y.\`...b.....\\.G
                        00ff - d9                                             .
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

    describe('Certificate', () => {
        test('self-signed certificate is valid with OpenSSL', async () => {
            const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
            const loadedCert = Certificate.fromPem(rsaSigningKeys.certPem)
            const publicKey = loadedCert.tbsCertificate.subjectPublicKeyInfo

            const cert = await Certificate.builder()
                .setSubject('CN=Test Self-Signed, O=Test Org, C=US')
                .setPublicKey(publicKey)
                .setPrivateKey(keyPair)
                .setValidityDays(365)
                .addExtension(
                    Extension.basicConstraints({
                        cA: true,
                    }),
                )
                .selfSign()

            const result = await opensslVerifyCertificate({
                certificate: cert.toPem(),
                selfSigned: true,
            })

            expect(result.success, result.error).toBe(true)
        })

        test('non-self-signed certificate from existing CA is valid with OpenSSL', async () => {
            // Use the pre-generated certificates which have a valid CA signature
            const userCert = Certificate.fromPem(rsaSigningKeys.certPem)
            const caCert = Certificate.fromPem(rsaSigningKeys.caCertPem)

            // Verify the user certificate with its CA
            const result = await opensslVerifyCertificate({
                certificate: userCert.toPem(),
                caCertificate: caCert.toPem(),
            })

            expect(result.success, result.error).toBe(true)
        })
    })

    describe('PFX (PKCS#12)', () => {
        test('PFX built with PFXBuilder is parseable by OpenSSL', async () => {
            const cert = Certificate.fromPem(rsaSigningKeys.certPem)
            const privateKey = PrivateKeyInfo.fromPem(
                rsaSigningKeys.privateKeyPem,
            )
            const password = 'test123'

            const pfx = await PFX.builder()
                .addCertificate(cert)
                .addPrivateKey(privateKey)
                .setPassword(password)
                .build()

            const result = await opensslPkcs12Parse({
                pfx: pfx.toDer(),
                password,
            })

            expect(result.success, result.error).toBe(true)
            expect(result.output).toContain('BEGIN CERTIFICATE')
            expect(result.output).toContain('BEGIN PRIVATE KEY')
        })

        test('PFX with full certificate chain is parseable by OpenSSL', async () => {
            const cert = Certificate.fromPem(rsaSigningKeys.certPem)
            const caCert = Certificate.fromPem(rsaSigningKeys.caCertPem)
            const privateKey = PrivateKeyInfo.fromPem(
                rsaSigningKeys.privateKeyPem,
            )
            const password = 'chain-pass'

            const pfx = await PFX.builder()
                .addCertificate(cert, caCert)
                .addPrivateKey(privateKey)
                .setPassword(password)
                .setFriendlyName('My Identity')
                .build()

            const result = await opensslPkcs12Parse({
                pfx: pfx.toDer(),
                password,
            })

            expect(result.success, result.error).toBe(true)
            // Two certificates should be present in the output
            const certCount = (result.output?.match(/BEGIN CERTIFICATE/g) ?? [])
                .length
            expect(certCount).toBe(2)
            expect(result.output).toContain('BEGIN PRIVATE KEY')
        })

        test('PFX created via PFX.create is parseable by OpenSSL', async () => {
            const cert = Certificate.fromPem(rsaSigningKeys.certPem)
            const privateKey = PrivateKeyInfo.fromPem(
                rsaSigningKeys.privateKeyPem,
            )
            const password = 'create-pass'

            const pfx = await PFX.create({
                certificates: [cert],
                privateKeys: [privateKey],
                password,
            })

            const result = await opensslPkcs12Parse({
                pfx: pfx.toDer(),
                password,
            })

            expect(result.success, result.error).toBe(true)
        })

        test('PFX with custom iterations is parseable by OpenSSL', async () => {
            const cert = Certificate.fromPem(rsaSigningKeys.certPem)
            const privateKey = PrivateKeyInfo.fromPem(
                rsaSigningKeys.privateKeyPem,
            )
            const password = 'iters-pass'

            const pfx = await PFX.builder()
                .addCertificate(cert)
                .addPrivateKey(privateKey)
                .setPassword(password)
                .setIterations(4096)
                .build()

            const result = await opensslPkcs12Parse({
                pfx: pfx.toDer(),
                password,
            })

            expect(result.success, result.error).toBe(true)
        })

        test('OpenSSL rejects PFX with wrong password (MAC verification)', async () => {
            const cert = Certificate.fromPem(rsaSigningKeys.certPem)
            const privateKey = PrivateKeyInfo.fromPem(
                rsaSigningKeys.privateKeyPem,
            )

            const pfx = await PFX.builder()
                .addCertificate(cert)
                .addPrivateKey(privateKey)
                .setPassword('correct-password')
                .build()

            const result = await opensslPkcs12Parse({
                pfx: pfx.toDer(),
                password: 'wrong-password',
            })

            expect(result.success).toBe(false)
        })
    })
})
