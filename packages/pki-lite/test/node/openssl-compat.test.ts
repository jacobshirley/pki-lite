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
import { OIDs } from '../../src/index.js'
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
                        serialNumber: 0x45E08D21404AF407B4051EF9DC53E8205C1073DC
                        signature: 
                          algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                          parameter: NULL
                        issuer:           C=US, ST=Test, L=Local, O=MyOrg, OU=CA, CN=MyRootCA
                        validity: 
                          notBefore: Sep 21 10:59:16 2025 GMT
                          notAfter: Sep 21 10:59:16 2026 GMT
                        subject:           C=US, ST=Test, L=Local, O=MyOrg, OU=Signing, CN=John Doe
                        key:           X509_PUBKEY: 
                          algor: 
                            algorithm: rsaEncryption (1.2.840.113549.1.1.1)
                            parameter: NULL
                          public_key:  (0 unused bits)
                            0000 - 30 82 01 0a 02 82 01 01-00 b7 e2 dc a2 ca   0.............
                            000e - 33 2a 5b fa f1 a6 62 de-fb be b3 c2 12 d0   3*[...b.......
                            001c - bc 95 1c e6 f8 23 ee d4-df db 55 88 f2 50   .....#....U..P
                            002a - 10 db ae 65 4b 0b af 09-61 17 ee e2 b9 43   ...eK...a....C
                            0038 - 86 44 25 7a 88 46 ac f0-23 92 4a e8 9c 20   .D%z.F..#.J.. 
                            0046 - 1e 97 9f 3c 80 fb 52 10-83 b9 f9 d1 ff cf   ...<..R.......
                            0054 - 57 a4 c0 a8 f3 f0 48 92-ba 00 d4 6a 4e 8f   W.....H....jN.
                            0062 - 8a ef b6 df 79 8e 54 f2-56 ca d4 66 06 87   ....y.T.V..f..
                            0070 - f5 df 1c 03 53 23 01 e2-e2 e6 90 cb 22 1a   ....S#......".
                            007e - 85 90 d5 c1 76 13 d3 17-48 2f 6a 7d 42 fa   ....v...H/j}B.
                            008c - 5b 7a fb de b7 ee 37 a0-94 a4 33 71 8b 7d   [z....7...3q.}
                            009a - bf 10 9b 3e a0 5b 5e d2-01 3b eb 42 11 24   ...>.[^..;.B.$
                            00a8 - f1 4f 62 bd a2 36 56 6c-17 c6 4e ea c9 da   .Ob..6Vl..N...
                            00b6 - 13 17 b8 fb bc 3d b2 f8-be 0d 49 73 56 54   .....=....IsVT
                            00c4 - a7 18 78 0b 52 04 31 05-ef a5 d3 6f 26 ad   ..x.R.1....o&.
                            00d2 - 75 2d ef 41 5e 2a 76 55-27 f5 68 75 30 cb   u-.A^*vU'.hu0.
                            00e0 - 27 f0 44 1a 6e 7e 4c 55-bf 62 1e 9c dd 3a   '.D.n~LU.b...:
                            00ee - 9c 76 d0 d8 5f 86 8d 8d-1c 22 eb cb c1 89   .v.._...."....
                            00fc - bc af ec 5d 7b 63 37 81-9e 23 bb bb 31 02   ...]{c7..#..1.
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
                              0000 - 04 14 d2 26 9d b1 3b 95-24 46 05 75 5d   ...&..;.$F.u]
                              000d - 07 13 09 ad 22 f1 e4 45-03               ...."..E.

                            object: X509v3 Authority Key Identifier (2.5.29.35)
                            critical: FALSE
                            value: 
                              0000 - 30 16 80 14 2b 9e c2 87-54 52 d6 b5 e8   0...+...TR...
                              000d - b2 df 6b 18 ed f7 21 54-98 11 ad         ..k...!T...
                      sig_alg: 
                        algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                        parameter: NULL
                      signature:  (0 unused bits)
                        0000 - 28 2d 04 69 5b 0b 6b 0b-f9 f4 08 9e 42 80 77   (-.i[.k.....B.w
                        000f - 2e ad 6a a8 e5 17 02 b9-71 05 cd 6f df 90 74   ..j.....q..o..t
                        001e - c1 63 99 52 ad 3f 94 11-d3 27 68 b0 f4 1d 1f   .c.R.?...'h....
                        002d - 17 5f f0 c0 0a d0 a6 0c-d6 52 63 87 4b 2a 38   ._.......Rc.K*8
                        003c - 8e 42 b9 d9 f7 7c 4b 4a-6b ab a8 2a ce 91 f5   .B...|KJk..*...
                        004b - ea 68 25 c0 64 97 f2 0b-43 43 49 e4 30 f6 78   .h%.d...CCI.0.x
                        005a - 4e d5 9f 7f d1 47 3d c7-f4 39 26 ec ab f4 c2   N....G=..9&....
                        0069 - bc 6c e4 66 23 a1 31 67-da f7 7d 15 08 a5 00   .l.f#.1g..}....
                        0078 - 5a ab 4b b8 6b e6 a9 7c-5a 1d 8b 54 69 4c 2b   Z.K.k..|Z..TiL+
                        0087 - 94 86 88 41 21 d5 38 97-eb 77 ee 61 08 33 fc   ...A!.8..w.a.3.
                        0096 - ce 92 05 56 0c 27 9d cb-5d 48 8e 68 12 d1 66   ...V.'..]H.h..f
                        00a5 - 81 5b 75 67 8f 19 ab 9f-20 0d da 89 5c 67 e4   .[ug.... ...\\g.
                        00b4 - 92 7e 25 7e 2e 55 25 85-62 e0 1a e3 db cb 96   .~%~.U%.b......
                        00c3 - 56 6c 90 be e8 d1 c7 fd-d1 e7 d1 cf 83 e9 73   Vl............s
                        00d2 - 8e ac a0 e3 6e 51 a1 79-6e 14 48 fc 44 86 dc   ....nQ.yn.H.D..
                        00e1 - 87 a4 86 68 ac 09 54 5a-3a bd 56 dd c5 fc db   ...h..TZ:.V....
                        00f0 - 62 e3 40 76 56 90 7e 0c-53 90 c9 4f 55 ea e9   b.@vV.~.S..OU..
                        00ff - 61 c8 e4 73 b6 4d de 31-01 c3 6d 4b f6 26 33   a..s.M.1..mK.&3
                        010e - 28 15 dd 11 fb 1e 3e cd-a3 d4 81 02 4a 18 af   (.....>.....J..
                        011d - 45 45 25 c7 28 73 44 1b-97 06 2d 16 e8 b5 c6   EE%.(sD...-....
                        012c - 2f 7c 64 0b 92 35 2c 7d-48 69 80 8f 7f a9 45   /|d..5,}Hi....E
                        013b - 8b 6c a5 5c 7d e8 bf e9-5a 12 3f 71 81 2e e1   .l.\\}...Z.?q...
                        014a - a0 c1 5f 62 4e 21 23 26-54 2f 88 35 6e c7 8a   .._bN!#&T/.5n..
                        0159 - dc b7 d5 8e 2e 59 02 9b-ae 33 df 49 9c a7 6d   .....Y...3.I..m
                        0168 - fe 07 ca 7f fc 04 a4 ca-c2 e8 22 ef 75 7f d8   ..........".u..
                        0177 - d2 59 57 df 44 3c b6 f4-d6 b6 ff 07 ad 75 cf   .YW.D<.......u.
                        0186 - bd be 46 f2 4e 10 5c c7-f3 ae 04 4f 23 91 bf   ..F.N.\\....O#..
                        0195 - e2 8a f2 07 ce 32 06 0e-d0 40 30 16 96 e2 21   .....2...@0...!
                        01a4 - 08 29 79 ab b9 f7 70 30-1f 02 ea 56 60 d6 06   .)y...p0...V\`..
                        01b3 - fa 1a 6b 87 9e ad cb 57-d1 c7 7b 97 ee e4 15   ..k....W..{....
                        01c2 - e9 08 45 4f 75 96 25 23-fe b0 65 de 10 24 08   ..EOu.%#..e..$.
                        01d1 - b9 eb 8c e1 4a 39 4b e6-83 66 48 62 bd 49 03   ....J9K..fHb.I.
                        01e0 - e2 a1 25 f2 ea 13 d6 54-91 6e 50 0f d3 74 35   ..%....T.nP..t5
                        01ef - ac 0a 7f fc 2a 56 2a 4c-c9 cd 9f 3a bb e6 da   ....*V*L...:...
                        01fe - dd 51                                          .Q
                  crls:
                    d.crl: 
                      crl: 
                        version: 1
                        sig_alg: 
                          algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
                          parameter: NULL
                        issuer:           C=US, ST=Test, L=Local, O=MyOrg, OU=CA, CN=MyRootCA
                        lastUpdate: Sep 21 10:59:16 2025 GMT
                        nextUpdate: Oct 21 10:59:16 2025 GMT
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
                        0000 - 8c 08 52 49 46 a8 d3 21-92 8f c6 de 8d fa 95   ..RIF..!.......
                        000f - ce 66 e6 18 e5 f9 ea 0e-61 e1 aa 81 57 fa 14   .f......a...W..
                        001e - 5a ec e1 09 c5 23 81 f7-4e 99 14 ff a3 82 67   Z....#..N.....g
                        002d - ec 48 69 69 6a d9 6e 38-5f cb 40 03 72 17 92   .Hiij.n8_.@.r..
                        003c - 93 18 c7 21 bc 1c 3c b4-7b c4 0d ca 94 0c 56   ...!..<.{.....V
                        004b - 06 cb 34 85 f2 a0 9c f4-a0 4e 78 64 35 24 c8   ..4......Nxd5$.
                        005a - 08 59 3e 88 5a 9d 86 97-a2 44 4a 8e 90 eb c4   .Y>.Z....DJ....
                        0069 - 9f 24 e4 f7 3e 10 62 e9-f1 35 93 5e f2 25 92   .$..>.b..5.^.%.
                        0078 - 1d db 0b 2e 3b f6 e5 7b-a7 fc 3f 96 5c 48 be   ....;..{..?.\\H.
                        0087 - c1 f3 da 75 7b 74 79 43-c0 b8 19 bd cf 75 73   ...u{tyC.....us
                        0096 - 16 87 98 8a b0 95 d2 e9-c5 23 b0 12 25 42 31   .........#..%B1
                        00a5 - 3c 78 c0 8c f8 cb 5d 00-76 f7 62 da d1 d8 03   <x....].v.b....
                        00b4 - 97 4f cb cf 69 2f 0c e9-ed 13 4b 33 ac 2f 87   .O..i/....K3./.
                        00c3 - 28 63 a8 21 11 79 3c f0-52 6a 9a e2 6a 00 44   (c.!.y<.Rj..j.D
                        00d2 - 16 4b ad 67 85 e7 42 87-46 ee ee 24 37 49 5a   .K.g..B.F..$7IZ
                        00e1 - fb a9 e8 11 67 3f e6 f5-29 70 87 05 94 bb 1a   ....g?..)p.....
                        00f0 - ec 8c e2 40 5c 10 d1 f0-d8 8b 8c 8a f9 53 77   ...@\\........Sw
                        00ff - 52 7a 92 d6 66 d3 df f4-a4 94 03 0a 01 01 a4   Rz..f..........
                        010e - 47 72 4c 45 b2 d8 ef 0c-ed a4 3c ff d4 18 de   GrLE......<....
                        011d - 37 37 e6 98 6e f5 de 9d-64 52 76 c1 ed 72 25   77..n...dRv..r%
                        012c - 14 d9 18 ba 8e fe 78 f1-6e a4 e5 d0 20 5a ac   ......x.n... Z.
                        013b - ac 8d 50 15 60 82 e2 4b-eb ec ce 91 cf a7 5c   ..P.\`..K......\\
                        014a - 81 6e a7 65 3c d5 ba 4d-74 83 73 69 2f 55 a5   .n.e<..Mt.si/U.
                        0159 - 92 09 63 0a 84 66 e5 c0-28 1a fb 4a f2 22 c3   ..c..f..(..J.".
                        0168 - 25 d6 a0 5c ad 70 06 4b-1e ad 9a 4d 61 a8 6f   %..\\.p.K...Ma.o
                        0177 - 29 ac 71 1a b2 0c fc 15-01 4b 60 9a e5 80 23   ).q......K\`...#
                        0186 - 75 4b 3d f1 b1 dc 9d 20-71 fb 75 24 e2 43 e6   uK=.... q.u$.C.
                        0195 - 15 82 8d ee 82 8f 79 e4-8e f3 6a 09 51 85 f9   ......y...j.Q..
                        01a4 - ed e7 3c 84 8b d9 35 57-1f 3d 89 f8 81 dc ed   ..<...5W.=.....
                        01b3 - 6e 22 12 d1 bf a4 64 5e-f1 11 d6 a4 2b 2e 79   n"....d^....+.y
                        01c2 - a0 34 58 08 90 90 e0 21-e4 c2 db fa 6e 2d ca   .4X....!....n-.
                        01d1 - 4d 85 9c 8a be 21 b9 98-80 fb 17 44 5d d1 95   M....!.....D]..
                        01e0 - 45 4a 92 db 54 41 b9 19-63 86 d9 bf d8 2e aa   EJ..TA..c......
                        01ef - fb 1b a5 8d f0 bc 35 0d-25 97 24 b7 20 21 e3   ......5.%.$. !.
                        01fe - 60 9e                                          \`.

                    d.other: 
                      otherRevInfoFormat: undefined (1.3.6.1.5.5.7.16.2)
                      otherRevInfo: SEQUENCE:
                  0:d=0  hl=4 l=1797 cons: SEQUENCE          
                  4:d=1  hl=2 l=   1 prim:  ENUMERATED        :00
                  7:d=1  hl=4 l=1790 cons:  cont [ 0 ]        
                 11:d=2  hl=4 l=1786 cons:   SEQUENCE          
                 15:d=3  hl=2 l=   9 prim:    OBJECT            :Basic OCSP Response
                 26:d=3  hl=4 l=1771 prim:    OCTET STRING      [HEX DUMP]:308206E730820104A1663064310B3009060355040613025553310D300B06035504080C0454657374310E300C06035504070C054C6F63616C310E300C060355040A0C054D794F7267310D300B060355040B0C044F4353503117301506035504030C0E4F43535020526573706F6E646572180F32303235303932313130353931365A30643062304D300906052B0E03021A05000414C3015D4847D542630BDFE6900831B54D0686BDF604142B9EC2875452D6B5E8B2DF6B18EDF721549811AD021445E08D21404AF407B4051EF9DC53E8205C1073DC8200180F32303235303932313130353931365AA1233021301F06092B060105050730010204120410EC9D54AA2C3D29BAA2E126A5E0E384A2300D06092A864886F70D01010B0500038201010032C2BAFC8E82CE2556A1B9A0D81F03BE9633E18FF63252917F91A7068F5139AB728B784AFEE54DA68FAC601940FD2A2E0BC5F84745FF64CF573321BA4AB6F505216740933718F92D615BC67FC35DB6949BCA77AA5963A505688A4FDE9218AA17B305B685F3A8C70132CC660E28F0EC6B06DA3FA289D26CA0A775AF7168CC5A4999C37231754EA5922BDE098D22799BA244047B7017FAC19D947CFD948D730A2EBD1993C2FD67B5452952BAF75242879F0973443634DB3C5D552B8463EC84F57FDD0B3EDC3AD9D25F02795A6331D361B842F88E1E64FF3DF5A5FB8E75362E397B8430EA526617AC7EEB540D8AA4910ADFEE35EA6EB7050F5177FB44AA52D0904FA08204C7308204C3308204BF308202A7A003020102021445E08D21404AF407B4051EF9DC53E8205C1073DD300D06092A864886F70D01010B0500305C310B3009060355040613025553310D300B06035504080C0454657374310E300C06035504070C054C6F63616C310E300C060355040A0C054D794F7267310B3009060355040B0C0243413111300F06035504030C084D79526F6F7443413020170D3235303932313130353931365A180F32303533303230363130353931365A3064310B3009060355040613025553310D300B06035504080C0454657374310E300C06035504070C054C6F63616C310E300C060355040A0C054D794F7267310D300B060355040B0C044F4353503117301506035504030C0E4F43535020526573706F6E64657230820122300D06092A864886F70D01010105000382010F003082010A0282010100BC1EDB6E515CDD4184D4240E2835A3A637B70FAABE1DE2A540BE3343C0884D88E166368AB4995388A22312EB3A2454A55323C7D4A452BE9F649DE9DC4A4B659990CE426C5D96B92716BCB0AF4B6B55FD62F3C1D4F2A205C0E9C4AF3F2504A3DC59548DD619CBC5470EC608629AEC500AC583DF95C46376BF1A4F17BA9B5B0FDA3FC6B625630628EC2802A36F02325C5C0EF837B4B26A4A0D79F2E51AC862B988157665F257A4434217D6AA36322C0D26BC7D251238764771088ECEB8C607F6659145E0C6FD514BF12DEBCE8DDE88C706246528D8438C34E2D153B3CDBA4A96961CC3B7674D9499992887A5BA866412C95444B885051AD5E7FB5F414269C3E5010203010001A36F306D30090603551D1304023000300B0603551D0F04040302078030130603551D25040C300A06082B06010505070309301D0603551D0E0416041496E7262A6FD98556866A01747E0888388699A3D4301F0603551D230418301680142B9EC2875452D6B5E8B2DF6B18EDF721549811AD300D06092A864886F70D01010B0500038202010030D3BA2D8DAEA95881C57FFEBA6A7D5991FA977E8DF982BDD536094B027222CD389A0B3CC39E2EC60A2547B27612E802CB30579001467281FCCAAABC22B5CCFF70C31EBF89C1943B98DA8BCC661915BC343D19E75A21C35DF90D88D508DF33005E5563BCC6B954116484314AF2EEE2442F1D2240D62E06E22A0C59EE3ABECBA2D79781BB1A36806AC1BDF77D1E0A934B5A194D7D5844FC98A10D5DD2952FE7678AC6FC627667A41F40D518D4BB721974475250272A2F553EE3FE7585DDE50AEFABEDA22DB8F3609007DE9385AFCA453AC491999C4C326598F0FC72FA07E4BC314D08BD255750039B28631DBF8EBFB96E74D873B7176CBFBB49078B6965DD5381C666EFD69CF210B3EAFBA151B5E42B38A15CFCDB1702C0E9C343B31F8F15472735A2C1367916973AF09204A0D299DF5B769B5A716A40319CCC1C9FC5FF325F4760C66743D5449C243B1F5B770B07FA4D9412C06588C2DF00183CA56C385D62596DAB3F3E350875C836981E9B04FD933980999F8CDC9EB8F5A54C6C1BBA3ACA210FD23B61D2D5F0CD8AC7FFAF310F1782D3CCB64D72F325C6DECB9D92CB8FC9296A8910204D90C20562C64F9DF262FB83DC3E091E9D5CDBD4478CDBB4C3D16D6536EF3E969F2DB2A5FFAD68CA4A82ADEA0D6CFFC610346703805042EF476A2F46AD4C4F40C9C6D9502E7264867FEBE601257B3BB0F453EEF62D8F7865863D24AE
                  signerInfos:
                      version: 1
                      d.issuerAndSerialNumber: 
                        issuer:           C=US, ST=Test, L=Local, O=MyOrg, OU=CA, CN=MyRootCA
                        serialNumber: 0x45E08D21404AF407B4051EF9DC53E8205C1073DC
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
                 22:d=3  hl=2 l=  32 prim:    OCTET STRING      [HEX DUMP]:FF4F81A04F941F712F6CE4CDC22C94BE67EE92CE169D78F56D0ED47E6E2ADF45
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
                156:d=4  hl=2 l=  20 prim:     INTEGER           :45E08D21404AF407B4051EF9DC53E8205C1073DC

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
                        0000 - 6f 95 88 24 92 47 67 e8-d7 4c 22 b6 9d ab 02   o..$.Gg..L"....
                        000f - 79 cd b7 ce 14 f1 69 4c-a4 62 2d 98 12 f0 eb   y.....iL.b-....
                        001e - f3 95 be ea 4b dc 18 96-30 b8 d8 31 52 fb 1d   ....K...0..1R..
                        002d - 56 f6 b5 e9 21 8f 02 8e-46 4d 6d 4a 76 54 b6   V...!...FMmJvT.
                        003c - f5 0d 42 ec 86 63 c3 ed-ab 6b 82 61 76 c9 06   ..B..c...k.av..
                        004b - 93 37 06 af ef 65 6b c2-08 5d 77 48 a2 af 7b   .7...ek..]wH..{
                        005a - 95 81 78 67 5f b6 ff 0f-d9 46 31 f9 71 13 94   ..xg_....F1.q..
                        0069 - b7 b4 b8 d9 7a ff 2c 3a-a6 cf a8 43 5e a3 0d   ....z.,:...C^..
                        0078 - 79 98 b3 57 00 de 3e c8-9b b3 f1 23 d7 42 d2   y..W..>....#.B.
                        0087 - 41 9d 15 19 24 c8 78 f2-7a 68 39 c5 a8 47 df   A...$.x.zh9..G.
                        0096 - ac 8a c5 91 09 b6 6e 93-c7 da b7 9f e7 1c e7   ......n........
                        00a5 - 08 41 79 3a 9b cc 5b 60-3f 9f 13 9c be 66 b1   .Ay:..[\`?....f.
                        00b4 - 2d 55 10 45 fe a2 f2 b7-a7 ab 8c 80 b5 8c c9   -U.E...........
                        00c3 - 72 7e dc 9e 95 6f 4a d6-ab 3d f9 28 ab 60 9a   r~...oJ..=.(.\`.
                        00d2 - 61 10 22 69 25 07 ee dc-fc c4 f4 5b 8f 43 ed   a."i%......[.C.
                        00e1 - e9 f3 c9 36 cb d3 ad f7-a7 2a 0e 53 cb ca 18   ...6.....*.S...
                        00f0 - f8 27 7b 5d b9 fb 3c 26-8d 65 79 0f 51 44 9b   .'{]..<&.ey.QD.
                        00ff - 39                                             9
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
