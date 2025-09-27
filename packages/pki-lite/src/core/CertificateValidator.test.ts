import { describe, test, expect, vi, beforeEach } from 'vitest'
import {
    CertificateValidator,
    CertificateValidationStatus,
    CertificateValidationOptions,
    TrustAnchor,
} from './CertificateValidator.js'
import { Certificate } from '../x509/Certificate.js'
import { CertificateList } from '../x509/CertificateList.js'
import { OCSPResponse } from '../ocsp/OCSPResponse.js'
import { OCSPResponseStatus } from '../ocsp/OCSPResponseStatus.js'
import { CertID } from '../ocsp/CertID.js'
import { RevokedCertificate } from '../x509/RevokedCertificate.js'
import { TBSCertList } from '../x509/TBSCertList.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Name } from '../x509/Name.js'
import { RelativeDistinguishedName } from '../x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../x509/AttributeTypeAndValue.js'
import { Validity } from '../x509/Validity.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { RSAPublicKey } from '../keys/RSAPublicKey.js'
import { OctetString } from '../asn1/OctetString.js'
import { Integer } from '../asn1/Integer.js'
import { Extension } from '../x509/Extension.js'
import { CertStatus } from '../ocsp/CertStatus.js'
import { ResponseData } from '../ocsp/ResponseData.js'
import { BasicOCSPResponse } from '../ocsp/BasicOCSPResponse.js'
import { ResponseBytes } from '../ocsp/ResponseBytes.js'
import { SingleResponse } from '../ocsp/SingleResponse.js'
import {
    GeneralSubtree,
    NameConstraints,
} from '../x509/extensions/NameConstraints.js'
import { GeneralName } from '../x509/GeneralName.js'
import { SubjectAltName } from '../x509/extensions/SubjectAltName.js'
import { CRLReason } from '../x509/CRLReason.js'

describe('CertificateValidator', () => {
    let validator: CertificateValidator
    let sampleCertificate: Certificate
    let expiredCertificate: Certificate
    let notYetValidCertificate: Certificate

    beforeEach(() => {
        validator = new CertificateValidator()
        sampleCertificate = createSampleCertificate()
        expiredCertificate = createExpiredCertificate()
        notYetValidCertificate = createNotYetValidCertificate()
    })

    describe('Basic Certificate Validation', () => {
        test('should validate a valid certificate', async () => {
            const result = await validator.validate(sampleCertificate)

            expect(result.isValid).toBe(true)
            expect(result.status).toBe(CertificateValidationStatus.VALID)
            expect(result.messages).toHaveLength(0)
            expect(result.revocationStatus.isRevoked).toBe(false)
            expect(result.revocationStatus.source).toBe('NONE')
        })

        test('should detect expired certificate', async () => {
            const result = await validator.validate(expiredCertificate)

            expect(result.isValid).toBe(false)
            expect(result.status).toBe(CertificateValidationStatus.EXPIRED)
            expect(result.messages).toHaveLength(1)
            expect(result.messages[0]).toContain('expired')
        })

        test('should detect not yet valid certificate', async () => {
            const result = await validator.validate(notYetValidCertificate)

            expect(result.isValid).toBe(false)
            expect(result.status).toBe(
                CertificateValidationStatus.NOT_YET_VALID,
            )
            expect(result.messages).toHaveLength(1)
            expect(result.messages[0]).toContain('not yet valid')
        })

        test('should respect time tolerance for expired certificate', async () => {
            const toleranceMs = 24 * 60 * 60 * 1000 // 1 day
            const result = await validator.validate(expiredCertificate, {
                timeTolerance: toleranceMs,
            })

            // Should still be expired if it's more than the tolerance
            expect(result.isValid).toBe(false)
            expect(result.status).toBe(CertificateValidationStatus.EXPIRED)
        })

        test('should use custom validation time', async () => {
            const customTime = new Date('2023-06-01T00:00:00.000Z')
            const result = await validator.validate(sampleCertificate, {
                validationTime: customTime,
            })

            expect(result.isValid).toBe(true)
            expect(result.status).toBe(CertificateValidationStatus.VALID)
        })
    })

    describe('CRL Revocation Checking', () => {
        test('should detect revoked certificate via CRL', async () => {
            const revokedCertSerial =
                sampleCertificate.tbsCertificate.serialNumber
            const crl = createSampleCRL([
                {
                    serialNumber: revokedCertSerial.toHexString(),
                    revocationDate: new Date('2023-01-15T00:00:00.000Z'),
                    reason: 1, // keyCompromise
                },
            ])

            const result = await validator.validate(
                sampleCertificate,
                {
                    checkCRL: true,
                },
                {
                    crls: [crl],
                },
            )

            expect(result.isValid).toBe(false)
            expect(result.status).toBe(CertificateValidationStatus.REVOKED)
            expect(result.revocationStatus.isRevoked).toBe(true)
            expect(result.revocationStatus.source).toBe('CRL')
            expect(result.revocationStatus.reason).toBe(1)
            expect(result.messages[0]).toContain('Certificate is revoked (CRL)')
        })

        test('should not detect non-revoked certificate via CRL', async () => {
            const crl = createSampleCRL([
                {
                    serialNumber: 'DEADBEEF', // Different serial
                    revocationDate: new Date('2023-01-15T00:00:00.000Z'),
                },
            ])

            const result = await validator.validate(
                sampleCertificate,
                {
                    checkCRL: true,
                },
                {
                    crls: [crl],
                },
            )

            expect(result.isValid).toBe(true)
            expect(result.status).toBe(CertificateValidationStatus.VALID)
            expect(result.revocationStatus.isRevoked).toBe(false)
            expect(result.revocationStatus.source).toBe('NONE')
        })

        test('should handle multiple CRLs', async () => {
            const revokedCertSerial =
                sampleCertificate.tbsCertificate.serialNumber
            const crl1 = createSampleCRL([
                {
                    serialNumber: 'DEADBEEF',
                    revocationDate: new Date('2023-01-15T00:00:00.000Z'),
                },
            ])
            const crl2 = createSampleCRL([
                {
                    serialNumber: revokedCertSerial.toHexString(),
                    revocationDate: new Date('2023-02-15T00:00:00.000Z'),
                    reason: 4, // superseded
                },
            ])

            const result = await validator.validate(
                sampleCertificate,
                {
                    checkCRL: true,
                },
                {
                    crls: [crl1, crl2],
                },
            )

            expect(result.isValid).toBe(false)
            expect(result.status).toBe(CertificateValidationStatus.REVOKED)
            expect(result.revocationStatus.isRevoked).toBe(true)
            expect(result.revocationStatus.source).toBe('CRL')
            expect(result.revocationStatus.reason).toBe(4)
        })
    })

    describe('OCSP Revocation Checking', () => {
        test('should detect revoked certificate via OCSP', async () => {
            const ocspResponse = createSampleOCSPResponse(
                sampleCertificate,
                'revoked',
                new Date('2023-01-15T00:00:00.000Z'),
                2, // cACompromise
            )

            const result = await validator.validate(
                sampleCertificate,
                {
                    checkOCSP: true,
                },
                {
                    ocspResponses: [ocspResponse],
                },
            )

            expect(result.isValid).toBe(false)
            expect(result.status).toBe(CertificateValidationStatus.REVOKED)
            expect(result.revocationStatus.isRevoked).toBe(true)
            expect(result.revocationStatus.source).toBe('OCSP')
            expect(result.revocationStatus.reason).toBe(2)
            expect(result.messages[0]).toContain(
                'Certificate is revoked (OCSP)',
            )
        })

        test('should confirm valid certificate via OCSP', async () => {
            const ocspResponse = createSampleOCSPResponse(
                sampleCertificate,
                'good',
            )

            const result = await validator.validate(
                sampleCertificate,
                {
                    checkOCSP: true,
                },
                {
                    ocspResponses: [ocspResponse],
                },
            )

            expect(result.isValid).toBe(true)
            expect(result.status).toBe(CertificateValidationStatus.VALID)
            expect(result.revocationStatus.isRevoked).toBe(false)
            expect(result.revocationStatus.source).toBe('OCSP')
            expect(result.revocationStatus.details).toContain(
                'confirmed as valid via OCSP',
            )
        })

        test('should handle unknown status via OCSP', async () => {
            const ocspResponse = createSampleOCSPResponse(
                sampleCertificate,
                'unknown',
            )

            const result = await validator.validate(
                sampleCertificate,
                {
                    checkOCSP: true,
                },
                {
                    ocspResponses: [ocspResponse],
                },
            )

            expect(result.isValid).toBe(true)
            expect(result.status).toBe(CertificateValidationStatus.VALID)
            expect(result.revocationStatus.isRevoked).toBe(false)
            expect(result.revocationStatus.source).toBe('OCSP')
            expect(result.revocationStatus.details).toContain(
                'status unknown via OCSP',
            )
        })

        test('should prefer OCSP over CRL', async () => {
            const revokedCertSerial =
                sampleCertificate.tbsCertificate.serialNumber

            // CRL says revoked
            const crl = createSampleCRL([
                {
                    serialNumber: revokedCertSerial.toHexString(),
                    revocationDate: new Date('2023-01-15T00:00:00.000Z'),
                },
            ])

            // OCSP says good
            const ocspResponse = createSampleOCSPResponse(
                sampleCertificate,
                'good',
            )

            const result = await validator.validate(
                sampleCertificate,
                {
                    checkCRL: true,
                    checkOCSP: true,
                },
                {
                    crls: [crl],
                    ocspResponses: [ocspResponse],
                },
            )

            expect(result.isValid).toBe(true)
            expect(result.status).toBe(CertificateValidationStatus.VALID)
            expect(result.revocationStatus.isRevoked).toBe(false)
            expect(result.revocationStatus.source).toBe('OCSP')
        })
    })

    describe('Combined Validation', () => {
        test('should check both expiry and revocation', async () => {
            const revokedCertSerial =
                expiredCertificate.tbsCertificate.serialNumber
            const crl = createSampleCRL([
                {
                    serialNumber: revokedCertSerial.toHexString(),
                    revocationDate: new Date('2023-01-15T00:00:00.000Z'),
                },
            ])

            const result = await validator.validate(
                expiredCertificate,
                {
                    checkCRL: true,
                },
                {
                    crls: [crl],
                },
            )

            // Should report expired (checked first) rather than revoked
            expect(result.isValid).toBe(false)
            expect(result.status).toBe(CertificateValidationStatus.EXPIRED)
            expect(result.messages[0]).toContain('expired')
        })

        test('should report revocation if certificate is valid but revoked', async () => {
            const revokedCertSerial =
                sampleCertificate.tbsCertificate.serialNumber
            const crl = createSampleCRL([
                {
                    serialNumber: revokedCertSerial.toHexString(),
                    revocationDate: new Date('2023-01-15T00:00:00.000Z'),
                },
            ])

            const result = await validator.validate(
                sampleCertificate,
                {
                    checkCRL: true,
                },
                {
                    crls: [crl],
                },
            )

            expect(result.isValid).toBe(false)
            expect(result.status).toBe(CertificateValidationStatus.REVOKED)
            expect(result.revocationStatus.isRevoked).toBe(true)
        })
    })

    describe('Error Handling', () => {
        test('should handle empty revocation data gracefully', async () => {
            const result = await validator.validate(
                sampleCertificate,
                {
                    checkCRL: true,
                    checkOCSP: true,
                },
                {
                    crls: [],
                    ocspResponses: [],
                },
            )

            expect(result.isValid).toBe(true)
            expect(result.status).toBe(CertificateValidationStatus.VALID)
            expect(result.revocationStatus.source).toBe('NONE')
        })

        test('should handle missing revocation data', async () => {
            const result = await validator.validate(sampleCertificate, {
                checkCRL: true,
                checkOCSP: true,
            })

            expect(result.isValid).toBe(true)
            expect(result.status).toBe(CertificateValidationStatus.VALID)
            expect(result.revocationStatus.source).toBe('NONE')
        })
    })

    describe('Revocation Reason Handling', () => {
        test('should handle various revocation reasons', async () => {
            const testCases = [
                { reason: 0, text: 'unspecified' },
                { reason: 1, text: 'keyCompromise' },
                { reason: 2, text: 'cACompromise' },
                { reason: 3, text: 'affiliationChanged' },
                { reason: 4, text: 'superseded' },
                { reason: 5, text: 'cessationOfOperation' },
                { reason: 6, text: 'certificateHold' },
                { reason: 8, text: 'removeFromCRL' },
                { reason: 9, text: 'privilegeWithdrawn' },
                { reason: 10, text: 'aACompromise' },
                { reason: 99, text: 'unknown(99)' },
            ]

            for (const testCase of testCases) {
                const ocspResponse = createSampleOCSPResponse(
                    sampleCertificate,
                    'revoked',
                    new Date(),
                    testCase.reason,
                )

                const result = await validator.validate(
                    sampleCertificate,
                    {
                        checkOCSP: true,
                    },
                    {
                        ocspResponses: [ocspResponse],
                    },
                )

                expect(result.revocationStatus.reason).toBe(testCase.reason)
                expect(result.messages[0]).toContain(testCase.text)
            }
        })
    })

    describe('Enhanced Features', () => {
        let endEntityCert: Certificate
        let intermediateCert: Certificate
        let rootCert: Certificate
        let trustAnchor: TrustAnchor

        beforeEach(() => {
            // Create test certificates
            rootCert = createRootCertificate()
            intermediateCert = createIntermediateCertificate(rootCert)
            endEntityCert = createEndEntityCertificate(intermediateCert)

            trustAnchor = {
                certificate: rootCert,
            }
        })

        describe('Trust Establishment', () => {
            test('should accept trust anchors for validation', async () => {
                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchor],
                    otherCertificates: [intermediateCert],
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.isValid).toBe(true)
                expect(result.chain).toBeDefined()
                expect(result.chain?.trustAnchor).toBeDefined()
                expect(result.chain?.isComplete).toBe(true)
                expect(result.diagnostics.stepsPerformed).toContain(
                    'Building certificate chain',
                )
            })

            test('should fail validation without trust anchor', async () => {
                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [], // No trust anchors
                    otherCertificates: [intermediateCert],
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.isValid).toBe(false)
                expect(result.status).toBe(
                    CertificateValidationStatus.CHAIN_INVALID,
                )
                expect(result.chain?.isComplete).toBe(false)
            })
        })

        describe('Certificate Chain Building', () => {
            test('should build complete certificate chain', async () => {
                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchor],
                    otherCertificates: [intermediateCert],
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.chain).toBeDefined()
                expect(result.chain?.certificates).toHaveLength(3)
                expect(result.chain?.certificates[0]).toBe(endEntityCert)
                expect(result.chain?.certificates[1]).toBe(intermediateCert)
                expect(result.chain?.certificates[2]).toBe(rootCert)
                expect(result.chain?.isComplete).toBe(true)
            })

            test('should handle incomplete chain gracefully', async () => {
                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchor],
                    otherCertificates: [], // Missing intermediate
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.isValid).toBe(false)
                expect(result.chain?.isComplete).toBe(false)
            })

            test('should prevent infinite loops in chain building', async () => {
                // Create a certificate that references itself as its issuer (creating a loop)
                const circularCert1 = createCircularCertificate1()
                const circularCert2 = createCircularCertificate2(circularCert1)

                // Make circularCert1 point to circularCert2 as issuer, creating A->B->A loop

                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchor],
                    otherCertificates: [circularCert1, circularCert2],
                }

                const result = await validator.validate(circularCert1, options)

                expect(result.isValid).toBe(false)
                expect(result.messages).toEqual(
                    expect.arrayContaining([expect.stringContaining('loop')]),
                )
            })
        })

        describe('Comprehensive Validation', () => {
            test('should validate entire certificate chain', async () => {
                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchor],
                    otherCertificates: [intermediateCert],
                    enforceCAConstraints: true,
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.isValid).toBe(true)
                expect(result.diagnostics.stepsPerformed).toContain(
                    'Validating certificate chain',
                )
                expect(result.diagnostics.stepsPerformed).toContain(
                    'Certificate chain validation completed successfully',
                )
            })

            test('should validate CA constraints', async () => {
                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchor],
                    otherCertificates: [intermediateCert],
                    enforceCAConstraints: true,
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.isValid).toBe(true)
            })

            test('should reject invalid CA certificate', async () => {
                // Create a non-CA intermediate certificate but use it in the intermediate position
                const invalidCA = createInvalidCACertificate()

                // Create an end-entity certificate that claims to be issued by the invalid CA
                const endEntityForInvalidCA =
                    createEndEntityCertificateFor(invalidCA)

                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchor],
                    otherCertificates: [invalidCA], // Using non-CA cert as intermediate
                    enforceCAConstraints: true,
                }

                const result = await validator.validate(
                    endEntityForInvalidCA,
                    options,
                )

                expect(result.isValid).toBe(false)
                expect(result.messages).toEqual(
                    expect.arrayContaining([
                        expect.stringContaining('CA constraints violation'),
                    ]),
                )
            })
        })

        describe('Name Constraints Support', () => {
            test('should validate permitted name constraints', async () => {
                const nameConstraints = new NameConstraints({
                    permittedSubtrees: [
                        new GeneralSubtree({
                            base: new GeneralName.dNSName({
                                value: 'example.com',
                            }),
                        }),
                    ],
                })

                const trustAnchorWithConstraints: TrustAnchor = {
                    certificate: rootCert,
                    nameConstraints,
                }

                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchorWithConstraints],
                    otherCertificates: [intermediateCert],
                    validateNameConstraints: true,
                }

                const result = await validator.validate(endEntityCert, options)
                expect(result.isValid).toBe(true)
            })

            test('should reject certificate violating name constraints', async () => {
                const nameConstraints = new NameConstraints({
                    excludedSubtrees: [
                        new GeneralSubtree({
                            base: new GeneralName.dNSName({
                                value: 'example.com',
                            }),
                        }),
                    ],
                })

                const trustAnchorWithConstraints: TrustAnchor = {
                    certificate: rootCert,
                    nameConstraints,
                }

                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchorWithConstraints],
                    otherCertificates: [intermediateCert],
                    validateNameConstraints: true,
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.isValid).toBe(false)
                expect(result.messages).toEqual(
                    expect.arrayContaining([
                        expect.stringContaining('Name constraints violation'),
                    ]),
                )
            })

            test('should accept subject alt names constraints', async () => {
                const nameConstraints = new NameConstraints({
                    permittedSubtrees: [
                        new GeneralSubtree({
                            base: new GeneralName.dNSName({
                                value: 'example.com',
                            }),
                        }),
                    ],
                })

                const trustAnchorWithConstraints: TrustAnchor = {
                    certificate: rootCert,
                    nameConstraints,
                }

                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchorWithConstraints],
                    otherCertificates: [intermediateCert],
                    validateNameConstraints: true,
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.isValid, result.messages.join(',')).toBe(true)
                expect(result.messages).toEqual(
                    expect.arrayContaining([
                        expect.stringContaining(
                            'Certificate chain validation successful',
                        ),
                    ]),
                )
            })
        })

        describe('Policy Validation', () => {
            test('should validate certificate policies', async () => {
                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchor],
                    otherCertificates: [intermediateCert],
                    validatePolicies: true,
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.policyResult).toBeDefined()
                expect(result.policyResult?.isValid).toBe(true)
            })

            test('should check required policies', async () => {
                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchor],
                    otherCertificates: [intermediateCert],
                    validatePolicies: true,
                    requiredPolicies: ['1.2.3.4.5'], // Non-existent policy
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.policyResult?.isValid).toBe(false)
                expect(result.policyResult?.violations).toContain(
                    'Required policy not found: 1.2.3.4.5',
                )
            })
        })

        describe('Enhanced Result Reporting', () => {
            test('should provide detailed diagnostic information', async () => {
                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchor],
                    otherCertificates: [intermediateCert],
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.diagnostics).toBeDefined()
                expect(result.diagnostics.stepsPerformed).toBeInstanceOf(Array)
                expect(
                    result.diagnostics.stepsPerformed.length,
                ).toBeGreaterThan(0)
                expect(result.diagnostics.warnings).toBeInstanceOf(Array)
                expect(result.diagnostics.context).toBeDefined()
                expect(result.diagnostics.context.chainLength).toBe(3)
            })

            test('should include chain information in result', async () => {
                const options: CertificateValidationOptions = {
                    validateChain: true,
                    trustAnchors: [trustAnchor],
                    otherCertificates: [intermediateCert],
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.chain).toBeDefined()
                expect(result.chain?.certificates).toBeDefined()
                expect(result.chain?.isComplete).toBe(true)
                expect(result.chain?.trustAnchor).toBeDefined()
            })
        })

        describe('Backward Compatibility', () => {
            test('should maintain existing API behavior', async () => {
                // Test that old validation behavior still works
                const result = await validator.validate(endEntityCert)

                expect(result.status).toBeDefined()
                expect(result.isValid).toBeDefined()
                expect(result.messages).toBeDefined()
                expect(result.revocationStatus).toBeDefined()
                expect(result.certificate).toBe(endEntityCert)
                expect(result.validatedAt).toBeDefined()
                expect(result.diagnostics).toBeDefined()
            })

            test('should work with existing validation options', async () => {
                const options: CertificateValidationOptions = {
                    checkCRL: true,
                    checkOCSP: false,
                    timeTolerance: 5000,
                }

                const result = await validator.validate(endEntityCert, options)

                expect(result.isValid).toBeDefined()
                expect(result.diagnostics.context.timeTolerance).toBe(5000)
            })
        })

        describe('pathLenConstraint enforcement', () => {
            test('should fail validation if pathLenConstraint is exceeded', async () => {
                // CA1 (pathLenConstraint = 0) -> CA2 -> Leaf
                const ca1 = createRootCertificate({
                    pathLenConstraint: 0,
                })
                const ca2 = createIntermediateCertificate(ca1)
                const leaf = createEndEntityCertificate(ca2)

                // Chain: [Leaf, CA2, CA1]
                const chain = {
                    certificates: [leaf, ca2, ca1],
                    isComplete: true,
                    trustAnchor: { certificate: ca1 },
                }

                const validator = new CertificateValidator()
                const result = await validator.validateChain(chain, {
                    enforceCAConstraints: true,
                })
                expect(result.isValid).toBe(false)
                expect(result.messages[0]).toMatch(
                    /pathLenConstraint violation/i,
                )
            })

            test('should pass validation if pathLenConstraint is not exceeded', async () => {
                // CA1 (pathLenConstraint = 1) -> CA2 -> Leaf
                const ca1 = createRootCertificate({
                    pathLenConstraint: 1,
                })
                const ca2 = createIntermediateCertificate(ca1)
                const leaf = createEndEntityCertificate(ca2)

                // Chain: [Leaf, CA2, CA1]
                const chain = {
                    certificates: [leaf, ca2, ca1],
                    isComplete: true,
                    trustAnchor: { certificate: ca1 },
                }

                const validator = new CertificateValidator()
                const result = await validator.validateChain(chain, {
                    enforceCAConstraints: true,
                })
                expect(result.isValid).toBe(true)
            })
        })
    })
})

// Helper functions for creating test data

function createSampleCertificate(): Certificate {
    const validity = new Validity({
        notBefore: new Date('2023-01-01T00:00:00.000Z'),
        notAfter: new Date('2026-12-31T23:59:59.000Z'),
    }) // Make sure it's valid for longer

    const serialNumber = new Integer({ value: 12345 })

    const subjectRdn = new RelativeDistinguishedName()
    subjectRdn.push(
        new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Certificate',
        }),
    )
    const subjectName = new Name.RDNSequence()
    subjectName.push(subjectRdn)

    const issuerRdn = new RelativeDistinguishedName()
    issuerRdn.push(
        new AttributeTypeAndValue({ type: '2.5.4.3', value: 'Test CA' }),
    )
    const issuerName = new Name.RDNSequence()
    issuerName.push(issuerRdn)

    const publicKey = new RSAPublicKey({
        modulus: new Uint8Array([
            0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc2, 0x8c,
            0x6c, 0x8e, 0x9b, 0x2c, 0x26, 0x2a, 0x4f, 0x5a, 0x2d,
        ]),
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
    })

    const subjectPublicKeyInfo = new SubjectPublicKeyInfo({
        algorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }), // RSA
        subjectPublicKey: publicKey,
    })

    const tbsCertificate = new Certificate.TBSCertificate({
        version: 2, // v3
        serialNumber: serialNumber.bytes,
        signature: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }), // SHA256withRSA
        issuer: issuerName,
        validity: validity,
        subject: subjectName,
        subjectPublicKeyInfo,
    })

    const signatureValue = new Uint8Array(256) // Mock signature

    return new Certificate({
        tbsCertificate,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }), // SHA256withRSA
        signatureValue,
    })
}

function createExpiredCertificate(): Certificate {
    const cert = createSampleCertificate()
    // Modify validity to be expired
    cert.tbsCertificate.validity = new Validity({
        notBefore: new Date('2020-01-01T00:00:00.000Z'),
        notAfter: new Date('2022-12-31T23:59:59.000Z'),
    })
    return cert
}

function createNotYetValidCertificate(): Certificate {
    const cert = createSampleCertificate()
    // Modify validity to be in the future
    cert.tbsCertificate.validity = new Validity({
        notBefore: new Date('2027-01-01T00:00:00.000Z'),
        notAfter: new Date('2028-12-31T23:59:59.000Z'),
    })
    return cert
}

function createSampleCRL(
    revokedCertificates: Array<{
        serialNumber: string | number
        revocationDate: Date
        reason?: number
    }>,
): CertificateList {
    const issuerRdn = new RelativeDistinguishedName()
    issuerRdn.push(
        new AttributeTypeAndValue({ type: '2.5.4.3', value: 'Test CA' }),
    )
    const issuerName = new Name.RDNSequence()
    issuerName.push(issuerRdn)

    const revokedCerts: RevokedCertificate[] = revokedCertificates.map(
        (cert) => {
            return new RevokedCertificate({
                userCertificate: cert.serialNumber,
                revocationDate: cert.revocationDate,
                crlEntryExtensions: cert.reason
                    ? [createReasonExtension(new CRLReason(cert.reason))]
                    : undefined,
            })
        },
    )

    const tbsCertList = new TBSCertList({
        signature: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }), // SHA256withRSA
        issuer: issuerName,
        thisUpdate: new Date(), // thisUpdate
        nextUpdate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // nextUpdate (+30 days)
        revokedCertificates: revokedCerts,
    })

    const signatureValue = new Uint8Array(256) // Mock signature

    return new CertificateList({
        tbsCertList,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }), // SHA256withRSA
        signatureValue,
    })
}

function createReasonExtension(reason: CRLReason) {
    // Create a simple CRL reason extension
    return new Extension({
        extnID: '2.5.29.21', // CRL Reason Code OID
        critical: false,
        extnValue: reason.toDer(),
    })
}

function createSampleOCSPResponse(
    certificate: Certificate,
    status: 'good' | 'revoked' | 'unknown',
    revocationTime?: Date,
    revocationReason?: number,
): OCSPResponse {
    // Create a basic OCSP response structure
    const certSerial = certificate.tbsCertificate.serialNumber.bytes

    // Mock CertID with the certificate's serial number
    const certID = new CertID({
        hashAlgorithm: new AlgorithmIdentifier({ algorithm: '1.3.14.3.2.26' }), // SHA-1
        issuerKeyHash: new OctetString({ bytes: new Uint8Array(20) }), // Mock issuer name hash
        issuerNameHash: new OctetString({ bytes: new Uint8Array(20) }), // Mock issuer key hash
        serialNumber: certSerial,
    })

    let certStatus: CertStatus
    if (status === 'good') {
        certStatus = CertStatus.createGood()
    } else if (status === 'revoked') {
        certStatus = CertStatus.createRevoked(
            revocationTime || new Date(),
            revocationReason,
        )
    } else {
        certStatus = CertStatus.createUnknown()
    }

    const singleResponse = new SingleResponse({
        certID,
        certStatus,
        thisUpdate: new Date(),
    })

    // Create a mock ResponderID using key hash
    const responderID = new OctetString({ bytes: new Uint8Array(20) }) // Mock key hash

    const responseData = new ResponseData({
        responses: [singleResponse],
        responderID,
        producedAt: new Date(),
    })

    const basicOCSPResponse = new BasicOCSPResponse({
        tbsResponseData: responseData,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }), // SHA256withRSA
        signature: new Uint8Array(256), // Mock signature
    })

    // Create ResponseBytes
    const responseBytes = new ResponseBytes({
        responseType: '1.3.6.1.5.5.7.48.1.1', // id-pkix-ocsp-basic
        response: basicOCSPResponse.toDer(),
    })

    return new OCSPResponse({
        responseStatus: OCSPResponseStatus.successful,
        responseBytes,
    })
}

// Enhanced test helper functions

function createRootCertificate(options?: {
    pathLenConstraint?: number
}): Certificate {
    // Create a basic root certificate for testing
    const validity = new Validity({
        notBefore: new Date(Date.now() - 24 * 60 * 60 * 1000),
        notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    })

    const subjectRdn = new RelativeDistinguishedName()
    subjectRdn.push(
        new AttributeTypeAndValue({ type: '2.5.4.3', value: 'Test Root CA' }),
    )
    const subject = new Name.RDNSequence()
    subject.push(subjectRdn)

    const issuer = subject // Self-signed

    const publicKey = new RSAPublicKey({
        modulus: new Uint8Array(256).fill(1), // Dummy key
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    })

    const subjectPublicKeyInfo = new SubjectPublicKeyInfo({
        algorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }),
        subjectPublicKey: publicKey,
    })

    const extensions = [
        Extension.basicConstraints({
            cA: true,
            pathLenConstraint: options?.pathLenConstraint,
        }),
    ]

    const tbsCert = new Certificate.TBSCertificate({
        version: 2, // Version 3
        serialNumber: new Uint8Array([0x01]), // Serial number
        signature: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }), // SHA256withRSA
        issuer,
        validity,
        subject,
        subjectPublicKeyInfo,
        issuerUniqueID: undefined, // issuerUniqueID
        subjectUniqueID: undefined, // subjectUniqueID
        extensions,
    })

    return new Certificate({
        tbsCertificate: tbsCert,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        signatureValue: new Uint8Array(256).fill(2), // Dummy signature
    })
}

function createIntermediateCertificate(issuer: Certificate): Certificate {
    const validity = new Validity({
        notBefore: new Date(Date.now() - 24 * 60 * 60 * 1000),
        notAfter: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000),
    })

    const subjectRdn = new RelativeDistinguishedName()
    subjectRdn.push(
        new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Intermediate CA',
        }),
    )
    const subject = new Name.RDNSequence()
    subject.push(subjectRdn)

    const issuerName = issuer.tbsCertificate.subject

    const publicKey = new RSAPublicKey({
        modulus: new Uint8Array(256).fill(3),
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    })

    const subjectPublicKeyInfo = new SubjectPublicKeyInfo({
        algorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }),
        subjectPublicKey: publicKey,
    })

    const extensions = [
        new Extension({
            extnID: '2.5.29.19', // Basic Constraints
            critical: true,
            extnValue: new Uint8Array([0x30, 0x03, 0x01, 0x01, 0xff]), // CA=TRUE
        }),
    ]

    const tbsCert = new Certificate.TBSCertificate({
        version: 2,
        serialNumber: new Uint8Array([0x02]),
        signature: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        issuer: issuerName,
        validity,
        subject,
        subjectPublicKeyInfo,
        issuerUniqueID: undefined,
        subjectUniqueID: undefined,
        extensions,
    })

    return new Certificate({
        tbsCertificate: tbsCert,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        signatureValue: new Uint8Array(256).fill(4),
    })
}

function createEndEntityCertificate(issuer: Certificate): Certificate {
    const validity = new Validity({
        notBefore: new Date(Date.now() - 24 * 60 * 60 * 1000),
        notAfter: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    })

    const subjectRdn = new RelativeDistinguishedName()
    subjectRdn.push(
        new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'test.example.com',
        }),
    )
    const subject = new Name.RDNSequence()
    subject.push(subjectRdn)

    const issuerName = issuer.tbsCertificate.subject

    const publicKey = new RSAPublicKey({
        modulus: new Uint8Array(256).fill(5),
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    })

    const subjectPublicKeyInfo = new SubjectPublicKeyInfo({
        algorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }),
        subjectPublicKey: publicKey,
    })

    // No Basic Constraints extension for end-entity certificate

    const tbsCert = new Certificate.TBSCertificate({
        version: 2,
        serialNumber: new Uint8Array([0x03]),
        signature: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        issuer: issuerName,
        validity,
        subject,
        subjectPublicKeyInfo,
        extensions: [
            new Extension({
                extnID: '2.5.29.17', // Subject Alternative Name
                critical: false,
                extnValue: new SubjectAltName(
                    new GeneralName.dNSName({ value: 'test.com' }),
                ).toDer(),
            }),
        ],
    })

    return new Certificate({
        tbsCertificate: tbsCert,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        signatureValue: new Uint8Array(256).fill(6),
    })
}

function createInvalidCACertificate(): Certificate {
    const validity = new Validity({
        notBefore: new Date(Date.now() - 24 * 60 * 60 * 1000),
        notAfter: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000),
    })

    const subjectRdn = new RelativeDistinguishedName()
    subjectRdn.push(
        new AttributeTypeAndValue({ type: '2.5.4.3', value: 'Invalid CA' }),
    )
    const subject = new Name.RDNSequence()
    subject.push(subjectRdn)

    const issuerRdn = new RelativeDistinguishedName()
    issuerRdn.push(
        new AttributeTypeAndValue({ type: '2.5.4.3', value: 'Test Root CA' }),
    )
    const issuer = new Name.RDNSequence()
    issuer.push(issuerRdn)

    const publicKey = new RSAPublicKey({
        modulus: new Uint8Array(256).fill(7),
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    })

    const subjectPublicKeyInfo = new SubjectPublicKeyInfo({
        algorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }),
        subjectPublicKey: publicKey,
    })

    // No Basic Constraints extension = not a CA

    const tbsCert = new Certificate.TBSCertificate({
        version: 2,
        serialNumber: new Uint8Array([0x04]),
        signature: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        issuer,
        validity,
        subject,
        subjectPublicKeyInfo,
    })

    return new Certificate({
        tbsCertificate: tbsCert,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        signatureValue: new Uint8Array(256).fill(8),
    })
}

function createCircularCertificate1(): Certificate {
    const validity = new Validity({
        notBefore: new Date(Date.now() - 24 * 60 * 60 * 1000),
        notAfter: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000),
    })

    const subjectRdn = new RelativeDistinguishedName()
    subjectRdn.push(
        new AttributeTypeAndValue({ type: '2.5.4.3', value: 'Circular CA 1' }),
    )
    const subject = new Name.RDNSequence()
    subject.push(subjectRdn)

    // Will be issued by Circular CA 2
    const issuerRdn = new RelativeDistinguishedName()
    issuerRdn.push(
        new AttributeTypeAndValue({ type: '2.5.4.3', value: 'Circular CA 2' }),
    )
    const issuer = new Name.RDNSequence()
    issuer.push(issuerRdn)

    const publicKey = new RSAPublicKey({
        modulus: new Uint8Array(256).fill(9),
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    })

    const subjectPublicKeyInfo = new SubjectPublicKeyInfo({
        algorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }),
        subjectPublicKey: publicKey,
    })

    const tbsCert = new Certificate.TBSCertificate({
        version: 2,
        serialNumber: new Uint8Array([0x05]), // Serial 5
        signature: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        issuer,
        validity,
        subject,
        subjectPublicKeyInfo,
    })

    return new Certificate({
        tbsCertificate: tbsCert,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        signatureValue: new Uint8Array(256).fill(10),
    })
}

function createEndEntityCertificateFor(issuer: Certificate): Certificate {
    const validity = new Validity({
        notBefore: new Date(Date.now() - 24 * 60 * 60 * 1000),
        notAfter: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    })

    const subjectRdn = new RelativeDistinguishedName()
    subjectRdn.push(
        new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'invalid-ca-test.example.com',
        }),
    )
    const subject = new Name.RDNSequence()
    subject.push(subjectRdn)

    const issuerName = issuer.tbsCertificate.subject

    const publicKey = new RSAPublicKey({
        modulus: new Uint8Array(256).fill(13),
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    })

    const subjectPublicKeyInfo = new SubjectPublicKeyInfo({
        algorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }),
        subjectPublicKey: publicKey,
    })

    const tbsCert = new Certificate.TBSCertificate({
        version: 2,
        serialNumber: new Uint8Array([0x07]), // Serial 7
        signature: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        issuer: issuerName,
        validity,
        subject,
        subjectPublicKeyInfo,
    })

    return new Certificate({
        tbsCertificate: tbsCert,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        signatureValue: new Uint8Array(256).fill(14),
    })
}

function createCircularCertificate2(cert1: Certificate): Certificate {
    const validity = new Validity({
        notBefore: new Date(Date.now() - 24 * 60 * 60 * 1000),
        notAfter: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000),
    })

    const subjectRdn = new RelativeDistinguishedName()
    subjectRdn.push(
        new AttributeTypeAndValue({ type: '2.5.4.3', value: 'Circular CA 2' }),
    )
    const subject = new Name.RDNSequence()
    subject.push(subjectRdn)

    // Issued by Circular CA 1, creating the loop
    const issuer = cert1.tbsCertificate.subject

    const publicKey = new RSAPublicKey({
        modulus: new Uint8Array(256).fill(11),
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    })

    const subjectPublicKeyInfo = new SubjectPublicKeyInfo({
        algorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }),
        subjectPublicKey: publicKey,
    })

    const tbsCert = new Certificate.TBSCertificate({
        version: 2,
        serialNumber: new Uint8Array([0x06]), // Serial 6
        signature: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        issuer,
        validity,
        subject,
        subjectPublicKeyInfo,
    })

    return new Certificate({
        tbsCertificate: tbsCert,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }),
        signatureValue: new Uint8Array(256).fill(12),
    })
}
