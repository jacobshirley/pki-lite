import { setCryptoProvider } from 'pki-lite/core/crypto/provider.js'
import { PFX } from 'pki-lite/pkcs12/PFX'
import { describe, expect, it } from 'vitest'
import { WebCryptoExtendedProvider } from '../../src'

const pem = `-----BEGIN PKCS12-----
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
-----END PKCS12-----`

describe('PKCS#12 PFX', () => {
    it('should decode a PFX file', async () => {
        setCryptoProvider(new WebCryptoExtendedProvider())

        const decoded = PFX.fromPem(pem)
        const privateKeys = await decoded.getPrivateKeys('Password123')
        expect(privateKeys.map((k) => k.getPrivateKey().toPem()))
            .toMatchInlineSnapshot(`
          [
            "-----BEGIN PRIVATE KEY-----
          MIIEogIBAAKCAQEAwhyN32zkV/7BCMECzNpYcZXUvgDUTnK1qunE1mijwSGpR1EK1f3pis5Cbtmp8z6z/snJAN1qhjkDX3ahWoivdpRFNPV78Egl/6CGvxWjnKVb4U5VnBIlHvs7VI/jMaZ3CltNZ7TCi/SG+0q/O0cRheAjZtoJK5vSb3dl3l6dW0U7nhBgKLVNDcScEEtkMJhbvkzid+m6VcznCqDIha2Bv2ag+JZJuICEBcl/hOqlJL1/VqCR5X6bdAepG3pIdSF8PNKCZnHmhiuuTUw/LDTnCiS6VJRXp64pQtdegwa8BRy29y9ACY/HomTOBbrk7qCidlaSrdOUkOA7Hr/QvD8oOQIDAQABAoH/GMpdqviQiWsovk5TBl1N9KmwdpXnrsQg1v6nrgYV7vvQZbR5uAGvg9yJNENlaYG5Zs1bNc77HULjLLAgsRGgmqdk/Nx1tjg+oKGD8MNGqxfMWRWn3is3t+yFCWoIUkQLkJ+ILSWbDxida9VzToDnZKJCyTnp93mf5xpByVnPx3sjtLdkaJS37prHw+AaPuXFg9bdJ9ZZB3bMub1EuCT2/YnIms3+TzpLVromoh3XaaS12bQ7i3HtHvK4O/dgffv/1UQ0JAt3aYQ1vsarEZJk49U+U4+JkLD/qkANc6PR8WxDM4HrzCQWjwP4vlcov+ZtE/6bLO++k/agXdz3th9NAoGBAOigm79PSpD3CRtX9YdWRjMxmB8O+800qkltBtIwNLlHPR0Nvf1BcV++wNKFjS/7VtqRvUShKabdzWKdQC5qTMoJzDHP650Gpa/u7R9/Mlgk5yoCQn2mUL7p42VNbn9YsBjGAi2Sqlbesw4OkiHgnT8lzQBDDPyrwg1GpAYtin1dAoGBANWdSGXcj3//Rv6pbjxQt6SImp/f1VlQqGaxwu3v2q4HdISKSDg2R5h9yggeMj6jrxbOUZfnx16mIjIRqL17BGmBTY1TvlyvCjh2hvZn5namLzmdDU4rFL5LEPoS4N+f5P3Bf8sIBmNwfg5b4L6yCmjbwTbTPQhOWj97Ueg0OsyNAoGAOk4W+0o6XD8ujyXqqjMbgTVK9W3h+rrae3DSJthiPpX2YVPSbKl8awz6c0l5667JRBsHHy5trB8nnTHgpkGKYZE3Fr0QRtklqgTuddiBm8oUDllmpOuMjW09y2Qu78ggyvTGEvoRq5hBtKI+SjNr9inZSdmEZcf+6Sjtb4b2kRkCgYEAueLii3GBlnrIhvddrDL5e747///CIrTjtmneHTvp6iMmq+fBrNjfOL3Nv363bnb1+DyWGEBj5+NeQn/HfQu97SnOGLvVHcZceIH8NBR6Iqm+0r3uRCWNKYMdROCEu1Ti6kcmM8HJ/WJ473nYe1lnYZRJ8LGlnMLCGhfwUMaSnEkCgYEA43bGgP6K9816NSFbZcTtA+nHGUxaaxie4JBHqA12YHo6nfQ5smr4pj/d4+Fx5eJUfYcAfxT8kPSpU8ESQGihSSPNwObJ6zPxf4GjJLGFCmLJKRyvnb4dO/HwVguZ3TkWs3wZtkLTbtLLHIvasU9G9HDEjeEVaqAkpAhv+/6DeIg=
          -----END PRIVATE KEY-----",
          ]
        `)

        const certs = await decoded.getX509Certificates('Password123')
        expect(certs.map((c) => c.toPem())).toMatchInlineSnapshot(`
          [
            "-----BEGIN CERTIFICATE-----
          MIIDVDCCAjygAwIBAgIKDda3kfb20aJ9GzANBgkqhkiG9w0BAQsFADBYMREwDwYDVQQDEwhQREYgTGl0ZTEJMAcGA1UEChMAMQkwBwYDVQQLEwAxIDAeBgkqhkiG9w0BCQEWEXBkZi1saXRlQHRlc3QuY29tMQswCQYDVQQGEwJVUzAeFw0yNTA4MTUxNjUzNDBaFw0zMDA4MTUxNjUzNDBaMFgxETAPBgNVBAMTCFBERiBMaXRlMQkwBwYDVQQKEwAxCTAHBgNVBAsTADEgMB4GCSqGSIb3DQEJARYRcGRmLWxpdGVAdGVzdC5jb20xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwhyN32zkV/7BCMECzNpYcZXUvgDUTnK1qunE1mijwSGpR1EK1f3pis5Cbtmp8z6z/snJAN1qhjkDX3ahWoivdpRFNPV78Egl/6CGvxWjnKVb4U5VnBIlHvs7VI/jMaZ3CltNZ7TCi/SG+0q/O0cRheAjZtoJK5vSb3dl3l6dW0U7nhBgKLVNDcScEEtkMJhbvkzid+m6VcznCqDIha2Bv2ag+JZJuICEBcl/hOqlJL1/VqCR5X6bdAepG3pIdSF8PNKCZnHmhiuuTUw/LDTnCiS6VJRXp64pQtdegwa8BRy29y9ACY/HomTOBbrk7qCidlaSrdOUkOA7Hr/QvD8oOQIDAQABoyAwHjAPBgkqhkiG9y8BAQoEAgUAMAsGA1UdDwQEAwIDGDANBgkqhkiG9w0BAQsFAAOCAQEAfIW/TmChrj0qefmN/xjxpENMDaXvQJ79nPDTVaqmsjhbbdAJnb2ewdkmK2bYoJBnuANPrIW1UeNO6wnr4dD9R+SQ4h57OU683WenIeiesZqlpyCV1PP0M0g3WwnAZAUhvNr9zJob1E5k4my6cwY9DT1HgKOKWdeOMFzoa8aV/uHwaZASZUAr1/+NAtA+XufONWLTVbvfEA0oL28BNunqv32m/nrrFSIryjYza7GPP7QjLxfM2EHqs6fnupIBm0HoIz26eroyPpzIjHWz77ykr1q46Xf/evougaTR4x8gJl0qEYFYPNBm4UdF1Ra+URfxcTgFAyANk9DwqlYlXfiqAw==
          -----END CERTIFICATE-----",
          ]
        `)

        const bags = await decoded.getBags('Password123')
        expect(bags.length).toBe(2)
    })
})
