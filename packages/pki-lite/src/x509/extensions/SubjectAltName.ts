import { Asn1BaseBlock, asn1js } from '../../core/PkiBase.js'
import { GeneralName, GeneralNames } from '../GeneralName.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

export class SubjectAltName extends GeneralNames {
    static fromAsn1(asn1: Asn1BaseBlock): SubjectAltName {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for SubjectAltName',
            )
        }

        const generalNames: GeneralName[] = asn1.valueBlock.value.map(
            GeneralName.fromAsn1,
        )
        return new SubjectAltName(...generalNames)
    }
}
