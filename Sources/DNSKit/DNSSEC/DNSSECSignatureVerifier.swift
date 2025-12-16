// DNSKit
// Copyright (C) Ian Spence and other DNSKit Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import Foundation

/// Subnet of the DNSSEC Client for signature verification
internal struct DNSSECSignatureVerifier {
    internal static func verifySignatures(ofMessage message: Message, andResources resources: inout [String: (Message, Message?)], referencingKeyMap keyMap: inout [UInt32: Answer]) throws {
        // Validate signatures of the records from the original message
        for zone in DNSSECResourceCollector.getAllZonesInAnswers(message.answers) {
            try verifyMessage(message, forZone: zone, referencingKeyMap: &keyMap)
        }

        // Validate the signatures of all messages fetched as part of this DNSSEC authentication
        for (zone, (dnskeyMessage, dsMessage)) in resources {
            try verifyMessage(dnskeyMessage, forZone: zone, referencingKeyMap: &keyMap)

            if let dsMessage = dsMessage {
                try verifyMessage(dsMessage, forZone: zone, referencingKeyMap: &keyMap)
            }
        }
    }

    internal static func verifyMessage(_ message: Message, forZone zone: String, referencingKeyMap keyMap: inout [UInt32: Answer]) throws {
        var rrset: [Answer] = []
        var rrsig: Answer?

        for answer in message.answers where answer.name == zone {
            if answer.recordType == .RRSIG {
                rrsig = answer
            } else {
                rrset.append(answer)
            }
        }
        guard let rrsig = rrsig else {
            printError("[\(#fileID):\(#line)] No rrsig found for zone \(zone)")
            throw DNSSECError.noSignatures("No signature found for resource records belonging to \(zone)")
        }
        guard let rrsigData = rrsig.data as? RRSIGRecordData else {
            throw DNSSECError.invalidResponse("Incorrect data type in rrsig response for zone \(zone)")
        }
        guard let dnskey = keyMap[UInt32(rrsigData.keyTag)] else {
            throw DNSSECError.missingKeys("No matching key found to sign resource records belonging to \(zone)")
        }

        try verifyAnswers(rrset, signatureAnswer: rrsig, dnskeyAnswer: dnskey)
    }

    /// Validate the set of DNS Answers against the signature and key
    /// - Parameters:
    ///   - answers: The set of answers, exclusing the RRSIG answer
    ///   - signatureAnswer: The RRSIG answer associated for the set of answers
    ///   - dnskeyAnswer: The DNSKEY used to sign the RRSIG
    /// - Throws: Will thow on validation error. If no error is thrown then the answers validated successfully.
    internal static func verifyAnswers(_ answers: [Answer], signatureAnswer: Answer, dnskeyAnswer: Answer) throws {
        if answers.count == 0 {
            printError("[\(#fileID):\(#line)] Empty rrset")
            throw DNSSECError.invalidResponse("Empty rrset")
        }

        // All answers must have the same name, type, and class
        for i in 0...answers.count-1 {
            if answers[i].name != answers[0].name {
                printError("[\(#fileID):\(#line)] Mismatches names in rrset")
                throw DNSSECError.invalidResponse("Mismatches names in rrset")
            }
            if answers[i].recordType != answers[0].recordType {
                printError("[\(#fileID):\(#line)] Mismatches types in rrset")
                throw DNSSECError.invalidResponse("Mismatches types in rrset")
            }
            if answers[i].recordClass != answers[0].recordClass {
                printError("[\(#fileID):\(#line)] Mismatches classes in rrset")
                throw DNSSECError.invalidResponse("Mismatches classes in rrset")
            }
        }

        guard let rrsig = signatureAnswer.data as? RRSIGRecordData else {
            printError("[\(#fileID):\(#line)] Incorrect RRSIG record data")
            throw DNSSECError.noSignatures("Incorrect RRSIG record data")
        }
        guard let dnskey = dnskeyAnswer.data as? DNSKEYRecordData else {
            printError("[\(#fileID):\(#line)] Incorrect DNSKEY record data")
            throw DNSSECError.noSignatures("Incorrect DNSKEY record data")
        }

        if rrsig.keyTag != dnskey.keyTag {
            printError("[\(#fileID):\(#line)] Mismatched keytag from signature")
            throw DNSSECError.badSigningKey("Mismatched keytag from signature")
        }
        if signatureAnswer.recordClass != dnskeyAnswer.recordClass {
            printError("[\(#fileID):\(#line)] Mismatched record class from signature")
            throw DNSSECError.badSigningKey("Mismatched record class from signature")
        }
        if rrsig.algorithm != dnskey.algorithm {
            printError("[\(#fileID):\(#line)] Mismatched algorithm from signature")
            throw DNSSECError.badSigningKey("Mismatched algorithm from signature")
        }
        if rrsig.signerName.lowercased() != dnskeyAnswer.name.lowercased() {
            printError("[\(#fileID):\(#line)] Mismatched signer name from signature. Expected '\(rrsig.signerName.lowercased())' to equal '\(dnskeyAnswer.name.lowercased())'")
            throw DNSSECError.badSigningKey("Mismatched signer name from signature")
        }
        if dnskey.keyProtocol != 3 {
            printError("[\(#fileID):\(#line)] Unknown key protocol")
            throw DNSSECError.badSigningKey("Unknown key protocol")
        }
        if !dnskey.zoneKey {
            printError("[\(#fileID):\(#line)] Improper zone key usage")
            throw DNSSECError.badSigningKey("Improper zone key usage")
        }
        if dnskey.revoked {
            printError("[\(#fileID):\(#line)] Key is revoked")
            throw DNSSECError.badSigningKey("Key is revoked")
        }
        if answers[0].recordClass != signatureAnswer.recordClass {
            printError("[\(#fileID):\(#line)] Mismatched record class from signature")
            throw DNSSECError.badSigningKey("Mismatched record class from signature")
        }
        if answers[0].recordType != rrsig.typeCovered {
            printError("[\(#fileID):\(#line)] Mismatched record type from signature")
            throw DNSSECError.badSigningKey("Mismatched record type from signature")
        }

        guard var signedData: Data = try? Data(rrsig.signedData()) else {
            printError("[\(#fileID):\(#line)] Unable to determine signed data from signature")
            throw DNSSECError.invalidResponse("Unable to determine signed data from signature")
        }

        for answer in answers.sorted() {
            do {
                let rawSignatureData = try answer.rawSignatureData(rrsigAnswer: signatureAnswer)
                signedData.append(rawSignatureData)
            } catch {
                printError("[\(#fileID):\(#line)] Unable to determine signed data from signature")
                throw DNSSECError.invalidResponse("Unable to determine signed data from signature")
            }
        }

        let publicKey: SecKey
        do {
            publicKey = try dnskey.parsePublicKey()
        } catch {
            printError("[\(#fileID):\(#line)] Invalid public key: \(error.localizedDescription)")
            throw DNSSECError.badSigningKey("Invalid public key: \(error.localizedDescription)")
        }

        let algorithm: SecKeyAlgorithm
        switch rrsig.algorithm {
        case .RSA_SHA1:
            printError("[\(#fileID):\(#line)] SHA-1 is unsupported")
            throw DNSSECError.unsupportedAlgorithm
        case .RSA_SHA256:
            algorithm = .rsaSignatureMessagePKCS1v15SHA256
        case .RSA_SHA512:
            algorithm = .rsaSignatureMessagePKCS1v15SHA512
        case .ECDSAP256_SHA256:
            algorithm = .ecdsaSignatureMessageX962SHA256
        case .ECDSAP384_SHA384:
            algorithm = .ecdsaSignatureMessageX962SHA384
        }

        let signature = rrsig.signatureForCrypto()

        var verifyError: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(publicKey, algorithm, signedData as CFData, signature as CFData, &verifyError)

        if verified {
            printDebug("[\(#fileID):\(#line)] Signature validation passed for \(answers[0].name)")
        } else {
            if log?.currentLevel() == .Debug {
                printDebug("[\(#fileID):\(#line)] Public key: \(dnskey.publicKey.hexEncodedString())")
                printDebug("[\(#fileID):\(#line)] Signed data: \(signedData.hexEncodedString())")
                printDebug("[\(#fileID):\(#line)] Signature: \(signature.hexEncodedString())")
            }
            printError("[\(#fileID):\(#line)] Signature validation failed with algorithm \(String(describing: algorithm))")
            throw DNSSECError.signatureFailed
        }
    }
}
