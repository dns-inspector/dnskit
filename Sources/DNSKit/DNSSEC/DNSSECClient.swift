// DNSKit
// Copyright (C) 2025 Ian Spence
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

/// DNSSEC client
internal struct DNSSECClient {
    /// Authenticate that the message was signed with a fully valid chain, going up to the DNS root.
    /// - Parameters:
    ///   - message: The message to authenticate
    ///   - client: The DNS client to use for queries
    ///   - complete: Called with the result of this DNSSEC operation
    internal static func authenticateMessage(_ message: Message, client: IClient, complete: (DNSSECResult) -> Void) throws {
        var oRrsigData: RRSIGRecordData?

        for answer in message.answers {
            if answer.recordType != .RRSIG {
                continue
            }

            guard let data = answer.data as? RRSIGRecordData else {
                printError("[\(#fileID):\(#line)] Invalid RRSIG data")
                throw DNSSECError.invalidResponse("Invalid RRSIG data")
            }

            oRrsigData = data
            break
        }

        guard let rrsigData = oRrsigData else {
            printError("[\(#fileID):\(#line)] No record signature included in message")
            throw DNSSECError.invalidResponse("No record signature included in message")
        }

        switch rrsigData.algorithm {
        case .RSA_SHA256, .RSA_SHA512, .ECDSAP256_SHA256, .ECDSAP384_SHA384:
            break
        default:
            printError("[\(#fileID):\(#line)] Unsupported or unknown algorithm")
            throw DNSSECError.unsupportedAlgorithm
        }

        let resources: [DNSSECResource]
        do {
            resources = try DNSSECClient.getKeyChain(startingAt: rrsigData.signerName, client: client)
            if resources.count == 0 {
                printError("[\(#fileID):\(#line)] No signing keys found")
                throw DNSSECError.missingKeys("No signing keys found")
            }
        } catch {
            var result = DNSSECResult()
            if let error = error as? DNSSECError {
                result.signatureError = error
            } else {
                printError("[\(#fileID):\(#line)] DNSSECClient.getKeyChain threw non DNSSECError type: \(error)")
                result.signatureError = .internalError(error.localizedDescription)
            }
            complete(result)
            return
        }

        let result = try authenticate(message: message, resources: resources)
        complete(result)
    }

    /// Authenticate the message with the given set of resources
    /// - Parameters:
    ///   - message: The message to authenticate
    ///   - resources: The authentication resources
    internal static func authenticate(message: Message, resources: [DNSSECResource]) throws -> DNSSECResult {
        var result = DNSSECResult()
        result.resources = resources

        // Double check that the root KSK is one of our trusted KSKs
        guard let rootResource = resources.last else {
            printError("[\(#fileID):\(#line)] No signing keys found")
            throw DNSSECError.missingKeys("No signing keys found")
        }
        var foundRootKsk = false
        for rootKeyAnswer in rootResource.dnsKeys {
            guard let data = rootKeyAnswer.data as? DNSKEYRecordData else {
                continue
            }

            if !data.keySigningKey {
                continue
            }

            for rootKsk in trustedRootKSKs where rootKsk.publicKey == data.publicKey {
                foundRootKsk = true
                break
            }
        }
        if !foundRootKsk {
            printError("[\(#fileID):\(#line)] Unable to locate root key signing key")
            result.chainError = DNSSECError.untrustedRootSigningKey
            return result
        }

        // Starting at the furthest descdent zone:
        // - Verify the signature of the original message against its RR and the DNSKEY we fetched
        // - Verify the signature of the DNSKEY message
        // - Verify the DS record of each parent zoon, until the root
        // If all of the above tests pass, then we can attest full trust of the chain

        // Verify the signature of the original message against its RR and the DNSKEY we fetched
        do {
            var rrset: [Answer] = []
            var oRrsigAnswer: Answer?

            for answer in message.answers {
                if answer.recordType == .RRSIG {
                    oRrsigAnswer = answer
                    continue
                } else {
                    rrset.append(answer)
                }
            }

            guard let rrsigAnswer = oRrsigAnswer else {
                printError("[\(#fileID):\(#line)] No signature for associated resource record")
                result.signatureError = DNSSECError.noSignatures("No signature for associated resource record")
                return result
            }

            guard let rrsig = rrsigAnswer.data as? RRSIGRecordData else {
                printError("[\(#fileID):\(#line)] No signature for associated resource record")
                result.signatureError = DNSSECError.noSignatures("No signature for associated resource record")
                return result
            }

            // Find the matching key
            var oZsk: Answer?
            for dnskey in resources[0].dnsKeys {
                guard let key = dnskey.data as? DNSKEYRecordData else {
                    printError("[\(#fileID):\(#line)] Bad record data type on \(dnskey.description)")
                    continue
                }
                if key.keyTag == rrsig.keyTag {
                    oZsk = dnskey
                    break
                }
            }
            guard let zsk = oZsk else {
                printError("[\(#fileID):\(#line)] No key with tag \(rrsig.keyTag) found on zone \(resources[0].zone)")
                result.signatureError = DNSSECError.missingKeys("No matching key found")
                return result
            }

            do {
                try DNSSECClient.validateAnswers(rrset, signatureAnswer: rrsigAnswer, dnskeyAnswer: zsk)
            } catch {
                printError("[\(#fileID):\(#line)] RRSIG validation failure for rrset record in \(rrset[0].name)")
                if let error = error as? DNSSECError {
                    result.signatureError = error
                } else {
                    printError("[\(#fileID):\(#line)] DNSSECClient.validateAnswers threw non DNSSECError type: \(error)")
                    result.signatureError = .internalError(error.localizedDescription)
                }
                return result
            }

            result.signatureVerified = true
        }

        // Verify the signature of the DNSKEY message
        do {
            let keyAnswers = resources[0].dnsKeys
            let rrsigAnswer = resources[0].keySignature
            guard let rrsig = rrsigAnswer.data as? RRSIGRecordData else {
                printError("[\(#fileID):\(#line)] No signature for associated resource record")
                result.signatureError = DNSSECError.noSignatures("No signature for associated resource record")
                return result
            }

            // Find the matching key
            var oKsk: Answer?
            for dnskey in resources[0].dnsKeys {
                guard let key = dnskey.data as? DNSKEYRecordData else {
                    continue
                }
                if key.keyTag == rrsig.keyTag {
                    oKsk = dnskey
                    break
                }
            }
            guard let ksk = oKsk else {
                printError("[\(#fileID):\(#line)] No key with tag \(rrsig.keyTag) found on zone")
                result.signatureError = DNSSECError.missingKeys("No matching key found")
                return result
            }

            do {
                try DNSSECClient.validateAnswers(keyAnswers, signatureAnswer: rrsigAnswer, dnskeyAnswer: ksk)
            } catch {
                printError("[\(#fileID):\(#line)] RRSIG validation failure for DNSKEY record in \(keyAnswers[0].name)")
                if let error = error as? DNSSECError {
                    result.signatureError = error
                } else {
                    printError("[\(#fileID):\(#line)] DNSSECClient.validateAnswers threw non DNSSECError type: \(error)")
                    result.signatureError = .internalError(error.localizedDescription)
                }
                return result
            }
        }

        // Only perform chain verification if there is a chain to verify
        if message.questions.first?.name == "." {
            result.chainTrusted = result.signatureVerified
            return result
        }

        // Verify the DS record of each parent zone, until the root
        for i in 0...resources.count-2 { // -2 because the root doesn't have a DS
            let rrset = resources[i].ds

            // Check the ds digest
            do {
                var digestMatched = true
                for dsAnswer in rrset {
                    guard let ds = dsAnswer.data as? DSRecordData else {
                        printError("[\(#fileID):\(#line)] Missing required DS record \(resources[i].zone)")
                        result.chainError = DNSSECError.noSignatures("Missing required DS record")
                        return result
                    }
                    for dnskeyAnswer in resources[i].dnsKeys {
                        guard let dnskey = dnskeyAnswer.data as? DNSKEYRecordData else {
                            continue
                        }
                        if ds.keyTag != dnskey.keyTag {
                            continue
                        }

                        guard let digest = try? dnskey.hashWithOwnerName(dsAnswer.name, digest: ds.digestType) else {
                            continue
                        }

                        if digest == ds.digest {
                            digestMatched = true
                            break
                        }
                    }
                }

                if !digestMatched {
                    printError("[\(#fileID):\(#line)] No matching DNSKEY found from DS digest")
                    result.chainError = DNSSECError.missingKeys("Unknown DNSKEY referenced in DS record")
                    return result
                }
            }

            guard let rrsigAnswer = resources[i].dsSignature else {
                printError("[\(#fileID):\(#line)] Missing DS record signature")
                result.signatureError = DNSSECError.noSignatures("Missing DS record signature")
                return result
            }

            guard let rrsig = rrsigAnswer.data as? RRSIGRecordData else {
                printError("[\(#fileID):\(#line)] Missing DS record signature")
                result.signatureError = DNSSECError.noSignatures("Missing DS record signature")
                return result
            }

            // DS Records are signed by their parent zone's key
            var dnskeyAnswer: Answer?
            var keyTag: UInt32?
            for answer in resources[i+1].dnsKeys {
                guard let dnskey = answer.data as? DNSKEYRecordData else {
                    continue
                }
                if dnskey.keyTag == rrsig.keyTag {
                    dnskeyAnswer = answer
                    keyTag = dnskey.keyTag
                    break
                }
            }
            guard let dnskeyAnswer = dnskeyAnswer, let keyTag = keyTag else {
                printError("[\(#fileID):\(#line)] No key with tag \(rrsig.keyTag) found on zone")
                result.chainError = DNSSECError.missingKeys("Missing DNSKEY for RRSIG")
                return result
            }

            do {
                printDebug("[\(#fileID):\(#line)] Validating DS record for \(rrset[0].name) against key \(keyTag)")
                try DNSSECClient.validateAnswers(rrset, signatureAnswer: rrsigAnswer, dnskeyAnswer: dnskeyAnswer)
            } catch {
                printError("[\(#fileID):\(#line)] RRSIG validation failure for DS record in \(rrset[0].name)")
                if let error = error as? DNSSECError {
                    result.chainError = error
                } else {
                    printError("[\(#fileID):\(#line)] DNSSECClient.validateAnswers threw non DNSSECError type: \(error)")
                    result.chainError = .internalError(error.localizedDescription)
                }
                result.chainTrusted = false
                return result
            }
            result.chainTrusted = true
        }

        return result
    }

    /// Get the chain of keys & signatures starting from the given name going up to the root zone
    /// - Parameters:
    ///   - name: The name to start from
    ///   - client: The client to use for performing queries
    /// - Returns: An array of DNSSEC resources for each zone
    /// - Throws: Will throw on any error getting the data or if any required data is missing
    internal static func getKeyChain(startingAt name: String, client: IClient) throws -> [DNSSECResource] {
        let names = AtomicArray<String>(initialValue: [])
        var nextName = name
        let questionsToSend = AtomicInt(initialValue: 0)
        let questionsAnswered = AtomicInt(initialValue: 0)

        while true {
            names.Append(nextName)
            _ = questionsToSend.IncrementAndGet(amount: 2) // DNSKEY + DS question per zone

            let nameParts = nextName.split(separator: ".")
            if nameParts.count == 0 || nameParts[0].count == 0 {
                break
            } else {
                nextName = nameParts.suffix(from: 1).joined(separator: ".")
                if nextName.count == 0 {
                    nextName = "."
                }
            }
        }

        let dnskeyErrors = AtomicMap<Int, DNSKitError>(initialValue: [:])
        let dsErrors = AtomicMap<Int, DNSKitError>(initialValue: [:])
        let dnskeyAnswers = AtomicMap<Int, [Answer]>(initialValue: [:])
        let dsAnswers = AtomicMap<Int, [Answer]>(initialValue: [:])

        let sync = DispatchSemaphore(value: 0)

        // Get all the resource we need in parallel
        for i in 0...names.Count()-1 {
            let name = names.Get(i)
            // Get the DNSKEY for this zone
            let dnskeyQuestion = Question(name: name, recordType: .DNSKEY, recordClass: .IN)
            printDebug("[\(#fileID):\(#line)] Getting DNSKEY for \(name)")
            let message = Message(question: dnskeyQuestion, dnssecOK: true)
            client.send(message: message) { result in
                switch result {
                case .success(let reply):
                    if reply.responseCode != .NOERROR {
                        printError("[\(#fileID):\(#line)] No DNSKEY record for zone \(name)")
                        dnskeyErrors.Set(i, .missingData("No DNSKEY record for zone \(name)"))
                        break
                    }

                    var hasDNSKEY = false
                    var hasRRSIG = false
                    for answer in reply.answers {
                        switch answer.recordType {
                        case .RRSIG:
                            hasRRSIG = true
                        case .DNSKEY:
                            hasDNSKEY = true
                        default:
                            break
                        }
                    }

                    if !hasDNSKEY {
                        printError("[\(#fileID):\(#line)] No DNSKEY record for zone \(name)")
                        dnskeyErrors.Set(i, .missingData("No DNSKEY record for zone \(name)"))
                    } else if !hasRRSIG {
                        printError("[\(#fileID):\(#line)] No RRSIG record for zone \(name)")
                        dnskeyErrors.Set(i, .missingData("No RRSIG record for zone \(name)"))
                    } else {
                        printDebug("[\(#fileID):\(#line)] Fetched \(reply.answers.count) DNSKEYs for zone \(name)")
                        dnskeyAnswers.Set(i, reply.answers)
                    }
                case .failure(let error):
                    printError("[\(#fileID):\(#line)] Error getting DNSKEY records for zone \(name)")
                    dnskeyErrors.Set(i, error)
                }

                if questionsAnswered.IncrementAndGet() >= questionsToSend.Get() {
                    sync.signal()
                }
            }

            // Root zone does not have a DS
            if name.count == 1 && name == "." {
                if questionsAnswered.IncrementAndGet() >= questionsToSend.Get() {
                    sync.signal()
                }
                continue
            }

            // Get the DS record for this zone
            let dsQuestion = Question(name: name, recordType: .DS, recordClass: .IN)
            printDebug("[\(#fileID):\(#line)] Getting DS for \(name)")
            let dsMessage = Message(question: dsQuestion, dnssecOK: true)
            client.send(message: dsMessage) { result in
                switch result {
                case .success(let reply):
                    if reply.responseCode != .NOERROR {
                        printError("[\(#fileID):\(#line)] No DS record for zone \(name)")
                        dnskeyErrors.Set(i, .missingData("No DS record for zone \(name)"))
                        break
                    }

                    var hasDS = false
                    var hasRRSIG = false
                    for answer in reply.answers {
                        switch answer.recordType {
                        case .RRSIG:
                            hasRRSIG = true
                        case .DS:
                            hasDS = true
                        default:
                            break
                        }
                    }

                    if !hasDS {
                        printError("[\(#fileID):\(#line)] No DS record for zone \(name)")
                        dsErrors.Set(i, .missingData("No DS record for zone \(name)"))
                    } else if !hasRRSIG {
                        printError("[\(#fileID):\(#line)] No RRSIG record for zone \(name)")
                        dsErrors.Set(i, .missingData("No RRSIG record for zone \(name)"))
                    } else {
                        printDebug("[\(#fileID):\(#line)] Fetched \(reply.answers.count) DSs for zone \(name)")
                        dsAnswers.Set(i, reply.answers)
                    }
                case .failure(let error):
                    printError("[\(#fileID):\(#line)] Error getting DS records for zone \(name)")
                    dsErrors.Set(i, error)
                }

                if questionsAnswered.IncrementAndGet() >= questionsToSend.Get() {
                    sync.signal()
                }
            }
        }

        _ = sync.wait(timeout: .now().adding(seconds: 10))
        if questionsAnswered.Get() != questionsToSend.Get() {
            printError("[\(#fileID):\(#line)] Unable to query for all records")
            printError("[\(#fileID):\(#line)] One or more DNSKEY or DS records or their associated signatures were not found")
            throw DNSSECError.missingKeys("One or more DNSKEY or DS records or their associated signatures were not found")
        }

        var resources: [DNSSECResource] = []

        // Sort through the answers and split up the DNSKEY, the RRSIG for the DNSKEY, and the same for the DS
        for i in 0..<names.Count() {
            let name = names.Get(i)
            var keys: [Answer] = []
            var oKeySig: Answer?
            for answer in dnskeyAnswers.Get(i) ?? [] {
                if answer.recordType == .DNSKEY {
                    keys.append(answer)
                } else if answer.recordType == .RRSIG {
                    oKeySig = answer
                }
            }
            guard let keySig = oKeySig else {
                printError("[\(#fileID):\(#line)] Missing RRSIG for DNSKEY \(name)")
                throw DNSSECError.missingKeys("Missing RRSIG for DNSKEY \(name)")
            }

            var ds: [Answer] = []
            var dsSig: Answer?
            if name.count > 1 {
                guard let answers = dsAnswers.Get(i) else {
                    printError("[\(#fileID):\(#line)] Missing RRSIG for DS \(name)")
                    throw DNSSECError.missingKeys("Missing RRSIG for DS \(name)")
                }
                for answer in answers {
                    if answer.recordType == .DS {
                        ds.append(answer)
                    } else if answer.recordType == .RRSIG {
                        dsSig = answer
                    }
                }
                if dsSig == nil {
                    printError("[\(#fileID):\(#line)] Missing RRSIG for DS \(name)")
                    throw DNSSECError.missingKeys("Missing RRSIG for DS \(name)")
                }
            }

            resources.append(DNSSECResource(zone: name, dnsKeys: keys, keySignature: keySig, ds: ds, dsSignature: dsSig))
        }

        printInformation("[\(#fileID):\(#line)] Fetched DNSKEY and DS for \(names.Count()) zones")
        return resources
    }

    /// Validate the set of DNS Answers against the signature and key
    /// - Parameters:
    ///   - answers: The set of answers, exclusing the RRSIG answer
    ///   - signatureAnswer: The RRSIG answer associated for the set of answers
    ///   - dnskeyAnswer: The DNSKEY used to sign the RRSIG
    /// - Throws: Will thow on validation error. If no error is thrown then the answers validated successfully.
    internal static func validateAnswers(_ answers: [Answer], signatureAnswer: Answer, dnskeyAnswer: Answer) throws {
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
            printError("[\(#fileID):\(#line)] Mismatched signer name from signature")
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
            printDebug("[\(#fileID):\(#line)] Signature validation passed")
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
