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
    /// Authenticate the given message by verifying its signatures and establishing a chain-of-trust for all
    /// zones and parent zones in the message.
    /// - Parameters:
    ///   - message: The message to authenticate
    ///   - client: The client to use to fetch additional resources
    /// - Returns: A DNSSEC result
    internal static func authenticateMessage(_ message: Message, client: IClient) throws -> DNSSECResult {
        let zonesToFetch = DNSSECResourceCollector.getAllZonesInMessage(message)
        printDebug("[\(#fileID):\(#line)] Getting resources for zones: \(zonesToFetch)")
        var resources = try DNSSECResourceCollector.getAllDNSSECResources(zones: zonesToFetch, client: client)

        var result = DNSSECResult()

        // Ensure the KSK of the root zone matches one of the expected keys
        guard let (rootDNSKey, _) = resources["."] else {
            printError("[\(#fileID):\(#line)] No root zone signing keys found")
            throw DNSSECError.missingKeys("No root zone signing keys found")
        }
        var foundRootKsk = false
        for answer in rootDNSKey.answers where answer.recordType == .DNSKEY {
            guard let data = answer.data as? DNSKEYRecordData else {
                throw DNSSECError.invalidResponse("Incorrect data type in DNSKEY response for root zone")
            }

            if !data.keySigningKey {
                continue
            }

            for rootKsk in trustedRootKSKs where rootKsk.publicKey == data.publicKey {
                foundRootKsk = true
                break
            }
#if DEBUG
            // Extra root zone KSKs only meant to debugging
            for debugKsk in debugTrustedRootKSKs where debugKsk.publicKey == data.publicKey {
                printWarning("[\(#fileID):\(#line)] Using debug root zone key signing key \(debugKsk.id)")
                foundRootKsk = true
                break
            }
#endif
        }
        if !foundRootKsk {
            printError("[\(#fileID):\(#line)] Unable to locate root key signing key")
            result.chainError = DNSSECError.untrustedRootSigningKey
            return result
        }

        // Build a map of keyId to key, and zone to DS record
        var keyMap: [UInt32: Answer] = [:]
        for (zone, (dnskeyMessage, dsMessage)) in resources {
            var dnskeys: [Answer] = []
            var dnskeySignature: Answer?
            for answer in dnskeyMessage.answers where answer.recordType == .DNSKEY {
                guard let data = answer.data as? DNSKEYRecordData else {
                    throw DNSSECError.invalidResponse("Incorrect data type in DNSKEY response for zone \(zone)")
                }
                keyMap[data.keyTag] = answer
                dnskeys.append(answer)
            }
            for answer in dnskeyMessage.answers where answer.recordType == .RRSIG {
                dnskeySignature = answer
            }
            guard let dnskeySignature = dnskeySignature else {
                throw DNSSECError.noSignatures("Missing signature for DNSKEY on \(zone)")
            }
            var ds: [Answer] = []
            var dsSignature: Answer?
            if let dsMessage = dsMessage {
                for answer in dsMessage.answers where answer.recordType == .DS {
                    ds.append(answer)
                }
                for answer in dsMessage.answers where answer.recordType == .RRSIG {
                    dsSignature = answer
                }
                if dsSignature == nil {
                    throw DNSSECError.noSignatures("Missing signature for DS on \(zone)")
                }
            }
            result.resources.append(DNSSECResource(zone: zone, dnsKeys: dnskeys, keySignature: dnskeySignature, ds: ds, dsSignature: dsSignature))
        }

        // Validate the signatures
        do {
            try DNSSECSignatureVerifier.verifySignatures(ofMessage: message, andResources: &resources, referencingKeyMap: &keyMap)
            result.signatureVerified = true
        } catch {
            printError("[\(#fileID):\(#line)] Signature validation failed: \(error)")
            if let error = error as? DNSSECError {
                result.signatureError = error
            } else {
                result.signatureError = DNSSECError.internalError("\(error)")
            }
        }

        // Only perform chain verification if there is a chain to verify
        if message.questions.first?.name == "." {
            result.chainTrusted = result.signatureVerified
            return result
        }

        // Establish chain of trust with the root zone
        do {
            try DNSSECChainEvalulator.evalulateChain(ofZones: DNSSECResourceCollector.getAllZonesInAnswers(message.answers), withResources: &resources, andKeyMap: &keyMap)
            result.chainTrusted = true
        } catch {
            if let error = error as? DNSSECError {
                result.chainError = error
            } else {
                result.chainError = DNSSECError.internalError("\(error)")
            }
        }

        return result
    }
}
