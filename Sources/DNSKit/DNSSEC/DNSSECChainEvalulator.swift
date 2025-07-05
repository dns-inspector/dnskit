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

/// Subnet of the DNSSEC Client for evaluating a chain-of-trust
internal struct DNSSECChainEvalulator {
    /// Evaluate the zone delegation and establish a chain-of-trust to the root zone
    /// - Parameters:
    ///   - zones: The zones to use. Should be the output from ``DNSSECResourceCollector.getAllZonesInAnswers``.
    ///   - Resources: The resources to reference
    ///   - keyMap: The key map to reference
    internal static func evalulateChain(ofZones zones: [String], withResources resources: inout [String: (Message, Message?)], andKeyMap keyMap: inout [UInt32: Answer]) throws {
        for startZone in zones {
            let parents = Name.parentNames(from: startZone)

            for i in 0...parents.count-2 { // -2 because the root doesn't have a DS
                let zone = parents[i]

                guard let (_, dsMessage) = resources[zone], let dsMessage = dsMessage else {
                    printError("[\(#fileID):\(#line)] No DS record found for \(zone)")
                    throw DNSSECError.noSignatures("No DS record for \(zone)")
                }
                guard let (dnskeyMessage, _) = resources[zone] else {
                    printError("[\(#fileID):\(#line)] No DNSKEY record found to sign \(zone)'s DS record")
                    throw DNSSECError.missingKeys("No DNSKEY record found to sign \(zone)'s DS record")
                }

                var hasValidDs = false
                for dsAnswer in dsMessage.answers where dsAnswer.recordType == .DS {
                    guard let ds = dsAnswer.data as? DSRecordData else {
                        printError("[\(#fileID):\(#line)] Missing required DS record \(zone)")
                        throw DNSSECError.noSignatures("Missing required DS record")
                    }
                    guard let dnskey = keyMap[UInt32(ds.keyTag)]?.data as? DNSKEYRecordData else {
                        // Some zones include multiple DS records, which may point to a DNSKEY that doesn't exist
                        // By itself this doesn't mean the delegation is invalid, so long as there is at least one valid DS record for the zone
                        printWarning("[\(#fileID):\(#line)] \(zone)'s DS record references non-existant DNSKEY")
                        continue
                    }

                    // Double check the zone signed the DS record as expected
                    var zoneSigned = false
                    for dnskeyAnswer in dnskeyMessage.answers where dnskeyAnswer.recordType == .DNSKEY {
                        guard let data = dnskeyAnswer.data as? DNSKEYRecordData else {
                            continue
                        }

                        if data.publicKey == dnskey.publicKey {
                            zoneSigned = true
                            break
                        }
                    }
                    if !zoneSigned {
                        printError("[\(#fileID):\(#line)] No DNSKEY record found to sign \(zone)'s DS record")
                        throw DNSSECError.missingKeys("No DNSKEY record found to sign \(zone)'s DS record")
                    }

                    let digest: Data
                    do {
                        digest = try dnskey.hashWithOwnerName(dsAnswer.name, digest: ds.digestType)
                    } catch {
                        printError("[\(#fileID):\(#line)] Unable to hash \(zone) name with DNSKEY: \(error)")
                        throw error
                    }

                    if digest != ds.digest {
                        printError("[\(#fileID):\(#line)] No matching DNSKEY found from DS digest")
                        throw DNSSECError.missingKeys("Unknown DNSKEY referenced in DS record")
                    }
                    hasValidDs = true
                }
                if !hasValidDs {
                    throw DNSSECError.missingKeys("No DNSKEY record found to sign \(zone)'s DS record")
                }
            }
        }
    }
}
