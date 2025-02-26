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

/// Describes all DNSSEC resources for a zone
public struct DNSSECResource: Sendable {
    /// The zone name
    public let zone: String
    /// DNSKEY answers for this zone
    public let dnsKeys: [Answer]
    /// Signatures for the DNSKEY response
    public let keySignature: Answer
    /// DS answers for this zone
    public let ds: [Answer]
    /// Signatures for the DS response
    public let dsSignature: Answer?

    internal init(zone: String, dnsKeys: [Answer], keySignature: Answer, ds: [Answer], dsSignature: Answer?) {
        self.zone = zone
        self.dnsKeys = dnsKeys
        self.keySignature = keySignature
        self.ds = ds
        self.dsSignature = dsSignature
    }

    /// Use for testing only
    internal init(dnskeyMessage: Message, dsMessage: Message?) {
        self.zone = dnskeyMessage.answers[0].name

        var dnsKeys: [Answer] = []
        var keySignature: Answer?
        for answer in dnskeyMessage.answers {
            switch answer.recordType {
            case .RRSIG:
                keySignature = answer
            case .DNSKEY:
                dnsKeys.append(answer)
            default:
                fatalError("Unknown message type")
            }
        }

        if dnsKeys.isEmpty {
            fatalError("no DNSKEY answer")
        }
        self.dnsKeys = dnsKeys
        if keySignature == nil {
            fatalError("no DNSKEY RRSIG answer")
        }
        self.keySignature = keySignature!

        if let message = dsMessage {
            var ds: [Answer] = []
            var dsSignature: Answer?
            for answer in message.answers {
                switch answer.recordType {
                case .RRSIG:
                    dsSignature = answer
                case .DS:
                    ds.append(answer)
                default:
                    fatalError("Unknown message type")
                }
            }

            if ds.isEmpty {
                fatalError("no DS answer")
            }
            if dsSignature == nil {
                fatalError("no DS RRSIG answer")
            }
            self.ds = ds
            self.dsSignature = dsSignature!
        } else {
            self.ds = []
            self.dsSignature = nil
        }
    }
}
