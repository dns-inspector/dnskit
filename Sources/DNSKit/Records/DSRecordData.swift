// DNSKit
// Copyright (C) 2024 Ian Spence
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

/// Describes the record data for a DS record
public struct DSRecordData: RecordData {
    /// The key tag that signed this digest
    public let keyTag: UInt16
    /// The algorithm of the signature
    public let algorithm: DNSSECAlgorithm
    /// The digest type
    public let digestType: DNSSECDigest
    /// The digest data
    public let digest: Data

    internal init(recordData: Data) throws {
        let (keyTag, algorithmRaw, digestTypeRaw) = recordData.withUnsafeBytes { data in
            let keyTag = data.loadUnaligned(fromByteOffset: 0, as: UInt16.self).bigEndian
            let algorithmRaw = data.loadUnaligned(fromByteOffset: 2, as: UInt8.self)
            let digestTypeRaw = data.loadUnaligned(fromByteOffset: 3, as: UInt8.self)
            return (keyTag, algorithmRaw, digestTypeRaw)
        }

        guard let algorithm = DNSSECAlgorithm(rawValue: algorithmRaw) else {
            throw Utils.MakeError("Unknown or unsupported DNSSEC algorithm")
        }

        guard let digestType = DNSSECDigest(rawValue: digestTypeRaw) else {
            throw Utils.MakeError("Unknown or unsupported DNSSEC digest type")
        }

        let digest = recordData.suffix(from: 4)

        self.keyTag = keyTag
        self.algorithm = algorithm
        self.digestType = digestType
        self.digest = digest
    }

    public var description: String {
        return "\(self.keyTag) \(self.algorithm.rawValue) \(self.digestType.rawValue) \(self.digest.hexEncodedString())"
    }
}
