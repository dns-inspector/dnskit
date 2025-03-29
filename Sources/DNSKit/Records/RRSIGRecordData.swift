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

/// Describes the record data for a RRSIG record
public struct RRSIGRecordData: RecordData {
    /// The record type covered by this signature
    public let typeCovered: RecordType
    /// The algorithm of the signature
    public let algorithm: DNSSECAlgorithm
    /// The number of labels covered by this signature
    public let labelCount: UInt8
    /// The TTL (in seconds) of this signature
    public let ttlSeconds: UInt32
    /// Expiry date for this signature
    public let signatureNotAfter: Date
    /// Effective start date for this signature
    public let signatureNotBefore: Date
    /// The key tag of the public key used for signing
    public let keyTag: UInt16
    /// The signing key name
    public let signerName: String
    /// The signature
    public let signature: Data

    internal let recordData: Data

    internal init(recordData: Data) throws {
        self.recordData = recordData

        let (typeCoveredRaw, algorithmRaw, labelCount, ttlSeconds, notAfter, notBefore, keyTag) = recordData.withUnsafeBytes { data in
            let typeCoveredRaw = data.loadUnaligned(fromByteOffset: 0, as: UInt16.self).bigEndian
            let algorithmRaw = data.loadUnaligned(fromByteOffset: 2, as: UInt8.self)
            let labelCount = data.loadUnaligned(fromByteOffset: 3, as: UInt8.self)
            let ttlSeconds = data.loadUnaligned(fromByteOffset: 4, as: UInt32.self).bigEndian
            let notAfter = data.loadUnaligned(fromByteOffset: 8, as: UInt32.self).bigEndian
            let notBefore = data.loadUnaligned(fromByteOffset: 12, as: UInt32.self).bigEndian
            let keyTag = data.loadUnaligned(fromByteOffset: 16, as: UInt16.self).bigEndian
            return (typeCoveredRaw, algorithmRaw, labelCount, ttlSeconds, notAfter, notBefore, keyTag)
        }

        let (signerName, dataOffset) = try Name.readName(recordData, startOffset: 18)

        let signature = recordData.suffix(from: dataOffset)

        guard let typeCovered = RecordType(rawValue: typeCoveredRaw) else {
            throw DNSKitError.invalidData("Unknown record type: \(typeCoveredRaw)")
        }

        guard let algorithm = DNSSECAlgorithm(rawValue: algorithmRaw) else {
            throw DNSKitError.unsupportedAlgorithm
        }

        self.typeCovered = typeCovered
        self.algorithm = algorithm
        self.labelCount = labelCount
        self.ttlSeconds = ttlSeconds
        self.signatureNotAfter = Date(timeIntervalSince1970: TimeInterval(notAfter))
        self.signatureNotBefore = Date(timeIntervalSince1970: TimeInterval(notBefore))
        self.keyTag = keyTag
        self.signerName = signerName
        self.signature = signature
    }

    internal func signedData() throws -> Data {
        // Signed data is everything but the signature itself
        let (_, dataOffset) = try Name.readName(self.recordData, startOffset: 18)
        return self.recordData.prefix(upTo: dataOffset)
    }

    internal func signatureForCrypto() -> Data {
        return ASN1.pkcs1Signature(self.signature, algorithm: self.algorithm)
    }

    public var description: String {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyyMMddHHmmss"
        dateFormatter.timeZone = TimeZone(abbreviation: "GMT")!
        return "\(self.algorithm.rawValue) \(self.labelCount) \(self.ttlSeconds) \(dateFormatter.string(from: self.signatureNotAfter)) \(dateFormatter.string(from: self.signatureNotBefore)) \(self.keyTag) \(self.signerName) \(self.signature.base64EncodedString())"
    }
}
