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

public enum NSEC3Algorithm: UInt8, Sendable {
    case sha1 = 1
}

/// Describes the record data for an NSEC3 record
public struct NSEC3RecordData: RecordData {
    public let algorithm: NSEC3Algorithm
    public let optOut: Bool
    public let iterations: UInt16
    public let saltLength: UInt8
    public let salt: Data?
    public let hashLength: UInt8
    public let hashedNextName: Data
    public let types: UInt32

    internal init(messageData: Data, startOffset: Int) throws {
        var offset = startOffset

        let dataArray = Array(messageData)
        guard let algorithm = NSEC3Algorithm(rawValue: dataArray[offset] as UInt8) else {
            throw DNSKitError.invalidData("Unknown NSEC3 algorithm")
        }
        self.algorithm = algorithm
        offset += 1

        let flags = dataArray[offset] as UInt8
        self.optOut = flags & 8 == 0
        offset += 1

        self.iterations = messageData.withUnsafeBytes { data in
            return data.loadUnaligned(fromByteOffset: offset, as: UInt16.self).bigEndian
        }
        offset += 2

        self.saltLength = dataArray[offset] as UInt8
        offset += 1

        if self.saltLength > 0 {
            let salt = Data(dataArray[offset..<offset+Int(self.saltLength)])
            self.salt = salt
            offset += Int(self.saltLength)
        } else {
            self.salt = nil
        }

        self.hashLength = dataArray[offset] as UInt8
        offset += 1

        let hashedNextName = Data(dataArray[offset..<offset+Int(self.hashLength)])
        self.hashedNextName = hashedNextName
        offset += Int(self.hashLength)

        self.types = messageData.withUnsafeBytes { data in
            return data.loadUnaligned(fromByteOffset: offset, as: UInt32.self).bigEndian
        }
    }

    public var description: String {
        return "\(self.algorithm.rawValue) \(self.optOut ? "1" : "0") \(self.salt?.base64EncodedString() ?? "-") \(self.hashedNextName.hexEncodedString())"
    }
}
