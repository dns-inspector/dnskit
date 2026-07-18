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

/// Describes the record data for a CAA record
public struct CAARecordData: RecordData {
    /// If this CAA record is flagged as critical
    public let critical: Bool
    /// The tag associated with the value
    public let tag: String
    /// The value of this CAA, typically the FQDN of the CA
    public let value: String

    internal init(recordData: Data) throws {
        let flags = recordData.withUnsafeBytes {
            return $0.loadUnaligned(fromByteOffset: 0, as: UInt8.self)
        }

        self.critical = flags == 128

        let tagLen = recordData.withUnsafeBytes {
            return $0.loadUnaligned(fromByteOffset: 1, as: UInt8.self)
        }

        let tagData = recordData.subdata(in: 2..<2+Int(tagLen))

        guard let tag = String(data: tagData, encoding: .ascii) else {
            throw DNSKitError.invalidData("Invalid tag data in CAA record")
        }

        self.tag = tag

        let valueData = recordData.suffix(from: 2+Int(tagLen))

        guard let value = String(data: valueData, encoding: .ascii) else {
            throw DNSKitError.invalidData("Invalid value data in CAA record")
        }

        self.value = value
    }

    public var description: String {
        return "\(critical ? "128" : "0") \(tag) \"\(value)\""
    }
}
