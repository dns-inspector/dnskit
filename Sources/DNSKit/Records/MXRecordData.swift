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

/// Describes the record data for an MX record
public struct MXRecordData: RecordData, CompressibleRecordData {
    /// The record priority
    public let priority: UInt16
    /// The mail server name
    public let name: String

    internal var uncompressedRecordData: Data

    internal init(messageData: Data, startOffset: Int) throws {
        let priority = messageData.withUnsafeBytes { data in
            return data.loadUnaligned(fromByteOffset: startOffset, as: UInt16.self).bigEndian
        }
        let (name, _) = try Name.readName(messageData, startOffset: startOffset+2)

        self.priority = priority
        self.name = name

        self.uncompressedRecordData = Data()
        self.uncompressedRecordData.append(priority.bigEndian)
        self.uncompressedRecordData.append(try Name.stringToName(name))
    }

    public var description: String {
        return "\(self.priority) \(self.name)"
    }
}
