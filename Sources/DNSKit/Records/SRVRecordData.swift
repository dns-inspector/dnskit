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

/// Describes the record data for a SRV record
public struct SRVRecordData: RecordData {
    /// The record priority
    public let priority: UInt16
    /// The record weight
    public let weight: UInt16
    /// The service port number
    public let port: UInt16
    /// The service host name
    public let name: String

    internal init(messageData: Data, startOffset: Int) throws {
        let (priority, weight, port) = messageData.withUnsafeBytes { data in
            var offset = startOffset
            let priority = data.loadUnaligned(fromByteOffset: offset, as: UInt16.self).bigEndian
            offset += 2

            let weight = data.loadUnaligned(fromByteOffset: offset, as: UInt16.self).bigEndian
            offset += 2

            let port = data.loadUnaligned(fromByteOffset: offset, as: UInt16.self).bigEndian

            return (priority, weight, port)
        }

        let (name, _) = try Name.readName(messageData, startOffset: startOffset+6)

        self.priority = priority
        self.weight = weight
        self.port = port
        self.name = name
    }

    public var description: String {
        return "\(self.priority) \(self.weight) \(self.port) \(self.name)"
    }
}
