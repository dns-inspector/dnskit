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

/// Describes the shared record data type for a resource type where the value is always and only a DNS name.
///
/// > Note: You should always prefer to use the associated RecordData type that matches the value of the RecordType. Don't cast the record data to `BasicNameRecordData` directly.
public struct BasicNameRecordData: RecordData, CompressibleRecordData {
    public let name: String

    internal var uncompressedRecordData: Data

    internal init(messageData: Data, startOffset: Int) throws {
        let (name, _) = try Name.readName(messageData, startOffset: startOffset)
        self.name = name

        self.uncompressedRecordData = try Name.stringToName(name)
    }

    public var description: String {
        return self.name
    }
}
