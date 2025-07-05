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

/// Describes a DNS question
public struct Question: Sendable {
    /// The resource's name
    public let name: String
    /// The resource's record type
    public let recordType: RecordType
    /// The resource's record class
    public let recordClass: RecordClass

    public init(name: String, recordType: RecordType, recordClass: RecordClass) {
        self.recordType = recordType
        self.recordClass = recordClass

        var name = name

        // Convenience: if the question is a PTR record and a bare IP address was passed in, automatically convert the address to the correct PTR format
        if recordType == .PTR && !name.contains(".in-addr.arpa") && !name.contains("ip6.arpa") {
            do {
                if name.contains(":") {
                    name = try IPAddress.v6ToArpaName(name)
                } else {
                    name = try IPAddress.v4ToArpaName(name)
                }
            } catch {
                printError("[\(#fileID):\(#line)] Unable to convert IP address to arpa name: \(error)")
            }
        }

        self.name = name
    }

    internal func data() throws -> Data {
        var data = Data()
        let name = try Name.stringToName(self.name)
        data.append(name)

        let rtype = UInt16(self.recordType.rawValue).bigEndian
        let rclass = UInt16(self.recordClass.rawValue).bigEndian

        withUnsafePointer(to: rtype) { rt in
            data.append(Data(bytes: rt, count: 2))
        }
        withUnsafePointer(to: rclass) { rc in
            data.append(Data(bytes: rc, count: 2))
        }

        return data
    }
}
