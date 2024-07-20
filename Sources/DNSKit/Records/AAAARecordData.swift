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

/// Describes the record data for an AAAA record
public struct AAAARecordData: RecordData {
    /// The IP address
    public let ipAddress: String

    internal init(ipAddress: Data) throws {
        if ipAddress.count > 16 {
            printError("[\(#fileID):\(#line)] Invalid IPv6 address: expecting >= 16 bytes got \(ipAddress.count)")
            throw Utils.MakeError("Invalid IPv6 address")
        }

        var buffer = ContiguousArray<Int8>(repeating: 0, count: Int(INET6_ADDRSTRLEN))
        self.ipAddress = ipAddress.withUnsafeBytes { data in
            let addr = data.assumingMemoryBound(to: sockaddr_in6.self)
            return buffer.withUnsafeMutableBufferPointer { buf in
                return String(cString: inet_ntop(AF_INET6, addr.baseAddress, buf.baseAddress, UInt32(buf.count)))
            }
        }
    }

    public var description: String {
        return self.ipAddress
    }
}
