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

/// Describes the record data for an A record
public struct ARecordData: RecordData {
    /// The IP address
    public let ipAddress: String

    internal init(ipAddress: Data) throws {
        if ipAddress.count > 4 {
            printError("[\(#fileID):\(#line)] Invalid IPv4 address: expecting >= 4 bytes got \(ipAddress.count)")
            throw Utils.MakeError("Invalid IPv4 address")
        }

        var buffer = ContiguousArray<Int8>(repeating: 0, count: Int(INET_ADDRSTRLEN))
        self.ipAddress = ipAddress.withUnsafeBytes { data in
            let addr = data.assumingMemoryBound(to: sockaddr_in.self)
            return buffer.withUnsafeMutableBufferPointer { buf in
                return String(cString: inet_ntop(AF_INET, addr.baseAddress, buf.baseAddress, UInt32(buf.count)))
            }
        }
    }

    public var description: String {
        return self.ipAddress
    }
}
