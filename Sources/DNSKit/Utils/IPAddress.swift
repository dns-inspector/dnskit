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

internal final class IPAddress {
    /// Read the binary representation of an IPv4 address and return a formatted string
    /// - Parameter data: The 4 bytes of an IPv4 address. Must be exactly 4 bytes.
    /// - Returns: A string representing an IPv4 address
    static func v4(_ data: Data) throws -> String {
        if data.count > 4 {
            printError("[\(#fileID):\(#line)] Invalid IPv4 address: expecting >= 4 bytes got \(data.count)")
            throw DNSKitError.invalidData("Invalid IPv4 address")
        }

        var buffer = ContiguousArray<Int8>(repeating: 0, count: Int(INET_ADDRSTRLEN))
        return data.withUnsafeBytes {
            let addr = $0.assumingMemoryBound(to: sockaddr_in.self)
            return buffer.withUnsafeMutableBufferPointer { buf in
                return String(cString: inet_ntop(AF_INET, addr.baseAddress, buf.baseAddress, UInt32(buf.count)))
            }
        }
    }

    /// Read the binary representation of an IPv6 address and return a formatted string
    /// - Parameter data: The 16 bytes of an IPv6 address. Must be exactly 16 bytes.
    /// - Returns: A string representing an IPv6 address
    static func v6(_ data: Data) throws -> String {
        if data.count > 16 {
            printError("[\(#fileID):\(#line)] Invalid IPv6 address: expecting >= 16 bytes got \(data.count)")
            throw DNSKitError.invalidData("Invalid IPv6 address")
        }

        var buffer = ContiguousArray<Int8>(repeating: 0, count: Int(INET6_ADDRSTRLEN))
        return data.withUnsafeBytes {
            let addr = $0.assumingMemoryBound(to: sockaddr_in6.self)
            return buffer.withUnsafeMutableBufferPointer { buf in
                return String(cString: inet_ntop(AF_INET6, addr.baseAddress, buf.baseAddress, UInt32(buf.count)))
            }
        }
    }
    
    /// Converts a human-readable IPv4 address to a in-addr arpa DNS name for PTR lookups
    /// - Parameter v4: An IPv4 address in human form "1.2.3.4"
    /// - Returns: A DNS name label for PTR records, "4.3.2.1.in-addr.arpa"
    static func v4ToArpaName(_ v4: String) throws -> String {
        let octets = v4.split(separator: ".")
        if octets.count != 4 {
            throw DNSKitError.invalidData("Invalid IPv4 address: \(v4)")
        }
        return octets.reversed().joined(separator: ".") + ".in-addr.arpa"
    }
    
    /// Converts a human-readable IPv6 address to a ip6 addr DNS name for PTR lookups.
    /// - Parameter v6: An IPv6 address in human form "2001::1"
    /// - Returns: A DNS name label for PTR records.
    static func v6ToArpaName(_ v6: String) throws -> String {
        var buffer = ContiguousArray<UInt8>(repeating: 0, count: 16)
        let r = buffer.withUnsafeMutableBufferPointer { b in
            return inet_pton(AF_INET6, v6, b.baseAddress)
        }
        if r != 1 {
            throw DNSKitError.invalidData("Invalid IPv6 address: \(v6)")
        }
        var nibbles: [String] = []
        let fullAddress = NSString(format: "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                                   buffer[0], buffer[1],
                                   buffer[2], buffer[3],
                                   buffer[4], buffer[5],
                                   buffer[6], buffer[7],
                                   buffer[8], buffer[9],
                                   buffer[10], buffer[11],
                                   buffer[12], buffer[13],
                                   buffer[14], buffer[15])
        for i in stride(from: fullAddress.length-1, to: -1, by: -1) { // "to: -1" is exclusive, this stops at 0
            let char = fullAddress.character(at: i)
            nibbles.append(String(Character(UnicodeScalar(char)!)))
        }
        
        return nibbles.joined(separator: ".") + ".ip6.arpa"
    }
}
