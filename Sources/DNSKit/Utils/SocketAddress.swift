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

internal enum IPAddressVersion: Int {
    case v4 = 4
    case v6 = 6
}

internal final class SocketAddress: CustomStringConvertible, CustomDebugStringConvertible, Sendable {
    let ipAddress: String
    let port: UInt16?
    let version: IPAddressVersion

    fileprivate static let portSuffixPattern = NSRegularExpression("\\]?:\\d{1,5}$", options: .caseInsensitive)
    fileprivate static let ipv4Pattern = NSRegularExpression("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(\\:[0-9]{1,5})?$", options: .caseInsensitive)
    fileprivate static let ipv6Pattern = NSRegularExpression("^\\[?(([0-9a-f\\:]+){1,4}){1,8}\\]?(\\:[0-9]{1,5})?$", options: .caseInsensitive)

    /// Create a new SocketAddress instance from the given socket address string
    /// - Parameter addressString: The address string
    ///
    /// Accepted IP address formats:
    ///
    /// **IPv4:**
    /// - `n.n.n.n`
    /// - `n.n.n.n:port`
    ///
    /// **IPv6:**
    /// - `x::`
    /// - `[x::]:port`
    ///
    init(addressString: String) throws {
        if SocketAddress.ipv4Pattern.matches(in: addressString, range: NSRange(location: 0, length: addressString.count)).count > 0 {
            var ipAddress = ""

            let portMatches = SocketAddress.portSuffixPattern.matches(in: addressString, range: NSRange(location: 0, length: addressString.count))
            if portMatches.count > 1 {
                printError("[\(#fileID):\(#line)] Invalid IPv4 address: \(addressString)")
                throw DNSKitError.invalidData("Invalid IPv4 address")
            } else if portMatches.count == 1 {
                let portStr = String(addressString.suffix(portMatches[0].range.length-1))
                ipAddress = String(addressString.prefix(portMatches[0].range.location))

                guard let port = UInt16(portStr) else {
                    printError("[\(#fileID):\(#line)] Invalid port number from address: \(addressString)")
                    throw DNSKitError.invalidData("Invalid port number")
                }

                self.port = port
            } else {
                ipAddress = addressString
                self.port = nil
            }

            var sa: sockaddr_in = .init()
            if inet_pton(AF_INET, ipAddress, &sa.sin_addr) == 0 {
                printError("[\(#fileID):\(#line)] Invalid IPv4 address: \(addressString)")
                throw DNSKitError.invalidData("Invalid IPv4 address")
            }

            self.ipAddress = ipAddress
            self.version = .v4
        } else if SocketAddress.ipv6Pattern.matches(in: addressString, range: NSRange(location: 0, length: addressString.count)).count > 0 {
            var ipAddress = ""

            // Check for port suffix. IPv6 addresses must be wrapped with [] when a port is specified
            let portMatches = SocketAddress.portSuffixPattern.matches(in: addressString, range: NSRange(location: 0, length: addressString.count))
            if addressString.first == "[" && portMatches.count == 1 {
                let portStr = String(addressString.suffix(portMatches[0].range.length-2))
                ipAddress = String(addressString.prefix(portMatches[0].range.location).dropFirst())

                guard let port = UInt16(portStr) else {
                    printError("[\(#fileID):\(#line)] Invalid port number from address: \(addressString)")
                    throw DNSKitError.invalidData("Invalid port number")
                }

                self.port = port
            } else {
                ipAddress = addressString
                self.port = nil
            }

            var sa: sockaddr_in6 = .init()
            if inet_pton(AF_INET6, ipAddress, &sa.sin6_addr) == 0 {
                printError("[\(#fileID):\(#line)] Invalid IPv6 address: \(addressString)")
                throw DNSKitError.invalidData("Invalid IPv6 address")
            }

            self.ipAddress = ipAddress
            self.version = .v6
        } else {
            printError("[\(#fileID):\(#line)] Unrecognized IP address: \(addressString)")
            throw DNSKitError.invalidData("Invalid port number")
        }
    }

    var description: String {
        switch self.version {
        case .v4:
            if let port = self.port {
                return "\(self.ipAddress):\(port)"
            } else {
                return "\(self.ipAddress)"
            }
        case .v6:
            if let port = self.port {
                return "[\(self.ipAddress)]:\(port)"
            } else {
                return "\(self.ipAddress)"
            }
        }
    }

    var debugDescription: String {
        return description
    }
}
