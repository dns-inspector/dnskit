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

internal enum SvcParamKeys: UInt16 {
    case Alpn = 1
    case NoDefaultAlpn = 2
    case Port = 3
    case IPv4Hint = 4
    case Ech = 5
    case IPv6Hint = 6
}

/// HTTP protocol versions
public enum HTTPVersions: String, Sendable {
    /// HTTP 1.1
    case HTTP1 = "http/1.1"
    /// HTTP 2
    case HTTP2 = "h2"
    /// HTTP 3 or "QUIC"
    case HTTP3 = "h3"
}

/// Describes the record data for a HTTPS record
public struct HTTPSRecordData: RecordData, CompressibleRecordData {
    /// The record priority
    public let priority: UInt16
    /// The record target
    public let target: String
    /// The supported HTTP protocols
    public let alpn: [HTTPVersions]?
    /// If no default HTTP protocol was specified. This will only ever be true or nil.
    public let noDefaultAlpn: Bool?
    /// The port
    public let port: UInt16?
    /// IPv4 hint addresses. If not nil then guaranteed to have at least one.
    public let ipv4Hint: [String]?
    /// IPv6 hint addresses. If not nil then guaranteed to have at least one.
    public let ipv6Hint: [String]?
    /// Encrypted client hello configuration
    public let ech: Data?

    internal var uncompressedRecordData: Data

    internal init(recordData: Data) throws {
        self.priority = recordData.withUnsafeBytes {
            return $0.loadUnaligned(fromByteOffset: 0, as: UInt16.self).bigEndian
        }

        let (target, dataOffset) = try Name.readName(recordData, startOffset: 2)
        self.target = target

        var uncompressedRecordData = Data()
        uncompressedRecordData.append(self.priority.bigEndian)
        uncompressedRecordData.append(try Name.stringToName(target))
        uncompressedRecordData.append(recordData.suffix(from: dataOffset))
        self.uncompressedRecordData = uncompressedRecordData

        var alpn: [HTTPVersions]?
        var noDefaultAlpn: Bool?
        var port: UInt16?
        var ipv4Hint: [String]?
        var ipv6Hint: [String]?
        var ech: Data?

        var moreParams = true
        var paramStartOffset = dataOffset
        while moreParams {
            let key = recordData.withUnsafeBytes {
                return $0.loadUnaligned(fromByteOffset: paramStartOffset, as: UInt16.self).bigEndian
            }
            let valueLength = recordData.withUnsafeBytes {
                return $0.loadUnaligned(fromByteOffset: paramStartOffset + 2, as: UInt16.self).bigEndian
            }
            let value: Data
            if valueLength == 0 {
                value = Data()
            } else {
                value = recordData.suffix(from: paramStartOffset + 4).prefix(Int(valueLength))
            }

            switch SvcParamKeys(rawValue: key) {
            case .Alpn:
                alpn = HTTPSRecordData.readAlpnValues(Array(value))
            case .NoDefaultAlpn:
                noDefaultAlpn = true
            case .Port:
                port = value.withUnsafeBytes {
                    $0.loadUnaligned(fromByteOffset: 0, as: UInt16.self).bigEndian
                }
            case .IPv4Hint:
                if valueLength % 4 != 0 {
                    throw DNSKitError.incorrectType("Invalid length of IPv4 hint in SvcParam")
                }
                let bytes: [UInt8] = Array(value)
                let numberOfAddresses = valueLength / 4
                for i in 0..<numberOfAddresses {
                    let addr = try IPAddress.v4(Data(bytes[Int(i*4)..<Int(i*4)+4]))
                    if ipv4Hint == nil {
                        ipv4Hint = []
                    }
                    ipv4Hint?.append(addr)
                }
            case .Ech:
                ech = value
            case .IPv6Hint:
                if valueLength % 16 != 0 {
                    throw DNSKitError.incorrectType("Invalid length of IPv6 hint in SvcParam")
                }
                let bytes: [UInt8] = Array(value)
                let numberOfAddresses = valueLength / 16
                for i in 0..<numberOfAddresses {
                    let addr = try IPAddress.v6(Data(bytes[Int(i*16)..<Int(i*16)+16]))
                    if ipv6Hint == nil {
                        ipv6Hint = []
                    }
                    ipv6Hint?.append(addr)
                }
            case nil:
                printWarning("[\(#fileID):\(#line)] Unknown SvcParamKey \(key)")
            }

            paramStartOffset += 4+Int(valueLength)
            if paramStartOffset >= recordData.count {
                moreParams = false
            }
        }

        self.alpn = alpn
        self.noDefaultAlpn = noDefaultAlpn
        self.port = port
        self.ipv4Hint = ipv4Hint
        self.ipv6Hint = ipv6Hint
        self.ech = ech
    }

    internal static func readAlpnValues(_ data: [UInt8]) -> [HTTPVersions] {
        var versions: [HTTPVersions] = []
        var moreValues = true
        var alpnStartOffset = 0
        while moreValues {
            let length = data[alpnStartOffset]
            let alpnRawValue = Data(data[alpnStartOffset+1..<alpnStartOffset+1+Int(length)])
            let alpnValue = String(data: alpnRawValue, encoding: .ascii)

            if let version = HTTPVersions(rawValue: alpnValue ?? "") {
                versions.append(version)
            } else {
                printWarning("[\(#fileID):\(#line)] Unknown HTTPS ALPN \(alpnRawValue)")
            }
            alpnStartOffset = alpnStartOffset+1+Int(length)
            if alpnStartOffset >= data.count {
                moreValues = false
            }
        }

        return versions
    }

    public var description: String {
        var d = "\(self.priority) \(self.target)"

        if noDefaultAlpn ?? false {
            d += " no-default-alpn=\"\""
        }

        if let alpn = self.alpn {
            d += " alpn=\"\(alpn.map({ $0.rawValue }).joined(separator: ","))\""
        }

        if let port = self.port {
            d += " port=\"\(port)\""
        }

        if let ipv4Hints = self.ipv4Hint {
            d += " ipv4hint=\"\(ipv4Hints.joined(separator: ","))\""
        }

        if let ipv6Hints = self.ipv6Hint {
            d += " ipv6hint=\"\(ipv6Hints.joined(separator: ","))\""
        }

        if let ech = self.ech {
            d += " ech=\"\(ech.base64EncodedString())\""
        }

        return d
    }
}
