import Foundation

internal final class IPAddress {
    /// Read the binary representation of an IPv4 address and return a formatted string
    /// - Parameter data: The 4 bytes of an IPv4 address. Must be exactly 4 bytes.
    /// - Returns: A string representing an IPv4 address
    static func v4(_ data: Data) throws -> String {
        if data.count > 4 {
            printError("[\(#fileID):\(#line)] Invalid IPv4 address: expecting >= 4 bytes got \(data.count)")
            throw Utils.MakeError("Invalid IPv4 address")
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
            throw Utils.MakeError("Invalid IPv6 address")
        }

        var buffer = ContiguousArray<Int8>(repeating: 0, count: Int(INET6_ADDRSTRLEN))
        return data.withUnsafeBytes {
            let addr = $0.assumingMemoryBound(to: sockaddr_in6.self)
            return buffer.withUnsafeMutableBufferPointer { buf in
                return String(cString: inet_ntop(AF_INET6, addr.baseAddress, buf.baseAddress, UInt32(buf.count)))
            }
        }
    }
}
