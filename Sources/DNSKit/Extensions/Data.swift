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

internal extension Data {
    static func zeroByte() -> Data {
        let z = UInt8(0)
        return withUnsafePointer(to: z) { p in
            return Data(bytes: p, count: 1)
        }
    }

    mutating func appendZeroByte() {
        let z = UInt8(0)
        withUnsafePointer(to: z) { p in
            self.append(p, count: 1)
        }
    }

    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }

    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return self.map { String(format: format, $0) }.joined()
    }

    func base64UrlEncodedValue() -> String {
        var value = self.base64EncodedString()
        value = value.replacingOccurrences(of: "=", with: "")
        value = value.replacingOccurrences(of: "+", with: "-")
        value = value.replacingOccurrences(of: "/", with: "_")
        return value
    }

    mutating func append(_ v: UInt8) {
        self.append(Data([v]))
    }

    mutating func append(_ v: UInt16) {
        Swift.withUnsafePointer(to: v) { n in
            self.append(Data(bytes: n, count: 2))
        }
    }

    mutating func append(_ v: UInt32) {
        Swift.withUnsafePointer(to: v) { n in
            self.append(Data(bytes: n, count: 4))
        }
    }

    mutating func append(_ v: UInt64) {
        Swift.withUnsafePointer(to: v) { n in
            self.append(Data(bytes: n, count: 8))
        }
    }
}

internal extension UnsafeRawBufferPointer {
    func loadUnaligned<T>(fromByteOffset offset: Int, as: T.Type) -> T {
        // Allocate correctly aligned memory and copy bytes there
        let alignedPointer = UnsafeMutableRawPointer.allocate(byteCount: MemoryLayout<T>.stride, alignment: MemoryLayout<T>.alignment)
        defer {
            alignedPointer.deallocate()
        }
        alignedPointer.copyMemory(from: baseAddress!.advanced(by: offset), byteCount: MemoryLayout<T>.size)
        return alignedPointer.load(as: T.self)
    }
}
