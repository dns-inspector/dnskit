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

/// Utilities for working with DNS names
public class Name {
    /// Encode a string as a DNS name. Will throw if an invalid DNS name is provided.
    /// - Parameter name: The DNS name to encode
    /// - Returns: A byte array containing the encoded name
    public static func stringToName(_ name: String) throws -> Data {
        if name.count == 1 && name == "." {
            return Data.zeroByte()
        }

        var buf = Data()

        // Note that we're not using the splitName function from this class
        // because the behaviour is different and undesired for this specific
        // use-case
        let labels = name.split(separator: ".")

        for label in labels {
            // Skip trailing '.'
            if label.count == 0 && label == labels.last {
                break
            }

            if label.count > 63 {
                throw DNSKitError.invalidData("Invalid DNS name: individual label exceeds 63 characters")
            }

            let length = UInt8(label.count)
            withUnsafePointer(to: length) { l in
                buf.append(l, count: 1)
            }
            if label.count == 0 {
                continue
            }
            if let rawLabel = label.data(using: .ascii) {
                buf.append(rawLabel)
            }
        }

        // Add the terminator
        buf.appendZeroByte()
        return buf
    }

    /// Reads and decodes a DNS name from the given data, decompressing the name if needed. Will throw on invalid data.
    /// - Parameters:
    ///   - data: The data to read from, typically an entire DNS message
    ///   - startOffset: The offset to start reading the name from
    /// - Returns: A tuple of the DNS name and the offset of where to continue reading data after this name has ended.
    public static func readName(_ data: Data, startOffset: Int) throws -> (name: String, dataOffset: Int) {
        printDebug("[\(#fileID):\(#line)] Attempt to read name at \(startOffset)")

        if startOffset < 0 || startOffset >= data.count {
            throw DNSKitError.invalidData("Invalid start offset when reading DNS name")
        }

        return try data.withUnsafeBytes { buffer in
            if buffer[startOffset...startOffset].load(as: UInt8.self) == 0 {
                return (".", startOffset+1)
            }

            var offset = startOffset
            var dataOffset = 0
            var name = String()

            var labelFlag = buffer[offset...offset].load(as: UInt8.self)
            var depth = 0
            while labelFlag > 0 {
                if depth > 10 {
                    throw DNSKitError.invalidData("Maximum pointer depth reached")
                }

                if labelFlag < 64 {
                    // Label value, labelFlag is length
                    if labelFlag >= buffer.count {
                        throw DNSKitError.invalidData("Label length outside of data bounds")
                    }

                    let labelData = Data(buffer[offset+1..<offset+1+Int(labelFlag)])
                    printDebug("[\(#fileID):\(#line)] Reading \(labelFlag) bytes at \(offset+1)")
                    offset += 1 + Int(labelFlag)
                    labelFlag = buffer[offset...offset].load(as: UInt8.self)

                    guard let label = String(data: labelData, encoding: .ascii) else {
                        printError("[\(#fileID):\(#line)] Invalid data in label text: \(labelData.hexEncodedString())")
                        throw DNSKitError.invalidData("Invalid data in label text")
                    }

                    if label.contains(".") {
                        throw DNSKitError.invalidData("Illegal characters in label text")
                    }

                    name.append("\(label).")
                    printDebug("[\(#fileID):\(#line)] Read label: \(label).")
                    continue
                }

                // Label is a pointer, lower 6 bits of the first byte + next byte are the destination
                let nextByte = buffer[offset+1...offset+1].load(as: UInt8.self)
                let b = [ labelFlag & 0x3f, nextByte ]
                let destination = b.withUnsafeBytes {
                    return $0.load(as: UInt16.self).bigEndian
                }
                printDebug("[\(#fileID):\(#line)] Label is a pointer to \(destination)")
                if dataOffset == 0 {
                    dataOffset = offset+2
                }
                if Int(destination) >= buffer.count {
                    throw DNSKitError.invalidData("Pointer offset outside of data bounds")
                }
                offset = Int(destination)
                labelFlag = buffer[offset...offset].load(as: UInt8.self)
                depth += 1
            }

            if name == "" {
                printError("[\(#fileID):\(#line)] Unexpected end of record name")
                throw DNSKitError.invalidData("Length is zero")
            }

            if dataOffset == 0 {
                dataOffset = startOffset + name.count + 1
            }
            printDebug("[\(#fileID):\(#line)] Read name \(name), data offset at \(dataOffset)")
            return (name, dataOffset)
        }
    }

    /// Split the given name into individual labels.
    /// - Parameter name: The DNS name. If only the root zone is passed ('.'), returns an empty array.
    /// - Returns: An array of labels
    public static func splitName(_ name: String) -> [String] {
        if name == "" {
            return []
        }
        if name.count == 1 && name == "." {
            return []
        }

        var n = NSString(string: name)
        if name.hasSuffix(".") {
            n = NSString(string: n.substring(to: n.length-1))
        }

        return n.components(separatedBy: ".")
    }

    /// Returns all the qualified parent names from the given name.
    /// For example, given 'foo.example.com', returns ['example.com.', 'com.', '.']
    /// - Parameter name: The DNS name.
    /// - Returns: An array of labels
    public static func parentNames(from name: String) -> [String] {
        var parts = splitName(name)
        var names: [String] = []

        while parts.count > 0 {
            parts = Array(parts.dropFirst())
            names.append(parts.joined(separator: ".") + ".")
        }

        return names
    }
}
