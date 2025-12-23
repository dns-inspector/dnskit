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

/// Describes the record data for an NSEC record
public struct NSECRecordData: RecordData {
    public let nextName: String
    public let types: Set<UInt16>

    internal init(recordData: Data) throws {
        let (name, typeOffset) = try Name.readName(recordData, startOffset: 0)
        self.nextName = name
        self.types = NSECRecordData.parseTypeFlags(recordData, typeOffset)
    }

    public var description: String {
        var typeStr: [String] = []
        for type in self.types {
            if let rrtype = RecordType(rawValue: type) {
                typeStr.append(String(describing: rrtype))
            } else {
                typeStr.append("\(type)")
            }
        }
        typeStr.sort()

        return "\(self.nextName) \(typeStr.joined(separator: " "))"
    }

    fileprivate static func parseTypeFlags(_ recordData: Data, _ startOffset: Int) -> Set<UInt16> {
        return recordData.withUnsafeBytes { buffer in
            var types: Set<UInt16> = .init()
            var offset = startOffset

            while offset < buffer.count {
                if offset+2 > buffer.count {
                    break
                }

                let window = buffer[offset...offset].load(as: UInt8.self)
                let bitmapLength = buffer[offset+1...offset+1].load(as: UInt8.self)
                offset += 2
                if offset+Int(bitmapLength) > buffer.count {
                    break
                }

                let bitmap = [UInt8](buffer[offset..<offset+Int(bitmapLength)])
                offset += Int(bitmapLength)

                for (byteIndex, b) in bitmap.enumerated() {
                    if b == 0 {
                        continue
                    }

                    var bit = 0
                    while bit < 8 {
                        bit += 1
                        if b & (0x80 >> bit) != 0 {
                            let type = (UInt16(window) << 8) | UInt16(byteIndex*8+bit)
                            types.insert(type)
                        }
                    }
                }
            }

            return types
        }
    }
}

public enum NSEC3Algorithm: UInt8, Sendable {
    case sha1 = 1
}

/// Describes the record data for an NSEC3 record
public struct NSEC3RecordData: RecordData {
    public let algorithm: NSEC3Algorithm
    public let optOut: Bool
    public let iterations: UInt16
    public let saltLength: UInt8
    public let salt: Data?
    public let hashLength: UInt8
    public let hashedNextName: Data
    public let types: Set<UInt16>

    internal init(recordData: Data) throws {
        var offset = 0
        let dataArray = Array(recordData)
        guard let algorithm = NSEC3Algorithm(rawValue: dataArray[offset] as UInt8) else {
            throw DNSKitError.invalidData("Unknown NSEC3 algorithm")
        }
        self.algorithm = algorithm
        offset += 1

        let flags = dataArray[offset] as UInt8
        self.optOut = flags & 8 == 0
        offset += 1

        self.iterations = recordData.withUnsafeBytes { data in
            return data.loadUnaligned(fromByteOffset: offset, as: UInt16.self).bigEndian
        }
        offset += 2

        self.saltLength = dataArray[offset] as UInt8
        offset += 1

        if self.saltLength > 0 {
            let salt = Data(dataArray[offset..<offset+Int(self.saltLength)])
            self.salt = salt
            offset += Int(self.saltLength)
        } else {
            self.salt = nil
        }

        self.hashLength = dataArray[offset] as UInt8
        offset += 1

        let hashedNextName = Data(dataArray[offset..<offset+Int(self.hashLength)])
        self.hashedNextName = hashedNextName
        offset += Int(self.hashLength)

        self.types = NSECRecordData.parseTypeFlags(recordData, offset)
    }

    public var description: String {
        var typeStr: [String] = []
        for type in self.types {
            if let rrtype = RecordType(rawValue: type) {
                typeStr.append(String(describing: rrtype))
            } else {
                typeStr.append("\(type)")
            }
        }
        typeStr.sort()

        return "\(self.algorithm.rawValue) \(self.optOut ? "1" : "0") \(self.salt?.base64EncodedString() ?? "-") \(self.hashedNextName.hexEncodedString()) \(typeStr.joined(separator: " "))"
    }
}
